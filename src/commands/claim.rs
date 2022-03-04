use stamp_aux;
use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto::key::SecretKey,
    dag::Transactions,
    identity::{
        ClaimID,
        ClaimBin,
        ClaimSpec,
        ClaimContainer,
        IdentityID,
        RelationshipType,
    },
    private::MaybePrivate,
    util::{Date, Public},
};
use std::convert::TryFrom;
use url::Url;

fn prompt_claim_value(prompt: &str) -> Result<String, String> {
    let value: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| format!("Error grabbing claim value: {:?}", e))?;
    Ok(value)
}

pub(crate) fn claim_pre_noval(id: &str) -> Result<(SecretKey, Transactions), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    Ok((master_key, transactions))
}

pub(crate) fn claim_pre(id: &str, prompt: &str) -> Result<(SecretKey, Transactions, String), String> {
    let (master_key, transactions) = claim_pre_noval(id)?;
    let value = prompt_claim_value(prompt)?;
    Ok((master_key, transactions, value))
}

fn unwrap_maybe<T, F>(maybe: &MaybePrivate<T>, masterkey_fn: F) -> Result<T, String>
    where T: serde::Serialize + serde::de::DeserializeOwned + Clone,
          F: FnOnce() -> Result<SecretKey, String>,
{
    if maybe.has_private() {
        let master_key = masterkey_fn()?;
        maybe.open(&master_key)
            .map_err(|e| format!("Unable to open private claim: {}", e))
    } else {
        let fake_master_key = SecretKey::new_xsalsa20poly1305();
        maybe.open(&fake_master_key)
            .map_err(|e| format!("Unable to open claim: {}", e))
    }
}

pub fn check(claim_id: &str) -> Result<(), String> {
    let transactions = db::find_identity_by_prefix("claim", claim_id)?
        .ok_or(format!("Identity with claim id {} was not found", claim_id))?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let claim = identity.claims().iter()
        .find(|x| id_str!(x.claim().id()).map(|x| x.starts_with(claim_id)) == Ok(true))
        .ok_or(format!("Couldn't find the claim {} in identity {}", claim_id, IdentityID::short(&id_str)))?;
    let claim_id_str = id_str!(claim.claim().id())?;
    match stamp_aux::claim::check_claim(&transactions, claim.claim()) {
        Ok(url) => {
            let green = dialoguer::console::Style::new().green();
            println!("\nThe claim {} has been {}!\n", ClaimID::short(&claim_id_str), green.apply_to("verified"));
            println!("{}", util::text_wrap(&format!("It is very likely that the identity {} owns the resource {}", IdentityID::short(&id_str), url)));
            Ok(())
        }
        Err(err) => {
            let red = dialoguer::console::Style::new().red();
            println!("\nThe claim {} {}\n", ClaimID::short(&claim_id_str), red.apply_to("could not be verified"));
            Err(format!("{}", err))
        }
    }
}

pub fn view(id: &str, claim_id: &str, output: &str) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let mut found: Option<ClaimContainer> = None;
    for claim in identity.claims() {
        let id_str = id_str!(claim.claim().id())?;
        if id_str.starts_with(claim_id) {
            found = Some(claim.clone());
            break;
        }
    }
    let claim = found.ok_or(format!("Cannot find the claim {} in identity {}", claim_id, id))?;
    if claim.has_private() && !identity.is_owned() {
        Err(format!("You cannot view private claims on an identity you don't own."))?;
    }

    let id_str = id_str!(identity.id())?;
    let masterkey_fn = || {
        let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
        identity.test_master_key(&master_key)
            .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
        Ok(master_key)
    };

    let output_bytes = match claim.claim().spec() {
        ClaimSpec::Identity(id) => {
            Vec::from(id_str!(id)?.as_bytes())
        }
        ClaimSpec::Name(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        ClaimSpec::Email(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        ClaimSpec::Photo(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_slice())
        }
        ClaimSpec::Pgp(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        ClaimSpec::Domain(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        ClaimSpec::Url(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_str().as_bytes())
        }
        ClaimSpec::HomeAddress(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        _ => Err(format!("Viewing is not implemented for this claim type"))?,
    };
    util::write_file(output, output_bytes.as_slice())?;
    Ok(())
}

pub fn list(id: &str, private: bool, verbose: bool) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let master_key_maybe = if private {
        let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
        identity.test_master_key(&master_key)
            .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
        Some(master_key)
    } else {
        None
    };
    print_claims_table(identity.claims(), master_key_maybe, verbose);
    Ok(())
}

pub fn print_claims_table(claims: &Vec<ClaimContainer>, master_key_maybe: Option<SecretKey>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let id_field = if verbose { "ID" } else { "ID (short)" };
    table.set_titles(row![id_field, "Type", "Value", "Created", "# stamps"]);
    for claim in claims {
        let (id_full, id_short) = id_str_split!(claim.claim().id());
        macro_rules! extract_str {
            ($maybe:expr, $tostr:expr) => {
                if let Some(master_key) = master_key_maybe.as_ref() {
                    $maybe.open(master_key)
                        .map(|val| {
                            let strval = $tostr(val);
                            if $maybe.has_private() {
                                let green = dialoguer::console::Style::new().green();
                                format!("{}", green.apply_to(&strval))
                            } else {
                                strval
                            }
                        })
                        .unwrap_or_else(|e| format!("Decryption error: {}", e))
                } else {
                    match $maybe {
                        MaybePrivate::Public(val) => {
                            $tostr(val.clone())
                        }
                        MaybePrivate::Private(..) => {
                            let red = dialoguer::console::Style::new().red();
                            format!("{}", red.apply_to("<private>"))
                        }
                    }
                }
            };
            ($maybe:expr) => {
                extract_str!($maybe, |x| x)
            };
        }
        let (ty, val) = match claim.claim().spec() {
            ClaimSpec::Identity(id) => {
                let (id_full, id_short) = id_str_split!(id);
                ("identity", if verbose { id_full } else { id_short })
            }
            ClaimSpec::Name(name) => ("name", extract_str!(name)),
            ClaimSpec::Birthday(birthday) => ("birthday", extract_str!(birthday, |x: Date| x.to_string())),
            ClaimSpec::Email(email) => ("email", extract_str!(email)),
            ClaimSpec::Photo(photo) => ("photo", extract_str!(photo, |x: ClaimBin| format!("<{} bytes>", x.len()))),
            ClaimSpec::Pgp(pgp) => ("pgp", extract_str!(pgp)),
            ClaimSpec::Domain(domain) => ("domain", extract_str!(domain)),
            ClaimSpec::Url(url) => ("url", extract_str!(url, |x: Url| x.into_string())),
            ClaimSpec::HomeAddress(address) => ("address", extract_str!(address)),
            ClaimSpec::Relation(relation) => {
                let rel_str = match relation {
                    MaybePrivate::Public(relationship) => {
                        let ty_str = match relationship.ty() {
                            RelationshipType::OrganizationMember => String::from("org"),
                            _ => String::from("<unknown>"),
                        };
                        let id: &IdentityID = relationship.subject();
                        let (id_full, id_short) = id_str_split!(id);
                        format!("{} ({})", if verbose { id_full } else { id_short }, ty_str)
                    }
                    MaybePrivate::Private(..) => String::from("******"),
                };
                ("relation", rel_str)
            }
            _ => ("<unknown>", String::from("<unknown>")),
        };
        let created = claim.claim().created().local().format("%b %d, %Y").to_string();
        table.add_row(row![
            if verbose { &id_full } else { &id_short },
            ty,
            val,
            created,
            format!("{}", claim.stamps().len()),
        ]);
    }
    table.printstd();
}

