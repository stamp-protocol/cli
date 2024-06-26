use crate::{
    commands::{dag, id, stamp},
    config, db, util,
};
use anyhow::{anyhow, Result};
use prettytable::Table;
use stamp_aux;
use stamp_core::{
    crypto::{
        base::{rng, SecretKey},
        private::MaybePrivate,
    },
    dag::{TransactionID, Transactions},
    identity::{
        claim::{Claim, ClaimID, ClaimSpec, RelationshipType},
        stamp::Stamp,
        Identity, IdentityID,
    },
    rasn::{Decode, Encode},
    util::{BinaryVec, Date, Public, SerText, Timestamp, Url},
};
use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;

fn prompt_claim_value(prompt: &str) -> Result<String> {
    let value: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| anyhow!("Error grabbing claim value: {:?}", e))?;
    Ok(value)
}

// TODO: this has nothing to do with claims...? Move somewhere more appropriate.
pub(crate) fn claim_pre_noval(id: &str) -> Result<(SecretKey, Transactions)> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let master_key =
        util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions
        .test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;
    Ok((master_key, transactions))
}

pub(crate) fn claim_pre(id: &str, prompt: &str) -> Result<(SecretKey, Transactions, String)> {
    let (master_key, transactions) = claim_pre_noval(id)?;
    let value = prompt_claim_value(prompt)?;
    Ok((master_key, transactions, value))
}

fn unwrap_maybe<T, F>(maybe: &MaybePrivate<T>, masterkey_fn: F) -> Result<T>
where
    T: Encode + Decode + Clone,
    F: FnOnce() -> Result<SecretKey>,
{
    if maybe.has_private() {
        let master_key = masterkey_fn()?;
        maybe.open(&master_key).map_err(|e| anyhow!("Unable to open private claim: {}", e))
    } else {
        let mut rng = rng::chacha20();
        let fake_master_key = SecretKey::new_xchacha20poly1305(&mut rng).map_err(|e| anyhow!("Unable to generate key: {}", e))?;
        maybe.open(&fake_master_key).map_err(|e| anyhow!("Unable to open claim: {}", e))
    }
}

pub fn check(claim_id: &str) -> Result<()> {
    let transactions =
        db::find_identity_by_prefix("claim", claim_id)?.ok_or(anyhow!("Identity with claim id {} was not found", claim_id))?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let claim = identity
        .claims()
        .iter()
        .find(|x| id_str!(x.id()).map(|x| x.starts_with(claim_id)).ok() == Some(true))
        .ok_or(anyhow!("Couldn't find the claim {} in identity {}", claim_id, IdentityID::short(&id_str)))?;
    let claim_id_str = id_str!(claim.id())?;
    match stamp_aux::claim::check_claim(&transactions, claim) {
        Ok(url) => {
            let green = dialoguer::console::Style::new().green();
            println!("\nThe claim {} has been {}!\n", ClaimID::short(&claim_id_str), green.apply_to("verified"));
            println!(
                "{}",
                util::text_wrap(&format!(
                    "It is very likely that the identity {} owns the resource {}",
                    IdentityID::short(&id_str),
                    url
                ))
            );
            Ok(())
        }
        Err(err) => {
            let red = dialoguer::console::Style::new().red();
            println!("\nThe claim {} {}\n", ClaimID::short(&claim_id_str), red.apply_to("could not be verified"));
            Err(anyhow!("{}", err))
        }
    }
}

pub fn view(id: &str, claim_id: &str, output: &str) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let mut found: Option<Claim> = None;
    for claim in identity.claims() {
        let id_str = id_str!(claim.id())?;
        if id_str.starts_with(claim_id) {
            found = Some(claim.clone());
            break;
        }
    }
    let claim = found.ok_or(anyhow!("Cannot find the claim {} in identity {}", claim_id, id))?;
    if claim.has_private() && !identity.is_owned() {
        Err(anyhow!("You cannot view private claims on an identity you don't own."))?;
    }

    let id_str = id_str!(identity.id())?;
    let masterkey_fn = || {
        let master_key =
            util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
        identity
            .test_master_key(&master_key)
            .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;
        Ok(master_key)
    };

    let output_bytes = match claim.spec() {
        ClaimSpec::Identity(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(id_str!(&val)?.as_bytes())
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
        ClaimSpec::Address(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        ClaimSpec::PhoneNumber(maybe) => {
            let val = unwrap_maybe(maybe, masterkey_fn)?;
            Vec::from(val.as_bytes())
        }
        _ => Err(anyhow!("Viewing is not implemented for this claim type"))?,
    };
    util::write_file(output, output_bytes.as_slice())?;
    Ok(())
}

pub fn list(id: &str, private: bool, verbose: bool) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let master_key_maybe = if private {
        let id_str = id_str!(identity.id())?;
        let master_key =
            util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
        identity
            .test_master_key(&master_key)
            .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;
        Some(master_key)
    } else {
        None
    };
    let ts_fake = Timestamp::from_str("0000-01-01T00:00:00.000Z").map_err(|e| anyhow!("Error creating fake timestamp: {:?}", e))?;
    let claim_list = identity
        .claims()
        .iter()
        .map(|claim| {
            let claim_id: TransactionID = claim.id().deref().clone();
            let ts = transactions
                .iter()
                .find(|t| t.id() == &claim_id)
                .map(|t| t.entry().created().clone())
                .unwrap_or_else(|| ts_fake.clone());
            (claim.clone(), ts)
        })
        .collect::<Vec<_>>();
    print_claims_table(&claim_list, master_key_maybe, verbose);
    Ok(())
}

pub fn stamp_list(id: &str, claim_id_or_name: &str, verbose: bool) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let claim = identity
        .claims()
        .iter()
        .find(|x| {
            x.name().as_ref().map(|y| y == claim_id_or_name).unwrap_or(false)
                || id_str!(x.id()).unwrap_or("".into()).starts_with(claim_id_or_name)
        })
        .ok_or_else(|| anyhow!("Could not find claim {} in identity {}.", claim_id_or_name, id_str))?;
    let stamps = claim.stamps().iter().collect::<Vec<_>>();
    stamp::print_stamps_table(&stamps, verbose, false)?;
    Ok(())
}

fn find_stamp_by_id<'a>(identity: &'a Identity, stamp_id: &str) -> Option<&'a Stamp> {
    identity.claims().iter().find_map(|c| {
        c.stamps()
            .iter()
            .find(|s| id_str!(s.id()).unwrap_or("".into()).starts_with(stamp_id))
    })
}

pub fn stamp_view(id: &str, stamp_id: &str) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let stamp =
        find_stamp_by_id(&identity, stamp_id).ok_or_else(|| anyhow!("Could not find stamp {} in identity {}.", stamp_id, id_str))?;
    let stamp_text = stamp
        .serialize_text()
        .map_err(|e| anyhow!("Problem serializing stamp transaction: {:?}", e))?;
    println!("{}", stamp_text);
    Ok(())
}

pub fn stamp_delete(id: &str, stamp_id: &str, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id));
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let stamp =
        find_stamp_by_id(&identity, stamp_id).ok_or_else(|| anyhow!("Could not find stamp {} in identity {}.", stamp_id, id_str))?;
    let stamp_text = stamp
        .serialize_text()
        .map_err(|e| anyhow!("Problem serializing stamp transaction: {:?}", e))?;
    println!("{}", stamp_text);
    println!("----------");
    if !util::yesno_prompt("Do you wish to delete the above stamp? [Y/n]", "Y")? {
        println!("Aborted.");
        return Ok(());
    }
    let trans = transactions
        .delete_stamp(&hash_with, Timestamp::now(), stamp.id().clone())
        .map_err(|e| anyhow!("Problem creating stamp delete transaction: {:?}", e))?;
    let master_key = util::passphrase_prompt(
        &format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)),
        identity.created(),
    )?;
    let signed = util::sign_helper(&identity, trans, &master_key, stage, sign_with)?;
    dag::save_or_stage(transactions, signed, stage)?;
    Ok(())
}

pub fn print_claims_table(claims: &Vec<(Claim, Timestamp)>, master_key_maybe: Option<SecretKey>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let id_field = if verbose { "ID" } else { "ID (short)" };
    table.set_titles(row![id_field, "Name", "Type", "Value", "Created", "# stamps"]);
    for (claim, created_ts) in claims {
        let (id_full, id_short) = id_str_split!(claim.id());
        macro_rules! extract_str {
            ($maybe:expr, $tostr:expr) => {
                if let Some(master_key) = master_key_maybe.as_ref() {
                    $maybe
                        .open(master_key)
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
                        MaybePrivate::Public(val) => $tostr(val.clone()),
                        MaybePrivate::Private { .. } => {
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
        let name = claim.name().as_ref().map(|x| x.clone()).unwrap_or("-".into());
        let (ty, val) = match claim.spec() {
            ClaimSpec::Identity(id) => (
                "identity",
                extract_str!(id, |x: IdentityID| {
                    let (id_full, id_short) = id_str_split!(&x);
                    if verbose {
                        id_full
                    } else {
                        id_short
                    }
                }),
            ),
            ClaimSpec::Name(name) => ("name", extract_str!(name)),
            ClaimSpec::Birthday(birthday) => ("birthday", extract_str!(birthday, |x: Date| x.to_string())),
            ClaimSpec::Email(email) => ("email", extract_str!(email)),
            ClaimSpec::Photo(photo) => ("photo", extract_str!(photo, |x: BinaryVec| format!("<{} bytes>", x.len()))),
            ClaimSpec::Pgp(pgp) => ("pgp", extract_str!(pgp)),
            ClaimSpec::Domain(domain) => ("domain", extract_str!(domain)),
            ClaimSpec::Url(url) => ("url", extract_str!(url, |x: Url| String::from(x))),
            ClaimSpec::Address(address) => ("address", extract_str!(address)),
            ClaimSpec::PhoneNumber(number) => ("phone #", extract_str!(number)),
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
                    MaybePrivate::Private { .. } => String::from("******"),
                };
                ("relation", rel_str)
            }
            _ => ("<unknown>", String::from("<unknown>")),
        };
        let created = created_ts.local().format("%b %d, %Y").to_string();
        table.add_row(row![
            if verbose { &id_full } else { &id_short },
            name,
            ty,
            val,
            created,
            format!("{}", claim.stamps().len()),
        ]);
    }
    table.printstd();
}
