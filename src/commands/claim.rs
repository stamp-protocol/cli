use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto::key::SecretKey,
    identity::{
        ClaimID,
        ClaimBin,
        ClaimSpec,
        ClaimContainer,
        IdentityID,
        Relationship,
        RelationshipType,
        VersionedIdentity,
    },
    private::MaybePrivate,
    util::{Timestamp, Date},
};
use std::convert::TryFrom;
use std::str::FromStr;
use url::Url;

fn prompt_claim_value(prompt: &str) -> Result<String, String> {
    let value: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| format!("Error grabbing claim value: {:?}", e))?;
    Ok(value)
}

fn claim_pre(id: &str, prompt: &str) -> Result<(SecretKey, VersionedIdentity, String), String> {
    let identity = id::try_load_single_identity(id)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let value = prompt_claim_value(prompt)?;
    Ok((master_key, identity, value))
}

fn claim_post(master_key: &SecretKey, identity: VersionedIdentity, spec: ClaimSpec) -> Result<(), String> {
    let identity_mod = identity.make_claim(&master_key, Timestamp::now(), spec)
        .map_err(|e| format!("There was a problem adding the claim to your identity: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Claim added!");
    Ok(())
}

fn maybe_private<T>(master_key: &SecretKey, private: bool, value: T) -> Result<MaybePrivate<T>, String>
    where T: Clone + serde::ser::Serialize + serde::de::DeserializeOwned
{
    let maybe = if private {
        MaybePrivate::new_private(&master_key, value)
            .map_err(|e| format!("There was a problem creating the private claim: {:?}", e))?
    } else {
        MaybePrivate::new_public(value)
    };
    Ok(maybe)
}

pub fn new_id(id: &str) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter the ID of your other identity")?;
    let id = IdentityID::try_from(value.as_str())
        .map_err(|e| format!("Couldn't read id {}: {:?}", value, e))?;
    let spec = ClaimSpec::Identity(id);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_name(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter your name")?;
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Name(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_birthday(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter your date of birth (eg 1987-11-23)")?;
    let dob = Date::from_str(&value)
        .map_err(|e| format!("Could not read that date format: {}", e))?;
    let maybe = maybe_private(&master_key, private, dob)?;
    let spec = ClaimSpec::Birthday(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_email(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter your email")?;
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Email(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_photo(id: &str, photofile: &str, private: bool) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let id_str = id_str!(identity.id())?;
    let photo_bytes = util::read_file(photofile)?;
    const CUTOFF: usize = 1024 * 8;
    if photo_bytes.len() > (1024 * 8) {
        Err(format!("Please choose a photo smaller than {} bytes (given photo is {} bytes)", CUTOFF, photo_bytes.len()))?;
    }
    let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;

    let maybe = maybe_private(&master_key, private, ClaimBin::from(photo_bytes))?;
    let spec = ClaimSpec::Photo(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_pgp(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter your PGP ID")?;
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Pgp(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_domain(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter your domain name")?;
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::Domain(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_url(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter the URL you own")?;
    let url = url::Url::parse(&value)
        .map_err(|e| format!("Failed to parse URL: {}", e))?;
    let maybe = maybe_private(&master_key, private, url)?;
    let spec = ClaimSpec::Url(maybe);
    let identity_mod = identity.make_claim(&master_key, Timestamp::now(), spec)
        .map_err(|e| format!("There was a problem adding the claim to your identity: {:?}", e))?;
    let claim = identity_mod.claims().iter().last().ok_or(format!("Unable to find created claim"))?;
    let instant_values = claim.claim().instant_verify_allowed_values(identity_mod.id())
        .map_err(|e| format!("Problem grabbing allowed claim values: {}", e))?;
    db::save_identity(identity_mod)?;
    println!("{}", util::text_wrap(&format!("Claim added! You can finalize this claim and make it verifiable instantly to others by updating the URL {} to contain one of the following two values:\n\n  {}\n  {}\n", value, instant_values[0], instant_values[1])));
    Ok(())
}

pub fn new_address(id: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter your address")?;
    let maybe = maybe_private(&master_key, private, value)?;
    let spec = ClaimSpec::HomeAddress(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn new_relation(id: &str, ty: &str, private: bool) -> Result<(), String> {
    let (master_key, identity, value) = claim_pre(id, "Enter the identity ID of the relation")?;
    let rel_id = IdentityID::try_from(value.as_str())
        .map_err(|e| format!("Couldn't read id {}: {:?}", value, e))?;
    let reltype = match ty {
        "org" => RelationshipType::OrganizationMember,
        _ => Err(format!("Invalid relationship type: {}", ty))?,
    };
    let relationship = Relationship::new(reltype, rel_id);
    let maybe = maybe_private(&master_key, private, relationship)?;
    let spec = ClaimSpec::Relation(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
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
    let identity = db::find_identity_by_prefix("claim", claim_id)?
        .ok_or(format!("Identity with claim id {} was not found", claim_id))?;
    let id_str = id_str!(identity.id())?;
    let claim = identity.claims().iter()
        .find(|x| id_str!(x.claim().id()).map(|x| x.starts_with(claim_id)) == Ok(true))
        .ok_or(format!("Couldn't find the claim {} in identity {}", claim_id, IdentityID::short(&id_str)))?;
    let claim_id_str = id_str!(claim.claim().id())?;
    let errfn = |err: String| -> String {
        let red = dialoguer::console::Style::new().red();
        println!("\nThe claim {} {}\n", ClaimID::short(&claim_id_str), red.apply_to("could not be verified"));
        err
    };
    let instant_values = claim.claim().instant_verify_allowed_values(identity.id())
        .map_err(|e| format!("Could not get verification values for claim {}: {}", claim_id, e))?;
    match claim.claim().spec() {
        ClaimSpec::Domain(maybe) => {
            let domain = maybe.open_public().ok_or(format!("This claim is private, but must be public to be checked."))?;
        }
        ClaimSpec::Url(maybe) => {
            let url = maybe.open_public().ok_or(format!("This claim is private, but must be public to be checked."))?;
            let body = ureq::get(&url.clone().into_string())
                .set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .set("Accept-Language", "en-US,en;q=0.5")
                .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0")
                .call()
                .map_err(|e| {
                    match e {
                        ureq::Error::Status(code, res) => {
                            let res_str = res.into_string()
                                .unwrap_or_else(|e| format!("Could not map error response to string: {:?}", e));
                            format!("Problem calling GET on {}: {} -- {}", url, code, &res_str[0..std::cmp::min(100, res_str.len())])
                        },
                        _ => format!("Problem calling GET on {}: {}", url, e)
                    }
                })
                .map_err(errfn)?
                .into_string()
                .map_err(|e| format!("Problem grabbing output of {}: {}", url, e))
                .map_err(errfn)?;
            let mut found = false;
            for val in instant_values {
                if body.contains(&val) {
                    found = true;
                    break;
                }
            }
            if found {
                let green = dialoguer::console::Style::new().green();
                println!("\nThe claim {} has been {}!\n", ClaimID::short(&claim_id_str), green.apply_to("verified"));
                println!("{}", util::text_wrap(&format!("It is very likely that the identity {} owns the URL {}", IdentityID::short(&id_str), url)));
            } else {
                Err(errfn(format!("The URL {} does not contain any of the required values for verification", url)))?;
            }
        }
        _ => Err(format!("Claim checking is only available for domain or URL claim types."))?,
    }
    Ok(())
}

pub fn view(id: &str, claim_id: &str, output: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
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
    let identity = id::try_load_single_identity(id)?;
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

pub fn delete(id: &str, claim_id: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let mut found: Option<ClaimContainer> = None;
    for claim in identity.claims() {
        let id_str = id_str!(claim.claim().id())?;
        if id_str.starts_with(claim_id) {
            found = Some(claim.clone());
            break;
        }
    }
    let claim = found.ok_or(format!("Cannot find the claim {} in identity {}", claim_id, id))?;
    if !util::yesno_prompt(&format!("Really delete the claim {} and all of its stamps? [y/N]", claim_id), "n")? {
        return Ok(());
    }
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
    let identity_mod = identity.remove_claim(&master_key, claim.claim().id())
        .map_err(|e| format!("There was a problem removing the claim: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Claim removed!");
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

