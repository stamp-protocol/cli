use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto::key::SecretKey,
    identity::{
        ClaimBin,
        ClaimSpec,
        ClaimContainer,
        IdentityID,
        Relationship,
        RelationshipType,
        VersionedIdentity,
    },
    private::MaybePrivate,
    util::Timestamp,
};
use std::convert::TryFrom;

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
    let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", util::id_short(&id_str)), identity.created())?;
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
    let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", util::id_short(&id_str)), identity.created())?;
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
    let spec = ClaimSpec::PGP(maybe);
    claim_post(&master_key, identity, spec)?;
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

pub fn list(id: &str, private: bool, verbose: bool) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let master_key_maybe = if private {
        let master_key = util::passphrase_prompt(format!("Your master passphrase for identity {}", util::id_short(id)), identity.created())?;
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
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", util::id_short(id)), identity.created())?;
    let identity_mod = identity.remove_claim(&master_key, claim.claim().id())
        .map_err(|e| format!("There was a problem removing the claim: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Claim removed!");
    Ok(())
}

pub fn print_claims_table(claims: &Vec<ClaimContainer>, master_key_maybe: Option<SecretKey>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type", "Value", "Created", "# stamps"]);
    for claim in claims {
        let (id_full, id_short) = id_str_split!(claim.claim().id());
        let string_from_private = |private: &MaybePrivate<String>| -> String {
            if let Some(master_key) = master_key_maybe.as_ref() {
                private.open(master_key).unwrap_or_else(|e| format!("Decryption error: {}", e))
            } else {
                match private {
                    MaybePrivate::Public(val) => val.clone(),
                    MaybePrivate::Private(..) => {
                        String::from("<private>")
                    }
                }
            }
        };
        let bytes_from_private = |private: &MaybePrivate<ClaimBin>| -> String {
            if let Some(master_key) = master_key_maybe.as_ref() {
                private.open(master_key)
                    .map(|x| format!("<{} bytes>", x.len()))
                    .unwrap_or_else(|e| format!("Decryption error: {}", e))
            } else {
                match private {
                    MaybePrivate::Public(val) => format!("<{} bytes>", val.len()),
                    MaybePrivate::Private(..) => {
                        String::from("<private>")
                    }
                }
            }
        };
        let (ty, val) = match claim.claim().spec() {
            ClaimSpec::Identity(id) => {
                let (id_full, id_short) = id_str_split!(id);
                ("identity", if verbose { id_full } else { id_short })
            }
            ClaimSpec::Name(name) => ("name", string_from_private(name)),
            ClaimSpec::Email(email) => ("email", string_from_private(email)),
            ClaimSpec::Photo(photo) => ("photo", bytes_from_private(photo)),
            ClaimSpec::PGP(pgp) => ("pgp", string_from_private(pgp)),
            ClaimSpec::HomeAddress(address) => ("address", string_from_private(address)),
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

