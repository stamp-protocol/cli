use crate::{
    db,
    id,
    util,
};
use stamp_core::{
    identity::{
        ClaimSpec,
        IdentityID,
        Relationship,
        RelationshipType,
        VersionedIdentity,
    },
    key::SecretKey,
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
    let master_key = util::passphrase_prompt("Your passphrase", identity.created())?;
    let value = prompt_claim_value(prompt)?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
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
        "family" => RelationshipType::Family,
        "friend" => RelationshipType::Friend,
        "org" => RelationshipType::OrganizationMember,
        _ => Err(format!("Invalid relationship type: {}", ty))?,
    };
    let relationship = Relationship::new(reltype, rel_id);
    let maybe = maybe_private(&master_key, private, relationship)?;
    let spec = ClaimSpec::Relation(maybe);
    claim_post(&master_key, identity, spec)?;
    Ok(())
}

pub fn list(id: &str, verbose: bool) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    util::print_claims_table(identity.claims(), verbose);
    Ok(())
}

