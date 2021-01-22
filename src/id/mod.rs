use crate::{
    db,
    util
};
use stamp_core::{
    identity::{Identity, VersionedIdentity, ClaimSpec, PublishedIdentity},
    key::{SecretKey, SignKeypair},
    private::MaybePrivate,
    util::{Timestamp, Lockable},
};
use std::convert::TryFrom;

fn passphrase_note() {
    util::print_wrapped("To protect you identity's keychain, enter a long but memorable passphrase. Choose something personal that is easy for you to remember but hard for someone else to guess.\n\n  Example: my dog butch has a friend named snow\n\nYou can change this later using the `stamp keychain passwd` command.");
}

fn prompt_claim_name_email(master_key: &SecretKey, id: Identity) -> Result<Identity, String> {
    println!("It's a good idea to associate your name and email with your identity.");
    if !util::yesno_prompt("Would you like to do this? [Y/n]", "y")? {
        return Ok(id);
    }
    let name: String = dialoguer::Input::new()
        .with_prompt("Your full name")
        .interact_text()
        .map_err(|e| format!("Error grabbing name input: {:?}", e))?;
    let email: String = dialoguer::Input::new()
        .with_prompt("Your primary email")
        .interact_text()
        .map_err(|e| format!("Error grabbing email input: {:?}", e))?;
    let id = id.make_claim(master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public(name)))
        .map_err(|e| format!("Error generating name claim: {:?}", e))?;
    let id = id.make_claim(master_key, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public(email)))
        .map_err(|e| format!("Error generating email claim: {:?}", e))?;
    Ok(id)
}

pub fn try_load_single_identity(id: &str) -> Result<VersionedIdentity, String> {
    let identities = db::load_identities_by_prefix(id)?;
    if identities.len() > 1 {
        util::print_identities_table(&identities, false);
        Err(format!("Multiple identities matched that ID"))?;
    } else if identities.len() == 0 {
        Err(format!("No identities matches that ID"))?;
    }
    Ok(identities[0].clone())
}

pub(crate) fn create_new() -> Result<(), String> {
    passphrase_note();
    let (identity, mut master_key) = util::with_new_passphrase("Your passphrase", |master_key, now| {
        let identity = Identity::new(master_key, now)
            .map_err(|err| format!("Failed to create identity: {:?}", err))?;
        Ok(identity)
    }, None)?;
    println!("");
    let id_str = String::try_from(identity.id())
        .map_err(|e| format!("There was a problem converting the id {:?} to a string: {:?}", identity.id(), e))?;
    println!("Generated a new identity with the ID {}", id_str);
    println!("");
    let identity = prompt_claim_name_email(&master_key, identity)?;
    master_key.mem_unlock().map_err(|_| format!("Unable to unlock master key memory."))?;
    let location = db::save_identity(identity)?;
    println!("---\nSuccess! New identity saved to:\n  {}", location.to_string_lossy());
    Ok(())
}

pub(crate) fn create_vanity(regex: Option<&str>, contains: Vec<&str>, prefix: Option<&str>) -> Result<(), String> {
    let mut counter = 0;
    let regex = if let Some(re) = regex {
        Some(regex::Regex::new(re).map_err(|e| format!("Problem compiling regex: {:?}", e))?)
    } else {
        None
    };
    let mut filter = |id_str: &str| -> bool {
        counter += 1;
        if counter % 100000 == 0 {
            eprintln!("Searched {} IDs...", counter);
        }
        if let Some(regex) = regex.as_ref() {
            if !regex.is_match(id_str) {
                return false;
            }
        }
        if let Some(prefix) = prefix {
            if !id_str.starts_with(prefix) {
                return false;
            }
        }
        for needle in &contains {
            if !id_str.contains(needle) {
                return false;
            }
        }
        eprintln!("Found it! {}", id_str);
        return true;
    };
    println!("Starting vanity ID search, this might take a while.");

    let mut alpha_keypair;
    let mut id;
    let mut now;
    let tmp_master_key = SecretKey::new_xsalsa20poly1305();
    loop {
        now = Timestamp::now();
        alpha_keypair = SignKeypair::new_ed25519(&tmp_master_key)
            .map_err(|e| format!("Error generating alpha keypair: {:?}", e))?;
        id = Identity::create_id(&tmp_master_key, &alpha_keypair, &now)
            .map_err(|e| format!("Error generating ID: {:?}", e))?;
        let based = String::try_from(&id)
            .map_err(|e| format!("There was a problem converting the id {:?} to a string: {:?}", id, e))?;
        if filter(&based) {
            break;
        }
    }

    passphrase_note();
    let (_, mut master_key) = util::with_new_passphrase("Your passphrase", |_master_key, _now| { Ok(()) }, Some(now.clone()))?;
    let alpha_keypair = alpha_keypair.reencrypt(&tmp_master_key, &master_key)
        .map_err(|e| format!("Error re-keying alpha keypair: {:?}", e))?;
    let identity = Identity::new_with_alpha_and_id(&master_key, now, alpha_keypair, id)
        .map_err(|err| format!("Failed to create identity: {:?}", err))?;
    let identity = prompt_claim_name_email(&master_key, identity)?;
    master_key.mem_unlock().map_err(|_| format!("Unable to unlock master key memory."))?;
    let location = db::save_identity(identity)?;
    println!("---\nSuccess! New identity saved to:\n  {}", location.to_string_lossy());
    Ok(())
}

pub fn list(search: Option<&str>, verbose: bool) -> Result<(), String> {
    let identities = db::list_local_identities(search)?;
    util::print_identities_table(&identities, verbose);
    Ok(())
}

pub fn import(location: &str) -> Result<(), String> {
    drop(location);
    println!("IMPLEMENT ME!");
    Ok(())
}

pub fn export(id: &str) -> Result<(), String> {
    let identity = try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt("Passphrase for publish keypair", identity.created())?;
    let published = PublishedIdentity::publish(&master_key, identity)
        .map_err(|e| format!("Error creating published identity: {:?}", e))?;
    let serialized = published.serialize()
        .map_err(|e| format!("Error serializing identity: {:?}", e))?;
    println!("{}", serialized);
    Ok(())
}

pub fn delete(search: &str, skip_confirm: bool, permanent: bool, verbose: bool) -> Result<(), String> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() == 0 {
        Err(format!("No identities match that search"))?;
    }
    util::print_identities_table(&identities, verbose);
    if !skip_confirm {
        let msg = if permanent {
            format!("Permanently delete these {} identities? [y/N]", identities.len())
        } else {
            format!("Move these {} identities to the trash? [y/N]", identities.len())
        };
        if !util::yesno_prompt(&msg, "n")? {
            return Ok(());
        }
    }
    for identity in identities {
        let id = String::try_from(identity.id())
            .map_err(|e| format!("There was a problem converting the id {:?} to a string: {:?}", identity.id(), e))?;
        db::delete_identity(&id, permanent)?;
    }
    Ok(())
}

