use crate::util;
use stamp_core::{
    identity::{Identity, ClaimSpec, PublishedIdentity},
    key::{SecretKey, SignKeypair},
    private::MaybePrivate,
    util::{Timestamp, Lockable, ser},
};

fn prompt_claim_name_email(master_key: &SecretKey, id: Identity) -> Result<Identity, String> {
    println!("It's a good idea to associate your name and email with your identity.");
    if !util::yesno_prompt("Would you like to do this? [Y/n]", "y")? {
        return Ok(id);
    }
    let name: String = dialoguer::Input::new()
        .with_prompt("Your full name")
        .interact_text()
        .map_err(|e| format!("Error grabbing retry input: {:?}", e))?;
    let email: String = dialoguer::Input::new()
        .with_prompt("Your primary email")
        .interact_text()
        .map_err(|e| format!("Error grabbing retry input: {:?}", e))?;
    let id = id.make_claim(master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::Public(name)))
        .map_err(|e| format!("Error generating name claim: {:?}", e))?;
    let id = id.make_claim(master_key, Timestamp::now(), ClaimSpec::Email(MaybePrivate::Public(email)))
        .map_err(|e| format!("Error generating email claim: {:?}", e))?;
    Ok(id)
}

fn dump_id(master_key: &SecretKey, id: Identity) -> Result<(), String> {
    let published = PublishedIdentity::publish(master_key, id)
        .map_err(|e| format!("Problem creating published identity: {:?}", e))?;
    let yaml = published.serialize()
        .map_err(|e| format!("Problem serializing identity: {:?}", e))?;
    println!("{}", yaml);
    Ok(())
}

pub(crate) fn create_new() -> Result<(), String> {
    util::passphrase_note();
    let (identity, mut master_key) = util::with_new_passphrase("Your passphrase", |master_key, now| {
        let identity = Identity::new(master_key, now)
            .map_err(|err| format!("Failed to create identity: {:?}", err))?;
        Ok(identity)
    }, None)?;
    println!("");
    let id_str: String = identity.id().into();
    println!("Generated a new identity with the ID {}", id_str);
    println!("");
    let identity = prompt_claim_name_email(&master_key, identity)?;
    dump_id(&master_key, identity.clone())?;
    master_key.mem_unlock().map_err(|_| format!("Unable to unlock master key memory."))?;
    // TODO: save in db
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
        let based = ser::base64_encode(id.as_ref());
        if filter(&based) {
            break;
        }
    }

    util::passphrase_note();
    let (_, mut master_key) = util::with_new_passphrase("Your passphrase", |_master_key, _now| { Ok(()) }, Some(now.clone()))?;
    let alpha_keypair = alpha_keypair.rekey(&tmp_master_key, &master_key)
        .map_err(|e| format!("Error re-keying alpha keypair: {:?}", e))?;
    let identity = Identity::new_with_alpha_and_id(&master_key, now, alpha_keypair, id)
        .map_err(|err| format!("Failed to create identity: {:?}", err))?;
    let identity = prompt_claim_name_email(&master_key, identity)?;
    dump_id(&master_key, identity.clone())?;
    master_key.mem_unlock().map_err(|_| format!("Unable to unlock master key memory."))?;
    // TODO: save in db
    drop(identity);
    Ok(())
}

