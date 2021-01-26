use crate::{
    commands::id,
    db,
    util,
};

pub fn root_sig(id: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", util::id_short(id)), identity.created())?;
    let identity_signed = identity.root_sign(&master_key)
        .map_err(|e| format!("Error re-signing identity: {:?}", e))?;
    identity_signed.verify()
        .map_err(|e| format!("Re-signed identity verification failed: {:?}", e))?;
    db::save_identity(identity_signed)?;
    println!("Identity re-signed");
    Ok(())
}

pub fn resave(id: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    db::save_identity(identity)?;
    println!("Identity re-saved");
    Ok(())
}

