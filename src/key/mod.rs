use crate::{
    db,
    id,
    util,
};

pub fn passwd(id: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt("Your current passphrase", identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let (_, new_master_key) = util::with_new_passphrase("Your new passphrase", |_master_key, _now| { Ok(()) }, Some(identity.created().clone()))?;
    let identity_reencrypted = identity.reencrypt(&master_key, &new_master_key)
        .map_err(|e| format!("Password change failed: {:?}", e))?;
    // make sure it actually works before we save it...
    identity_reencrypted.test_master_key(&new_master_key)
        .map_err(|e| format!("Password change failed: {:?}", e))?;
    identity_reencrypted.verify()
        .map_err(|e| format!("Identity verification failed: {:?}", e))?;
    db::save_identity(identity_reencrypted)?;
    println!("Identity re-encrypted with new passphrase!");
    Ok(())
}

