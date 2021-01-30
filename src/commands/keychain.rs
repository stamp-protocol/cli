use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto,
    identity::{
        keychain::{Key, Subkey},
    },
    private::Private,
};
use std::convert::TryFrom;

pub fn new(id: &str, ty: &str, name: &str, desc: Option<&str>) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", util::id_short(id)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let key = match ty {
        "sign" => {
            let new_key = crypto::key::SignKeypair::new_ed25519(&master_key)
                .map_err(|e| format!("Error generating key: {:?}", e))?;
            Key::new_sign(new_key)
        }
        "crypto" => {
            let new_key = crypto::key::CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key)
                .map_err(|e| format!("Error generating key: {:?}", e))?;
            Key::new_crypto(new_key)
        }
        "secret" => {
            let new_key = Private::seal(&master_key, &crypto::key::SecretKey::new_xsalsa20poly1305())
                .map_err(|e| format!("Error generating key: {:?}", e))?;
            Key::new_secret(new_key)
        }
        _ => Err(format!("Invalid key type: {}", ty))?,
    };
    let identity_mod = identity.add_subkey(&master_key, key, name, desc)
        .map_err(|e| format!("Problem adding key to identity: {:?}", e))?;
    let added_key = identity_mod.keychain().subkeys().iter()
        .rev()
        .find(|x| x.key().name() == name)
        .ok_or(format!("Problem finding new key"))?;
    let key_id = id_str!(added_key.id())?;
    db::save_identity(identity_mod)?;
    println!("New {} subkey added: {}!", ty, key_id);
    Ok(())
}

pub fn list(id: &str, search: Option<&str>, verbose: bool) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let keys = identity.keychain().subkeys().iter()
        .filter_map(|x| {
            if let Some(search) = search {
                id_str!(x.id()).ok()
                    .and_then(|id_str| {
                        if id_str.contains(search) || x.key().name().contains(search) {
                            Some(x)
                        } else {
                            None
                        }
                    })
            } else {
                Some(x)
            }
        })
        .collect::<Vec<_>>();
    print_keys_table(&keys, verbose);
    Ok(())
}

pub fn delete(id: &str, search: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let id_str = id_str!(identity.id())?;
    let key = identity.keychain().subkeys().iter()
        .rev()
        .find_map(|x| {
            id_str!(x.id()).ok()
                .and_then(|id_str| {
                    if id_str.starts_with(search) || x.key().name() == search {
                        Some(x)
                    } else {
                        None
                    }
                })
        })
        .ok_or(format!("Cannot find key {} in identity {}", search, util::id_short(&id_str)))?
        .clone();
    match key.key().key() {
        Key::Secret(..) | Key::ExtensionSecret(..) => {}
        _ => {
            util::print_wrapped("You are about to delete a non-secret key. It's generally a better idea to revoke instead of delete, otherwise it becomes impossible to decrypt old messages or verify old signatures you may have made.\n\n");
            if !util::yesno_prompt("Are you sure you want to delete this key? [y/N]", "n")? {
                return Ok(());
            }
        }
    }
    match key.key().key() {
        Key::Policy(..) | Key::Publish(..) | Key::Root(..) => {
            println!("");
            util::print_wrapped("You are about to delete a policy, publish, or root key. This is a terrible idea, unless you're absolutely sure you know what you're doing. This can seriously screw up your identity and render it useless. If you're dead set on this, please at least take a backup first with `stamp id export-private`.\n\n");
            if !util::yesno_prompt("Are you *really* sure you want to delete this key? [y/N]", "n")? {
                return Ok(());
            }
        }
        _ => {}
    }
    let key_id = id_str!(key.id())?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", util::id_short(&id_str)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let identity_mod = identity.delete_subkey(&master_key, key.id())
        .map_err(|e| format!("Problem deleting subkey from keychain: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Key {} removed from identity {}", util::id_short(&key_id), util::id_short(&id_str));
    Ok(())
}

pub fn revoke(id: &str, search: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let id_str = id_str!(identity.id())?;
    let key = identity.keychain().subkeys().iter()
        .rev()
        .find_map(|x| {
            id_str!(x.id()).ok()
                .and_then(|id_str| {
                    if id_str.starts_with(search) || x.key().name() == search {
                        Some(x)
                    } else {
                        None
                    }
                })
        })
        .ok_or(format!("Cannot find key {} in identity {}", search, util::id_short(&id_str)))?
        .clone();
    let key_id = id_str!(key.id())?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", util::id_short(&id_str)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let identity_mod = identity.delete_subkey(&master_key, key.id())
        .map_err(|e| format!("Problem deleting subkey from keychain: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Key {} removed from identity {}", util::id_short(&key_id), util::id_short(&id_str));
    Ok(())
}

pub fn passwd(id: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", util::id_short(id)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let (_, new_master_key) = util::with_new_passphrase("Your new master passphrase", |_master_key, _now| { Ok(()) }, Some(identity.created().clone()))?;
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

pub fn print_keys_table(keys: &Vec<&Subkey>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type", "Name", "Description", "Full"]);
    for key in keys {
        let (id_full, id_short) = id_str_split!(key.id());
        let ty = match key.key().key() {    // really? key.key().key()???
            Key::Policy(..) => "policy",
            Key::Publish(..) => "publish",
            Key::Root(..) => "root",
            Key::Sign(..) => "sign",
            Key::Crypto(..) => "crypto",
            Key::Secret(..) => "secret",
            Key::ExtensionKeypair(..) => "extension-pair",
            Key::ExtensionSecret(..) => "extension-secret",
        };
        let name = key.key().name();
        let description = key.key().description().as_ref().map(|x| x.clone()).unwrap_or(String::from(""));
        let full = if key.key().key().has_private() { "x" } else { "" };
        table.add_row(row![
            if verbose { &id_full } else { &id_short },
            ty,
            name,
            description,
            full,
        ]);
    }
    table.printstd();
}

