use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto::{self, key::SecretKey},
    identity::{
        IdentityID,
        VersionedIdentity,
        keychain::{KeyID, Key, Subkey},
    },
    private::Private,
    util::{base64_encode, base64_decode},
};
use std::convert::TryFrom;

pub fn new(id: &str, ty: &str, name: &str, desc: Option<&str>) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
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
    print_keys_table(&keys, verbose, false);
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
        .ok_or(format!("Cannot find key {} in identity {}", search, IdentityID::short(&id_str)))?
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
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let identity_mod = identity.delete_subkey(&master_key, key.id())
        .map_err(|e| format!("Problem deleting subkey from keychain: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Key {} removed.", KeyID::short(&key_id));
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
        .ok_or(format!("Cannot find key {} in identity {}", search, IdentityID::short(&id_str)))?
        .clone();
    let key_id = id_str!(key.id())?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let identity_mod = identity.delete_subkey(&master_key, key.id())
        .map_err(|e| format!("Problem deleting subkey from keychain: {:?}", e))?;
    db::save_identity(identity_mod)?;
    println!("Key {} revoked.", KeyID::short(&key_id));
    Ok(())
}

pub fn passwd(id: &str, keyfile: Option<&str>, keyparts: Vec<&str>) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    fn master_key_from_base64_shamir_parts(parts: &Vec<&str>) -> Result<SecretKey, String> {
        let keyfile_parts = parts.iter()
            .map(|part| {
                base64_decode(part.trim()).map_err(|e| format!("Problem reading key part: {:?}", e))
            })
            .map(|part| {
                part.and_then(|x| {
                    sharks::Share::try_from(x.as_slice())
                        .map_err(|e| format!("Problem deserializing key part: {:?}", e))
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut key_bytes = None;
        for min_shares in (0..keyfile_parts.len()).rev() {
            let sharks = sharks::Sharks(min_shares as u8);
            match sharks.recover(keyfile_parts.as_slice()) {
                Ok(bytes) => {
                    key_bytes = Some(bytes);
                    break;
                }
                _ => {}
            }
        }
        let key_bytes = key_bytes.ok_or(format!("Could not reconstruct master key."))?;
        let master_key = crypto::key::SecretKey::new_xsalsa20poly1305_from_slice(key_bytes.as_slice())
            .map_err(|e| format!("Problem creating master key: {}", e))?;
        Ok(master_key)
    }

    let master_key = if let Some(keyfile) = keyfile {
        let keyfile_contents = util::read_file(keyfile)?;
        let keyfile_string = String::from_utf8(keyfile_contents)
            .map_err(|_| format!("Invalid keyfile format."))?;
        let keyfile_parts = keyfile_string.split("\n").collect::<Vec<_>>();
        let master_key = master_key_from_base64_shamir_parts(&keyfile_parts)?;
        identity.test_master_key(&master_key)
            .map_err(|e| format!("Incorrect master key: {}", e))?;
        util::print_wrapped("Successfully recovered master key from keyfile!\n");
        master_key
    } else if keyparts.len() > 0 {
        let master_key = master_key_from_base64_shamir_parts(&keyparts)?;
        identity.test_master_key(&master_key)
            .map_err(|e| format!("Incorrect master key: {}", e))?;
        util::print_wrapped("Successfully recovered master key from key parts!\n");
        master_key
    } else {
        let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
        identity.test_master_key(&master_key)
            .map_err(|e| format!("Incorrect passphrase: {}", e))?;
        master_key
    };
    let (_, new_master_key) = util::with_new_passphrase("Your new master passphrase", |_master_key, _now| { Ok(()) }, Some(identity.created().clone()))?;
    let identity_reencrypted = identity.reencrypt(&master_key, &new_master_key)
        .map_err(|e| format!("Password change failed: {}", e))?;
    // make sure it actually works before we save it...
    identity_reencrypted.test_master_key(&new_master_key)
        .map_err(|e| format!("Password change failed: {}", e))?;
    identity_reencrypted.verify()
        .map_err(|e| format!("Identity verification failed: {}", e))?;
    db::save_identity(identity_reencrypted)?;
    println!("Identity re-encrypted with new passphrase!");
    Ok(())
}

pub fn keyfile(id: &str, shamir: &str, output: &str) -> Result<(), String> {
    let mut shamir_parts = shamir.split("/");
    let min_shares: u8 = shamir_parts.next()
        .ok_or(format!("Invalid shamir format (must be \"M/S\")"))?
        .parse()
        .map_err(|_| format!("Invalid shamir format (must be \"M/S\")"))?;
    let num_shares: u8 = shamir_parts.next()
        .ok_or(format!("Invalid shamir format (must be \"M/S\")"))?
        .parse()
        .map_err(|_| format!("Invalid shamir format (must be \"M/S\")"))?;
    if min_shares > num_shares {
        Err(format!("Shamir minimum shares (M) must be equal or lesser to total shares (S)"))?;
    }
    let identity = id::try_load_single_identity(id)?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {}", e))?;
    let sharks = sharks::Sharks(min_shares);
    let dealer = sharks.dealer(master_key.as_ref());
    let shares: Vec<String> = dealer.take(num_shares as usize)
        .map(|x| base64_encode(Vec::from(&x).as_slice()))
        .collect::<Vec<_>>();
    util::write_file(output, shares.join("\n").as_bytes())
}

pub fn print_keys_table(keys: &Vec<&Subkey>, verbose: bool, choice: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let id_field = if verbose { "ID" } else { "ID (short)" };
    if choice {
        table.set_titles(row!["Choose", id_field, "Type", "Name", "Description", "Full"]);
    } else {
        table.set_titles(row![id_field, "Type", "Name", "Description", "Full"]);
    }
    let mut idx = 0;
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
        if choice {
            table.add_row(row![
                format!("{}", idx + 1),
                if verbose { &id_full } else { &id_short },
                ty,
                name,
                description,
                full,
            ]);
        } else {
            table.add_row(row![
                if verbose { &id_full } else { &id_short },
                ty,
                name,
                description,
                full,
            ]);
        }
        idx += 1;
    }
    table.printstd();
}

pub fn find_keys_by_search_or_prompt<T, F>(identity: &VersionedIdentity, key_search: Option<&str>, key_type: &str, key_filter: F) -> Result<Subkey, String>
    where F: Fn(&Subkey) -> Option<&T>,
{
    #[derive(Debug)]
    enum FoundOne {
        One(Subkey),
        Many(Vec<Subkey>),
        None,
    }

    fn choose_key_from(prompt: &str, keys: &Vec<&Subkey>) -> Option<Subkey> {
        print_keys_table(&keys, false, true);
        let choice = util::value_prompt(prompt).ok()?;
        let choice_idx: usize = choice.parse().ok()?;
        if choice_idx > 0 && keys.get(choice_idx - 1).is_some() {
            Some(keys[choice_idx - 1].clone())
        } else {
            None
        }
    }

    let key_maybe = if let Some(key_search) = key_search {
        match identity.keychain().subkey_by_name(key_search) {
            Some(key) => FoundOne::One(key.clone()),
            None => {
                let keys_from_id = identity.keychain().subkeys().iter()
                    .filter_map(|x| {
                        key_filter(x)?;
                        let id_str = id_str!(x.id()).ok()?;
                        if id_str.starts_with(key_search) { Some(x) } else { None }
                    })
                    .map(|x| x.clone())
                    .collect::<Vec<_>>();
                if keys_from_id.len() > 1 {
                    FoundOne::Many(keys_from_id)
                } else if keys_from_id.len() == 0 {
                    Err(format!("No `{}` keys match that search", key_type))?
                } else {
                    FoundOne::One(keys_from_id[0].clone())
                }
            }
        }
    } else {
        FoundOne::None
    };

    let key = match key_maybe {
        FoundOne::One(key) => key,
        FoundOne::Many(keys) => {
            let keys_as_ref = keys.iter().collect::<Vec<_>>();

            choose_key_from("Multiple keys matched your search. Choose which key you want: [1, 2, ...]", &keys_as_ref)
                .ok_or(format!("The key you chose isn't an option"))?
        }
        FoundOne::None => {
            let keys_as_ref = identity.keychain().subkeys().iter()
                .filter_map(|sub| {
                    key_filter(sub)?;
                    Some(sub)
                })
                .collect::<Vec<_>>();
            let len = keys_as_ref.len();
            if len == 1 {
                keys_as_ref[0].clone()
            } else if len > 1 {
                choose_key_from("Choose which of the keys you want to use: [1, 2, ...]", &keys_as_ref)
                    .ok_or(format!("The key you chose isn't an option"))?
            } else {
                Err(format!("The identity you are trying to send a message to has no `{}` keys.", key_type))?
            }
        }
    };
    Ok(key)
}

