use anyhow::{anyhow, Result};
use crate::{
    commands::{
        id, dag,
        claim::claim_pre_noval,
    },
    config,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto::{
        self,
        base::{KeyID, SecretKey, rng},
    },
    identity::{
        Identity,
        IdentityID,
        keychain::{AdminKey, AdminKeypair, ExtendKeypair, Key, RevocationReason, Subkey},
    },
    private::PrivateWithMac,
    util::{Timestamp, Public, base64_encode, base64_decode},
};
use std::convert::{TryFrom, TryInto};

pub struct PrintableKey {
    key_id: KeyID,
    ty: String,
    name: String,
    description: Option<String>,
    revocation: Option<RevocationReason>,
    has_private: bool,
}

impl From<&AdminKey> for PrintableKey {
    fn from(key: &AdminKey) -> Self {
        PrintableKey {
            key_id: key.key().key_id(),
            ty: "admin".into(),
            name: key.name().clone(),
            description: key.description().clone(),
            revocation: key.revocation().clone(),
            has_private: key.has_private(),
        }
    }
}

impl From<&Subkey> for PrintableKey {
    fn from(key: &Subkey) -> Self {
        let ty = match key.key() {
            Key::Sign(..) => "sign",
            Key::Crypto(..) => "crypto",
            Key::Secret(..) => "secret",
        };
        PrintableKey {
            key_id: key.key_id(),
            ty: ty.into(),
            name: key.name().clone(),
            description: key.description().clone(),
            revocation: key.revocation().clone(),
            has_private: key.has_private(),
        }
    }
}

pub fn new(id: &str, ty: &str, name: &str, desc: Option<&str>, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let mut rng = rng::chacha20();
    let hash_with = config::hash_algo(Some(&id));
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
    identity.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;
    let transaction = match ty {
        "admin" => {
            let admin_keypair = AdminKeypair::new_ed25519(&mut rng, &master_key)
                .map_err(|e| anyhow!("Error generating key: {:?}", e))?;
            let admin_key = AdminKey::new(admin_keypair, name, desc);
            transactions.add_admin_key(&hash_with, Timestamp::now(), admin_key)
                .map_err(|e| anyhow!("Problem adding key to identity: {:?}", e))?
        }
        "sign" | "crypto" | "secret" => {
            let key = match ty {
                "sign" => {
                    let new_key = crypto::base::SignKeypair::new_ed25519(&mut rng, &master_key)
                        .map_err(|e| anyhow!("Error generating key: {:?}", e))?;
                    Key::new_sign(new_key)
                }
                "crypto" => {
                    let new_key = crypto::base::CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key)
                        .map_err(|e| anyhow!("Error generating key: {:?}", e))?;
                    Key::new_crypto(new_key)
                }
                "secret" => {
                    let rand_key = crypto::base::SecretKey::new_xchacha20poly1305(&mut rng)
                        .map_err(|e| anyhow!("Unable to generate key: {}", e))?;
                    let new_key = PrivateWithMac::seal(&master_key, rand_key)
                        .map_err(|e| anyhow!("Error generating key: {:?}", e))?;
                    Key::new_secret(new_key)
                }
                _ => Err(anyhow!("Invalid key type: {}", ty))?,
            };
            transactions.add_subkey(&hash_with, Timestamp::now(), key, name, desc)
                .map_err(|e| anyhow!("Problem adding key to identity: {:?}", e))?
        }
        _ => Err(anyhow!("Invalid key type: {}", ty))?,
    };
    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    dag::save_or_stage(transactions, signed, stage)?;
    Ok(())
}

pub fn list(id: &str, ty: Option<&str>, revoked: bool, search: Option<&str>) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let mut keys: Vec<PrintableKey> = Vec::new();
    let has_search = search.is_some();
    let search_str = search.unwrap_or("");
    if ty.is_none() || ty == Some("admin") {
        for k in identity.keychain().admin_keys() {
            let mut include = true;
            if include && has_search {
                include = k.name().contains(search_str);
            }
            if include && !revoked {
                include = k.revocation().is_none();
            }
            if include {
                keys.push(k.into());
            }
        }
    }
    if ty.is_none() || ty == Some("subkeys") || ty == Some("sign") || ty == Some("crypto") || ty == Some("secret") {
        for k in identity.keychain().subkeys() {
            let mut include = true;
            if include && ty == Some("sign") {
                include = k.key().as_signkey().is_some();
            }
            if include && ty == Some("crypto") {
                include = k.key().as_cryptokey().is_some();
            }
            if include && ty == Some("secret") {
                include = k.key().as_secretkey().is_some();
            }
            if include && !revoked {
                include = k.revocation().is_none();
            }
            if include {
                keys.push(k.into());
            }
        }
    }
    print_keys_table(&keys, false, revoked);
    Ok(())
}

pub fn update(id: &str, search: &str, name: Option<&str>, desc: Option<Option<&str>>, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id));
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let key_admin = identity.keychain().admin_key_by_name(search)
        .or_else(|| identity.keychain().admin_key_by_keyid_str(search));
    let key_subkey = identity.keychain().subkey_by_name(search)
        .or_else(|| identity.keychain().subkey_by_keyid_str(search));

    if key_admin.is_none() && key_subkey.is_none() {
        Err(anyhow!("Cannot find key {} in identity {}", search, IdentityID::short(&id_str)))?;
    }

    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;

    let (transaction, _key_id) = match (key_admin, key_subkey) {
        (Some(admin), _) => {
            let trans = transactions.edit_admin_key(&hash_with, Timestamp::now(), admin.key_id(), name, desc)
                .map_err(|e| anyhow!("Error updating admin key: {:?}", e))?;
            (trans, admin.key().key_id())
        }
        (_, Some(subkey)) => {
            let trans = transactions.edit_subkey(&hash_with, Timestamp::now(), subkey.key_id(), name, desc)
                .map_err(|e| anyhow!("Error updating subkey: {:?}", e))?;
            (trans, subkey.key_id())
        }
        _ => Err(anyhow!("Unreachable path. Odd."))?,
    };
    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    dag::save_or_stage(transactions, signed, stage)?;
    Ok(())
}

pub fn revoke(id: &str, search: &str, reason: &str, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id));
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let key_admin = identity.keychain().admin_key_by_name(search)
        .or_else(|| identity.keychain().admin_key_by_keyid_str(search));
    let key_subkey = identity.keychain().subkey_by_name(search)
        .or_else(|| identity.keychain().subkey_by_keyid_str(search));

    if key_admin.is_none() && key_subkey.is_none() {
        Err(anyhow!("Cannot find key {} in identity {}", search, IdentityID::short(&id_str)))?;
    }

    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;

    let rev_reason = match reason {
        "superseded" => RevocationReason::Superseded,
        "compromised" => RevocationReason::Compromised,
        "invalid" => RevocationReason::Invalid,
        _ => RevocationReason::Unspecified,
    };
    let (transaction, _key_id) = match (key_admin, key_subkey) {
        (Some(admin), _) => {
            let trans = transactions.revoke_admin_key(&hash_with, Timestamp::now(), admin.key_id(), rev_reason, None::<String>)
                .map_err(|e| anyhow!("Error revoking admin key: {:?}", e))?;
            (trans, admin.key().key_id())
        }
        (_, Some(subkey)) => {
            let trans = transactions.revoke_subkey(&hash_with, Timestamp::now(), subkey.key_id(), rev_reason, None::<String>)
                .map_err(|e| anyhow!("Error revoking subkey: {:?}", e))?;
            (trans, subkey.key_id())
        }
        _ => Err(anyhow!("Unreachable path. Odd."))?,
    };
    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    dag::save_or_stage(transactions, signed, stage)?;
    Ok(())
}

pub fn delete_subkey(id: &str, search: &str, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id));
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let key = identity.keychain().subkeys().iter()
        .rev()
        .find_map(|x| {
            if x.name() == search {
                Some(x)
            } else {
                None
            }
        })
        .ok_or(anyhow!("Cannot find key {} in identity {}", search, IdentityID::short(&id_str)))?
        .clone();
    match key.key() {
        Key::Secret(..) => {}
        _ => {
            util::print_wrapped("You are about to delete a non-secret key. It's generally a better idea to revoke instead of delete, otherwise it becomes impossible to decrypt old messages or verify old signatures you may have made.\n\n");
            if !util::yesno_prompt("Are you sure you want to delete this key? [y/N]", "n")? {
                return Ok(());
            }
        }
    }
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {:?}", e))?;
    let transaction = transactions.delete_subkey(&hash_with, Timestamp::now(), key.key_id())
        .map_err(|e| anyhow!("Problem deleting subkey from keychain: {:?}", e))?;
    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    dag::save_or_stage(transactions, signed, stage)?;
    Ok(())
}

pub fn passwd(id: &str, keyfile: Option<&str>, keyparts: Vec<&str>) -> Result<()> {
    let mut rng = rng::chacha20();
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    fn master_key_from_base64_shamir_parts(parts: &Vec<&str>) -> Result<SecretKey> {
        let keyfile_parts = parts.iter()
            .map(|part| {
                base64_decode(part.trim()).map_err(|e| anyhow!("Problem reading key part: {:?}", e))
            })
            .map(|part| {
                part.and_then(|x| {
                    sharks::Share::try_from(x.as_slice())
                        .map_err(|e| anyhow!("Problem deserializing key part: {:?}", e))
                })
            })
            .collect::<Result<Vec<_>>>()?;
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
        let key_bytes: [u8; 32] = key_bytes
            .ok_or(anyhow!("Could not reconstruct master key."))?
            .as_slice()
            .try_into()?;
        let master_key = crypto::base::SecretKey::new_xchacha20poly1305_from_bytes(key_bytes)
            .map_err(|e| anyhow!("Problem creating master key: {}", e))?;
        Ok(master_key)
    }

    let master_key = if let Some(keyfile) = keyfile {
        let keyfile_contents = util::read_file(keyfile)?;
        let keyfile_string = String::from_utf8(keyfile_contents)
            .map_err(|_| anyhow!("Invalid keyfile format."))?;
        let keyfile_parts = keyfile_string.split("\n").collect::<Vec<_>>();
        let master_key = master_key_from_base64_shamir_parts(&keyfile_parts)?;
        identity.test_master_key(&master_key)
            .map_err(|e| anyhow!("Incorrect master key: {}", e))?;
        util::print_wrapped("Successfully recovered master key from keyfile!\n");
        master_key
    } else if keyparts.len() > 0 {
        let master_key = master_key_from_base64_shamir_parts(&keyparts)?;
        identity.test_master_key(&master_key)
            .map_err(|e| anyhow!("Incorrect master key: {}", e))?;
        util::print_wrapped("Successfully recovered master key from key parts!\n");
        master_key
    } else {
        let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
        identity.test_master_key(&master_key)
            .map_err(|e| anyhow!("Incorrect passphrase: {}", e))?;
        master_key
    };
    let (_, new_master_key) = util::with_new_passphrase("Your new master passphrase", |_master_key, _now| { Ok(()) }, Some(identity.created().clone()))?;
    let transactions_reencrypted = transactions.reencrypt(&mut rng, &master_key, &new_master_key)
        .map_err(|e| anyhow!("Password change failed: {}", e))?;
    // make sure it actually works before we save it...
    transactions_reencrypted.test_master_key(&new_master_key)
        .map_err(|e| anyhow!("Password change failed: {}", e))?;
    db::save_identity(transactions_reencrypted)?;
    println!("Identity re-encrypted with new passphrase!");
    Ok(())
}

/// Generate a sync token or display the currently saved one.
pub(crate) fn sync_token(id: &str, blind: bool, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id));
    let (master_key, transactions) = claim_pre_noval(id)?;
    let (transaction_maybe, seckey) = stamp_aux::sync::gen_token(&master_key, &transactions, &hash_with)
        .map_err(|e| anyhow!("Error generating sync key: {}", e))?;
    let channel = stamp_aux::sync::shared_key_to_channel(&seckey)
        .map_err(|e| anyhow!("Error converting shared key to channel: {}", e))?;
    let identity = util::build_identity(&transactions)?;

    let has_transaction = transaction_maybe.is_some();
    if let Some(transaction) = transaction_maybe {
        let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
        dag::save_or_stage(transactions, signed, stage)?;
    }
    if !has_transaction || !stage {
        let id_str = id_str!(identity.id())?;
        let key_str = stamp_core::util::base64_encode(seckey.as_ref());
        if blind {
            let green = dialoguer::console::Style::new().green();
            eprintln!("Your blind sync token is:\n", );
            println!("{}:{}", &id_str[0..16], channel);
            eprintln!("\nThis token can be used on {} devices.", green.apply_to("untrusted"));
        } else {
            let red = dialoguer::console::Style::new().red();
            eprintln!("Your sync token is:\n");
            println!("{}:{}:{}", &id_str[0..16], channel, key_str);
            eprintln!("\nThis token must ONLY be used on trusted devices. {}", red.apply_to("Keep it safe!"));
            eprintln!("Use the -b option for generating an untrusted (blind) token.");
        }
    }
    Ok(())
}

pub fn keyfile(id: &str, shamir: &str, output: &str) -> Result<()> {
    let mut shamir_parts = shamir.split("/");
    let min_shares: u8 = shamir_parts.next()
        .ok_or(anyhow!("Invalid shamir format (must be \"M/S\")"))?
        .parse()
        .map_err(|_| anyhow!("Invalid shamir format (must be \"M/S\")"))?;
    let num_shares: u8 = shamir_parts.next()
        .ok_or(anyhow!("Invalid shamir format (must be \"M/S\")"))?
        .parse()
        .map_err(|_| anyhow!("Invalid shamir format (must be \"M/S\")"))?;
    if min_shares > num_shares {
        Err(anyhow!("Shamir minimum shares (M) must be equal or lesser to total shares (S)"))?;
    }
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(id)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {}", e))?;
    let sharks = sharks::Sharks(min_shares);
    let dealer = sharks.dealer(master_key.as_ref());
    let shares: Vec<String> = dealer.take(num_shares as usize)
        .map(|x| base64_encode(Vec::from(&x).as_slice()))
        .collect::<Vec<_>>();
    util::write_file(output, shares.join("\n").as_bytes())
}

pub fn print_keys_table(keys: &Vec<PrintableKey>, choice: bool, show_revoked: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let mut cols = Vec::with_capacity(7);
    if choice {
        cols.push("Choose");
    }
    cols.push("Name");
    cols.push("ID");
    cols.push("Type");
    cols.push("Description");
    cols.push("Owned");
    if show_revoked {
        cols.push("Revoked");
    }
    table.set_titles(prettytable::Row::new(cols.into_iter().map(|x| prettytable::Cell::new(x)).collect::<Vec<_>>()));
    let mut idx = 0;
    for key in keys {
        let description = key.description.as_ref().map(|x| x.clone()).unwrap_or(String::from(""));
        let full = if key.has_private { "x" } else { "" };
        let mut cols = Vec::with_capacity(7);
        if choice {
            cols.push(prettytable::Cell::new(format!("{}", idx + 1).as_str()));
        }
        cols.push(prettytable::Cell::new(&key.name));
        cols.push(prettytable::Cell::new(format!("{}", &key.key_id).as_str()));
        cols.push(prettytable::Cell::new(&key.ty));
        cols.push(prettytable::Cell::new(description.as_str()));
        cols.push(prettytable::Cell::new(full));
        if show_revoked {
            cols.push(prettytable::Cell::new(if key.revocation.is_some() { "x" } else { "" }));
        }
        table.add_row(prettytable::Row::new(cols));
        idx += 1;
    }
    table.printstd();
}

pub fn find_keys_by_search_or_prompt<T, F>(identity: &Identity, key_search: Option<&str>, key_type: &str, key_filter: F) -> Result<Subkey>
    where F: Fn(&Subkey) -> Option<&T>,
{
    #[derive(Debug)]
    enum FoundOne {
        One(Subkey),
        Many(Vec<Subkey>),
        None,
    }

    fn choose_key_from(prompt: &str, keys: &Vec<&Subkey>) -> Option<Subkey> {
        print_keys_table(&keys.iter().map(|x| x.clone().into()).collect::<Vec<_>>(), true, false);
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
                        if x.key_id().as_string().starts_with(key_search) {
                            Some(x)
                        } else {
                            None
                        }
                    })
                    .map(|x| x.clone())
                    .collect::<Vec<_>>();
                if keys_from_id.len() > 1 {
                    FoundOne::Many(keys_from_id)
                } else if keys_from_id.len() == 0 {
                    Err(anyhow!("No `{}` keys match that search", key_type))?
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
                .ok_or(anyhow!("The key you chose isn't an option"))?
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
                    .ok_or(anyhow!("The key you chose isn't an option"))?
            } else {
                Err(anyhow!("The identity you are trying to send a message to has no `{}` keys.", key_type))?
            }
        }
    };
    Ok(key)
}

