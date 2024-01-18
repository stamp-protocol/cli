use anyhow::{anyhow, Result};
use crate::{
    commands::{id, keychain},
    db,
    util,
};
use stamp_core::{
    crypto::{
        base::rng,
        message::{self, Message},
    },
    identity::IdentityID,
    util::{base64_encode, base64_decode, SerdeBinary},
};
use std::convert::TryFrom;

pub fn send(id_from: &str, key_search_from: Option<&str>, key_search_to: Option<&str>, input: &str, output: &str, search_to: &str, base64: bool) -> Result<()> {
    let mut rng = rng::chacha20();
    let transactions_from = id::try_load_single_identity(id_from)?;
    let identity_from = util::build_identity(&transactions_from)?;
    let identities = db::list_local_identities(Some(search_to))?;
    if identities.len() > 1 {
        let identities_vec = identities.iter()
            .map(|x| util::build_identity(x))
            .collect::<Result<Vec<_>>>()?;
        id::print_identities_table(&identities_vec, false);
        Err(anyhow!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(anyhow!("No identities match that search"))?;
    }
    let transactions_to = identities[0].clone();
    let identity_to = util::build_identity(&transactions_to)?;
    let key_from = keychain::find_keys_by_search_or_prompt(&identity_from, key_search_from, "crypto", |sub| sub.key().as_cryptokey())?;
    let key_to = keychain::find_keys_by_search_or_prompt(&identity_to, key_search_to, "crypto", |sub| sub.key().as_cryptokey())?;

    let msg_bytes = util::read_file(input)?;
    let id_str = id_str!(identity_from.id())?;
    let master_key_from = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity_from.created())?;
    transactions_from.test_master_key(&master_key_from)
        .map_err(|e| anyhow!("Incorrect passphrase: {}", e))?;
    let sealed = message::send(&mut rng, &master_key_from, identity_from.id(), &key_from, &key_to, msg_bytes.as_slice())
        .map_err(|e| anyhow!("Problem sealing the message: {}", e))?;
    let serialized = sealed.serialize_binary()
        .map_err(|e| anyhow!("Problem serializing the sealed message: {}", e))?;
    if base64 {
        let base64 = base64_encode(serialized.as_slice());
        util::write_file(output, base64.as_bytes())?;
    } else {
        util::write_file(output, serialized.as_slice())?;
    };
    Ok(())
}

pub fn send_anonymous(key_search_to: Option<&str>, input: &str, output: &str, search_to: &str, base64: bool) -> Result<()> {
    let mut rng = rng::chacha20();
    let identities = db::list_local_identities(Some(search_to))?;
    if identities.len() > 1 {
        let identities_vec = identities.iter()
            .map(|x| util::build_identity(x))
            .collect::<Result<Vec<_>>>()?;
        id::print_identities_table(&identities_vec, false);
        Err(anyhow!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(anyhow!("No identities match that search"))?;
    }
    let transactions_to = identities[0].clone();
    let identity_to = util::build_identity(&transactions_to)?;
    let key_to = keychain::find_keys_by_search_or_prompt(&identity_to, key_search_to, "crypto", |sub| sub.key().as_cryptokey())?;

    let msg_bytes = util::read_file(input)?;
    let sealed = message::send_anonymous(&mut rng, &key_to, msg_bytes.as_slice())
        .map_err(|e| anyhow!("Problem sealing the message: {}", e))?;
    let serialized = sealed.serialize_binary()
        .map_err(|e| anyhow!("Problem serializing the sealed message: {}", e))?;
    if base64 {
        let base64 = base64_encode(serialized.as_slice());
        util::write_file(output, base64.as_bytes())?;
    } else {
        util::write_file(output, serialized.as_slice())?;
    };
    Ok(())
}

pub fn open(id_to: &str, key_search_open: Option<&str>, input: &str, output: &str) -> Result<()> {
    let transactions_to = id::try_load_single_identity(id_to)?;
    let identity_to = util::build_identity(&transactions_to)?;
    let sealed_bytes = util::read_file(input)?;
    let sealed_message = Message::deserialize_binary(sealed_bytes.as_slice())
        .or_else(|_| {
            Message::deserialize_binary(&base64_decode(sealed_bytes.as_slice())?)
        })
        .map_err(|e| anyhow!("Error reading sealed message: {}", e))?;
    macro_rules! dry {
        ({$master_key:ident, $key_to:ident, $sealed_message:ident } $opener:expr) => {
            let $key_to = keychain::find_keys_by_search_or_prompt(&identity_to, key_search_open, "crypto", |sub| sub.key().as_cryptokey())?;
            let id_str = id_str!(identity_to.id())?;
            let $master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity_to.created())?;
            identity_to.test_master_key(&$master_key)
                .map_err(|e| anyhow!("Incorrect passphrase: {}", e))?;
            $opener
                .map_err(|e| anyhow!("Problem opening message: {}", e))?
        }
    }
    let opened = match &sealed_message {
        Message::Anonymous(_) => {
            dry!{
                { master_key_to, key_to, bytes }
                message::open_anonymous(&master_key_to, &key_to, &sealed_message)
            }
        }
        Message::Signed(signed_msg) => {
            let transactions_from = db::load_identity(signed_msg.signed_by_identity())?
                .ok_or(anyhow!("The identity that sent this message has not been imported, see the `stamp id import` command"))?;
            let identity_from = util::build_identity(&transactions_from)?;
            let key_from = identity_from.keychain().subkey_by_keyid(&signed_msg.signed_by_key())
                .ok_or(anyhow!("The identity that send this message is missing the key used to sign the message"))?;
            dry!{
                { master_key_to, key_to, bytes }
                message::open(&master_key_to, &key_to, &key_from, &sealed_message)
            }
        }
    };
    util::write_file(output, opened.as_slice())?;
    Ok(())
}

