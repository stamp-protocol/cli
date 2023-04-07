use anyhow::{anyhow, Result};
use crate::{
    commands::{id, keychain},
    db,
    util,
};
use stamp_core::{
    crypto::sign::{self, Signature},
    identity::{IdentityID},
    util::{base64_encode, base64_decode, SerdeBinary},
};
use std::convert::TryFrom;

pub fn sign(id_sign: &str, key_search_sign: Option<&str>, input: &str, output: &str, attached: bool, base64: bool) -> Result<()> {
    let transactions = id::try_load_single_identity(id_sign)?;
    let identity = util::build_identity(&transactions)?;
    let key_sign = keychain::find_keys_by_search_or_prompt(&identity, key_search_sign, "sign", |sub| sub.key().as_signkey())?;

    let msg_bytes = util::read_file(input)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {}", e))?;
    let signature = if attached {
        sign::sign_attached(&master_key, identity.id(), &key_sign, msg_bytes.as_slice())
            .map_err(|e| anyhow!("Problem creating signature: {}", e))?
    } else {
        sign::sign(&master_key, identity.id(), &key_sign, msg_bytes.as_slice())
            .map_err(|e| anyhow!("Problem creating signature: {}", e))?
    };
    let serialized = signature.serialize_binary()
        .map_err(|e| anyhow!("Problem serializing the signature: {}", e))?;
    if base64 {
        let base64 = base64_encode(serialized.as_slice());
        util::write_file(output, base64.as_bytes())?;
    } else {
        util::write_file(output, serialized.as_slice())?;
    };
    Ok(())
}

pub fn verify(input_signature: &str, input_message: Option<&str>) -> Result<()> {
    let sig_bytes = util::read_file(input_signature)?;
    let signature = Signature::deserialize_binary(sig_bytes.as_slice())
        .or_else(|_| {
            Signature::deserialize_binary(&base64_decode(sig_bytes.as_slice())?)
        })
        .map_err(|e| anyhow!("Error reading signature: {}", e))?;
    let sig = match &signature {
        Signature::Detached { sig } => sig,
        Signature::Attached { sig, .. } => sig,
    };
    let identity_id = sig.signed_by_identity();
    let key_id = sig.signed_by_key();
    let id_str = id_str!(identity_id)?;
    let transactions = db::load_identity(identity_id)?
        .ok_or(anyhow!("Identity {} not found. Have you imported it?", IdentityID::short(&id_str)))?;
    let identity = util::build_identity(&transactions)?;
    let subkey = identity.keychain().subkey_by_keyid(&key_id)
        .ok_or(anyhow!("Signing key {} not found in identity {}", key_id.as_string(), IdentityID::short(&id_str)))?;
    let res = match &signature {
        Signature::Detached { .. } => {
            let input_message = input_message
                .ok_or(anyhow!("A MESSAGE argument must be give when verifying a detached signature."))?;
            let message_bytes = util::read_file(&input_message)?;
            sign::verify(&subkey, &signature, message_bytes.as_slice())
        }
        Signature::Attached { .. } => {
            sign::verify_attached(&subkey, &signature)
        }
    };
    match res {
        Ok(..) => {
            let green = dialoguer::console::Style::new().green();
            println!("The signature is {}!", green.apply_to("valid"));
        }
        Err(e) => {
            let red = dialoguer::console::Style::new().red();
            eprintln!("{}: {}", red.apply_to("Invalid signature"), e);
        }
    }
    Ok(())
}

