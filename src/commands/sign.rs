use anyhow::{anyhow, Result};
use crate::{
    commands::{dag, id, keychain},
    config,
    db,
    util,
};
use stamp_aux::db::stage_transaction;
use stamp_core::{
    crypto::{
        base::Hash,
        sign::{self, Signature},
    },
    dag::{Transaction, TransactionBody},
    identity::{IdentityID},
    util::{base64_encode, base64_decode, SerdeBinary, Timestamp},
};
use std::convert::TryFrom;

pub fn sign_id(id_sign: &str, input: &str, output: &str, base64: bool, stage: bool, sign_with: Option<&str>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id_sign));
    let transactions = id::try_load_single_identity(id_sign)?;
    let identity_id = transactions.identity_id()
        .ok_or(anyhow!("Unable to generate identity id"))?;
    let identity = util::build_identity(&transactions)?;
    let msg_bytes = util::read_file(input)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| anyhow!("Incorrect passphrase: {}", e))?;
    let transaction = transactions.sign(&hash_with, Timestamp::now(), &hash_with, msg_bytes.as_slice())?;
    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    if stage {
        let msg = dag::post_save(&transactions, &signed, stage)?;
        stage_transaction(&identity_id, signed)
            .map_err(|e| anyhow!("Error staging transaction: {:?}", e))?;
        if let Some(msg) = msg {
            println!("{}", msg);
        }
    } else {
        let serialized = signed.serialize_binary()
            .map_err(|e| anyhow!("Problem serializing the signature: {}", e))?;
        if base64 {
            let base64 = base64_encode(serialized.as_slice());
            util::write_file(output, base64.as_bytes())?;
        } else {
            util::write_file(output, serialized.as_slice())?;
        };
    }
    Ok(())
}

pub fn sign_subkey(id_sign: &str, key_search_sign: Option<&str>, input: &str, output: &str, attached: bool, base64: bool) -> Result<()> {
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
    enum PolicyOrSub {
        Policy(Transaction),
        Subkey(Signature),
    }
    let signature = Transaction::deserialize_binary(sig_bytes.as_slice())
        .or_else(|_| {
            Transaction::deserialize_binary(&base64_decode(sig_bytes.as_slice())?)
        })
        .map(|x| PolicyOrSub::Policy(x))
        .or_else(|_| {
            Signature::deserialize_binary(sig_bytes.as_slice())
                .or_else(|_| {
                    Signature::deserialize_binary(&base64_decode(sig_bytes.as_slice())?)
                })
            .map(|x| PolicyOrSub::Subkey(x))
        })
        .map_err(|e| anyhow!("Error reading signature: {}", e))?;
    let res = match &signature {
        PolicyOrSub::Policy(transaction) => {
            let input_message = input_message
                .ok_or(anyhow!("A MESSAGE argument must be give when verifying an policy signature."))?;
            let message_bytes = util::read_file(&input_message)?;
            match transaction.entry().body() {
                TransactionBody::SignV1 { creator, body_hash } => {
                    let id_str = format!("{}", creator);
                    let creator_transactions = db::load_identity(&creator)?
                        .ok_or(anyhow!("Identity {} not found. Have you imported it?", id_str))?;
                    let creator_identity = util::build_identity(&creator_transactions)?;
                    // TODO: verify against past version of creator_transactions if verification
                    // fails and we have a non-empty previous_transactions. see issue #41
                    transaction.verify(Some(&creator_identity))
                        .map_err(|e| anyhow!("Policy signature invalid: {}", e))?;
                    match body_hash {
                        Hash::Blake3(..) => {
                            let compare = Hash::new_blake3(message_bytes.as_slice())?;
                            if &compare == body_hash {
                                Ok(())
                            } else {
                                Err(anyhow!("Policy signature hash ({}) does not match message hash ({})", body_hash, compare))
                            }
                        }
                    }
                }
                _ => Err(anyhow!("Invalid policy signature: invalid transaction type (expected `Sign` transaction)"))?,
            }
        }
        PolicyOrSub::Subkey(signature) => {
            let sig = match signature {
                Signature::Detached { sig } => sig,
                Signature::Attached { sig, .. } => sig,
            };
            let identity_id = sig.signed_by_identity();
            let key_id = sig.signed_by_key();
            let id_str = id_str!(identity_id)?;
            let transactions = db::load_identity(identity_id)?
                .ok_or(anyhow!("Identity {} not found. Have you imported it?", id_str))?;
            let identity = util::build_identity(&transactions)?;
            let subkey = identity.keychain().subkey_by_keyid(&key_id)
                .ok_or(anyhow!("Signing key {} not found in identity {}", key_id.as_string(), IdentityID::short(&id_str)))?;
            match signature {
                Signature::Detached { .. } => {
                    let input_message = input_message
                        .ok_or(anyhow!("A MESSAGE argument must be give when verifying a detached signature."))?;
                    let message_bytes = util::read_file(&input_message)?;
                    sign::verify(&subkey, signature, message_bytes.as_slice())
                        .map_err(|e| anyhow!("{}", e))
                }
                Signature::Attached { .. } => {
                    sign::verify_attached(&subkey, signature)
                        .map_err(|e| anyhow!("{}", e))
                }
            }
        }
    };
    match res {
        Ok(..) => {
            let green = dialoguer::console::Style::new().green();
            match signature {
                PolicyOrSub::Policy(trans) => {
                    let identity_id = match trans.entry().body() {
                        TransactionBody::SignV1 { creator, .. } => creator,
                        _ => Err(anyhow!("Problem pulling signature `creator` field from policy signature. Perhaps it is not a Sign transaction."))?,
                    };
                    let id_str_creator = id_str!(identity_id)?;
                    println!("This signature is {}! It is a policy signature made by the identity {}.", green.apply_to("valid"), id_str_creator);
                }
                PolicyOrSub::Subkey(sig) => {
                    let signed_obj = match sig {
                        Signature::Detached { sig } => sig,
                        Signature::Attached { sig, .. } => sig,
                    };
                    println!("This signature is {}! It is a subkey signature made by the identity {} with the key {}.", green.apply_to("valid"), signed_obj.signed_by_identity(), signed_obj.signed_by_key());
                }
            }
        }
        Err(e) => {
            let red = dialoguer::console::Style::new().red();
            eprintln!("{}: {}", red.apply_to("Invalid signature"), e);
        }
    }
    Ok(())
}

