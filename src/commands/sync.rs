use crate::{
    commands::{
        claim::claim_pre_noval,
    },
    db,
    util,
    SyncToken,
};
use stamp_core::{
    crypto::key::SecretKey,
    identity::keychain::RevocationReason,
};
use stamp_net::{Multiaddr};
use std::convert::TryFrom;

/// Generate a sync token or display the currently saved one.
pub(crate) fn token(id: &str, blind: bool, regen: bool) -> Result<(), String> {
    let (master_key, transactions) = claim_pre_noval(id)?;
    let do_regen = if regen { Some(RevocationReason::Superseded) } else { None };
    let (transactions, seckey, pubkey) = stamp_aux::sync::gen_token(&master_key, transactions, do_regen)
        .map_err(|e| format!("Error generating sync key: {}", e))?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    db::save_identity(transactions)?;
    // we can't pass around unencrypted keys by design, so instead we re-encrypt
    // the key with a well-known secret key that we can use to unlock it later.
    let pubkey_ser = pubkey.serialize()
        .map_err(|e| format!("Error serializing channel pubkey: {}", e))?;
    let channel = stamp_core::util::base64_encode(&pubkey_ser);
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
    Ok(())
}

/// Start a private sync listener. If the `join` option is pointed at an existing
/// stamp net node, the listener will join and participate in the larger stamp net
/// protocol.
pub(crate) fn listen(token: &SyncToken, bind: Multiaddr, join: Vec<Multiaddr>) -> Result<(), String> {
    stamp_aux::util::setup_tracing()
        .map_err(|e| format!("Error initializing tracing: {}", e))?;
    let shared_key = if let Some(base64_key) = token.shared_key.as_ref() {
        let bytes = stamp_core::util::base64_decode(base64_key)
            .map_err(|e| format!("Error decoding shared key: {}", e))?;
        let key = SecretKey::new_xchacha20poly1305_from_slice(&bytes[..])
            .map_err(|e| format!("Error decoding shared key: {}", e))?;
        Some(key)
    } else {
        None
    };
    stamp_aux::sync::listen(&token.identity_id, &token.channel, shared_key, bind, join)
        .map_err(|e| format!("Problem starting listener: {}", e))?;
    Ok(())
}

/// Run the sync. This is basically like [listen()][listen] but it quits after
/// grabbing the first round of identity transactions.
pub(crate) fn run(id: Option<String>, token_maybe: Option<SyncToken>, join: Vec<Multiaddr>) -> Result<(), String> {
    stamp_aux::util::setup_tracing()
        .map_err(|e| format!("Error initializing tracing: {}", e))?;
    let (id_str, shared_key) = match (token_maybe.as_ref(), id) {
        (Some(SyncToken { ref identity_id, shared_key: Some(ref base64_key), ..}), _) => {
            let bytes = stamp_core::util::base64_decode(base64_key)
                .map_err(|e| format!("Error decoding shared key: {}", e))?;
            let key = SecretKey::new_xchacha20poly1305_from_slice(&bytes[..])
                .map_err(|e| format!("Error decoding shared key: {}", e))?;
            (identity_id.clone(), key)
        }
        (None, Some(id)) => {
            let (master_key, transactions) = claim_pre_noval(&id)?;
            let identity = util::build_identity(&transactions)?;
            let id_str = id_str!(identity.id())?;
            let key = identity.keychain()
                .subkey_by_name("stamp/sync")
                .map(|x| x.key().as_secretkey().clone())
                .flatten()
                .map(|x| x.open(&master_key))
                .transpose()
                .map_err(|e| format!("Error opening sync key: {}", e))?
                .ok_or(format!("Missing stamp/sync subkey for identity {} (try using a full sync token instead)", id_str))?;
            (id_str, key)
        }
        _ => Err(format!("Error selecting identity"))?,
    };
    println!("id/key: {:?} / {:?}", id_str, shared_key);
    Ok(())
}

