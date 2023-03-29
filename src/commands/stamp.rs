use crate::{
    commands::{dag, id},
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    crypto::message::{Message},
    dag::{TransactionID},
    identity::{
        ClaimID, Confidence, StampEntry, StampRequest, Stamp, IdentityID,
        stamp::RevocationReason,
    },
    util::{Timestamp, SerdeBinary, SerText, base64_decode},
};
use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;

pub fn new(our_identity_id: &str, claim_id: &str, stage: bool, sign_with: Option<&str>) -> Result<(), String> {
    let our_transactions = id::try_load_single_identity(our_identity_id)?;
    let their_transactions = db::find_identity_by_prefix("claim", claim_id)?
        .ok_or(format!("Identity with claim {} not found", claim_id))?;
    let our_identity = util::build_identity(&our_transactions)?;
    let their_identity = util::build_identity(&their_transactions)?;
    let claim = their_identity.claims()
        .iter()
        .find_map(|x| {
            match id_str!(x.id()) {
                Ok(id) => if id.starts_with(claim_id) { Some(x) } else { None },
                Err(..) => None,
            }
        })
        // weird if we got here, but let's handle it gracefully...
        .ok_or(format!("Claim {} not found in identity {}", claim_id, id_str!(their_identity.id())?))?;
    let their_id_str = id_str!(their_identity.id())?;
    let claim_id_str = id_str!(claim.id())?;
    util::print_wrapped(&format!("You are about to stamp the claim {} made by the identity {}.\n", ClaimID::short(&claim_id_str), IdentityID::short(&their_id_str)));
    util::print_wrapped("Effectively, you are vouching for them and that their claim is true. You can specify your confidence in the claim:\n");
    util::print_wrapped("    none\n");
    util::print_wrapped_indent("you are not verifying the claim at all, but wish to stamp it anyway\n", "        ");
    util::print_wrapped("    low\n");
    util::print_wrapped_indent("you have done a quick and dirty verification of the claim\n", "        ");
    util::print_wrapped("    medium\n");
    util::print_wrapped_indent("you're doing a decent amount of verification, such as having them click a verification link in email\n", "        ");
    util::print_wrapped("    high\n");
    util::print_wrapped_indent("you have verified the claim extensively (birth certificates, retinal scans, fingerprint matching, etc)\n", "        ");
    util::print_wrapped("    extreme\n");
    util::print_wrapped_indent("you have known this person for the last 50 years and can be absolutely certain that the claim they are making is correct and they are not a hologram or an android imposter\n", "        ");
    let confidence_val = util::value_prompt("\nHow confident are you in this claim?")?;
    let confidence = match confidence_val.as_str() {
        "none" => Confidence::None,
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        "extreme" => Confidence::Extreme,
         _ => Err(format!("Invalid confidence value: {}", confidence_val))?,
    };
    let expires: Option<Timestamp> = if util::yesno_prompt("Would you like your stamp to expire on a certain date? [y/N]", "n")? {
        let expire_val = util::value_prompt("What date would you like it to expire? [ex 2024-10-13T12:00:00Z]")?;
        let ts: Timestamp = expire_val.parse()
            .map_err(|e| format!("Error parsing time: {}: {:?}", expire_val, e))?;
        Some(ts)
    } else {
        None
    };
    let our_id = id_str!(our_identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&our_id)), our_identity.created())?;
    our_transactions.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let stamp_entry = StampEntry::new(our_identity.id().clone(), their_identity.id().clone(), claim.id().clone(), confidence, expires);
    let transaction = our_transactions.make_stamp(Timestamp::now(), stamp_entry)
        .map_err(|e| format!("Error making stamp: {:?}", e))?;
    let signed = util::sign_helper(&our_identity, transaction, &master_key, stage, sign_with)?;
    dag::save_or_stage(our_transactions, signed, stage)?;
    Ok(())
}

pub fn request(our_identity_id: &str, claim_search: &str, our_crypto_subkey_search: &str, stamper_identity_id: &str, stamper_crypto_subkey_search: &str) -> Result<Vec<u8>, String> {
    let our_transactions = id::try_load_single_identity(our_identity_id)?;
    let stamper_transactions = id::try_load_single_identity(stamper_identity_id)?;
    let our_identity = util::build_identity(&our_transactions)?;
    let our_id = id_str!(our_identity.id())?;
    let stamper_identity = util::build_identity(&stamper_transactions)?;
    let key_from = our_identity.keychain().subkeys().iter()
        .find(|k| {
            k.key_id().as_string().starts_with(our_crypto_subkey_search) ||
                k.name() == our_crypto_subkey_search
        })
        .ok_or_else(|| format!("Cannot find `from` key {}", our_crypto_subkey_search))?;
    let key_to = stamper_identity.keychain().subkeys().iter()
        .find(|k| {
            k.key_id().as_string().starts_with(stamper_crypto_subkey_search) ||
                k.name() == stamper_crypto_subkey_search
        })
        .ok_or_else(|| format!("Cannot find `to` key {}", our_crypto_subkey_search))?;
    let claim = our_identity.claims().iter()
        .find(|x| {
            let claim_id = String::try_from(x.id()).unwrap_or("".into());
            claim_id.starts_with(claim_search) ||
                x.name().as_ref().map(|x| x == claim_search).unwrap_or(false)
        })
        .ok_or_else(|| format!("Cannot find claim {}", claim_search))?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&our_id)), our_identity.created())?;
    our_transactions.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let req_message = StampRequest::new(&master_key, our_identity.id(), &key_from, &key_to, claim)
        .map_err(|e| format!("Problem creating stamp request: {:?}", e))?;
    let bytes = req_message.serialize_binary()
        .map_err(|e| format!("Problem serializing stamp request: {:?}", e))?;
    Ok(bytes)
}

pub fn open_request(our_identity_id: &str, our_crypto_subkey_search: &str, req: &str) -> Result<(), String> {
    let our_transactions = id::try_load_single_identity(our_identity_id)?;
    let our_identity = util::build_identity(&our_transactions)?;
    let our_id = id_str!(our_identity.id())?;
    let key_to = our_identity.keychain().subkeys().iter()
        .find(|k| {
            k.key_id().as_string().starts_with(our_crypto_subkey_search) ||
                k.name() == our_crypto_subkey_search
        })
        .ok_or_else(|| format!("Cannot find `to` key {}", our_crypto_subkey_search))?;
    let sealed_bytes = util::read_file(req)?;
    let sealed_message = Message::deserialize_binary(sealed_bytes.as_slice())
        .or_else(|_| {
            Message::deserialize_binary(&base64_decode(sealed_bytes.as_slice())?)
        })
        .map_err(|e| format!("Error reading sealed message: {}", e))?;
    let signed_message = sealed_message.signed()
        .ok_or_else(|| format!("Invalid stemp request message"))?;
    let stampee_identity_id = signed_message.signed_by_identity();
    let stampee_key_id = signed_message.signed_by_key();
    let stampee_identity_id_str = id_str!(stampee_identity_id)?;
    let stampee_transactions = id::try_load_single_identity(&stampee_identity_id_str)?;
    let stampee_identity = util::build_identity(&stampee_transactions)?;
    let key_from = stampee_identity.keychain().subkey_by_keyid(stampee_key_id)
        .ok_or_else(|| format!("Cannot find `from` key {:?}", stampee_key_id))?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&our_id)), our_identity.created())?;
    our_transactions.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let claim = StampRequest::open(&master_key, &key_to, &key_from, &sealed_message)
        .map_err(|e| format!("Problem opening stamp request: {:?}", e))?;
    let claim_str = claim.serialize_text()
        .map_err(|e| format!("Problem serializing claim: {:?}", e))?;
    println!("{}", claim_str);
    Ok(())
}

pub fn list(id: &str, revoked: bool, verbose: bool) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let ts_fake = Timestamp::from_str("0000-01-01T00:00:00.000Z")
        .map_err(|e| format!("Error creating fake timestamp: {:?}", e))?;
    let stamps = identity.stamps().iter()
        .filter(|x| {
            if revoked {
                true
            } else {
                x.revocation().is_none()
            }
        })
        .map(|stamp| {
            let stamp_id: TransactionID = stamp.id().deref().clone();
            let ts = transactions.iter()
                .find(|t| t.id() == &stamp_id)
                .map(|t| t.entry().created().clone())
                .unwrap_or_else(|| ts_fake.clone());
            (stamp.clone(), ts)
        })
        .collect::<Vec<_>>();
    print_stamps_table(&stamps, verbose, revoked)?;
    Ok(())
}

/*
pub fn accept(our_identity_id: &str, location: &str) -> Result<(), String> {
    let our_transactions = id::try_load_single_identity(our_identity_id)?;
    let our_identity = util::build_identity(&our_transactions)?;
    let stamp_contents = util::load_file(location)?;
    let stamp = Stamp::deserialize(stamp_contents.as_slice())
        .map_err(|e| format!("Problem deserializing stamp: {:?}", e))?;
    let stamp_id_str = id_str!(stamp.id())?;
    let our_id = id_str!(our_identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&our_id)), our_identity.created())?;
    our_identity.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let our_transactions_mod = our_transactions.accept_stamp(&master_key, Timestamp::now(), stamp)
        .map_err(|e| format!("Error accepting stamp: {:?}", e))?;
    db::save_identity(our_transactions_mod)?;
    println!("Stamp {} accepted!", StampID::short(&stamp_id_str));
    Ok(())
}
*/

pub fn revoke(id: &str, stamp_search: &str, reason: &str, stage: bool, sign_with: Option<&str>) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let stamp = identity.stamps().iter()
        .find(|x| {
            let id_str = String::try_from(x.id()).unwrap_or_else(|_| "<bad id>".into());
            id_str.starts_with(stamp_search)
        })
        .ok_or_else(|| format!("Couldn't find stamp {}", stamp_search))?;
    if stamp.revocation().is_some() {
        Err(format!("The stamp {} is already revoked", stamp.id()))?;
    }
    let master_key = util::passphrase_prompt(&format!("Your current master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    transactions.test_master_key(&master_key)
        .map_err(|e| format!("Incorrect passphrase: {:?}", e))?;
    let rev_reason = match reason {
        "superseded" => RevocationReason::Superseded,
        "compromised" => RevocationReason::Compromised,
        "invalid" => RevocationReason::Invalid,
        _ => RevocationReason::Unspecified,
    };
    let trans = transactions.revoke_stamp(Timestamp::now(), stamp.id().clone(), rev_reason)
        .map_err(|e| format!("Problem creating revocation transaction: {:?}", e))?;
    let signed = util::sign_helper(&identity, trans, &master_key, stage, sign_with)?;
    dag::save_or_stage(transactions, signed, stage)?;
    Ok(())
}

pub fn print_stamps_table(stamps: &Vec<(Stamp, Timestamp)>, verbose: bool, show_revoked: bool) -> Result<(), String> {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let id_field = if verbose { "ID" } else { "ID (short)" };
    table.set_titles(row![id_field, "Name", "Type", "Value", "Created", "# stamps"]);

    let mut cols = Vec::with_capacity(7);
    cols.push(id_field);
    cols.push("Stampee");
    cols.push("Claim");
    cols.push("Confidence");
    cols.push("Created");
    cols.push("Expires");
    if show_revoked {
        cols.push("Revoked");
    }
    table.set_titles(prettytable::Row::new(cols.into_iter().map(|x| prettytable::Cell::new(x)).collect::<Vec<_>>()));

    for (stamp, created_ts) in stamps {
        let revoked = stamp.revocation().is_some();
        let (id_full, id_short) = id_str_split!(stamp.id());
        let (claim_id_full, claim_id_short) = id_str_split!(stamp.entry().claim_id());
        let (stampee_full, stampee_short) = id_str_split!(stamp.entry().stampee());
        let expires = stamp.entry().expires().as_ref()
            .map(|x| x.local().format("%b %d, %Y").to_string())
            .unwrap_or_else(|| String::from("-"));
        let created = created_ts.local().format("%b %d, %Y").to_string();
        let confidence = match stamp.entry().confidence() {
            Confidence::None => "none",
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
            Confidence::Extreme => "extreme",
        };
        let mut cols = Vec::with_capacity(7);
        cols.push(prettytable::Cell::new(if verbose { &id_full } else { &id_short }));
        cols.push(prettytable::Cell::new(if verbose { &stampee_full } else { &stampee_short }));
        cols.push(prettytable::Cell::new(if verbose { &claim_id_full } else { &claim_id_short }));
        cols.push(prettytable::Cell::new(confidence));
        cols.push(prettytable::Cell::new(&created));
        cols.push(prettytable::Cell::new(&expires));
        if show_revoked {
            cols.push(prettytable::Cell::new(if revoked { "x" } else { "" }));
        }
        table.add_row(prettytable::Row::new(cols));

    }
    table.printstd();
    Ok(())
}
