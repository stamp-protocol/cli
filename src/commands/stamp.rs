use crate::{
    commands::{dag, id},
    db,
    util,
};
use stamp_core::{
    identity::{ClaimID, StampID, Confidence, StampEntry, IdentityID},
    util::Timestamp,
};
use std::convert::TryFrom;

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
    /*
    let stamp = our_identity.stamp(&master_key, confidence, Timestamp::now(), their_identity.id(), claim.claim(), expires)
        .map_err(|e| format!("Problem generating stamp: {:?}", e))?;
    let serialized = stamp.serialize()
        .map_err(|e| format!("Problem serializing stamp: {:?}", e))?;
    Ok(serialized)
    */
}

//pub fn request(our_identity_id: &str, claim_id: &str, our_crypto_subkey_search: &str, stamper_identity_id: &str, stamper_crypto_subkey_search: &str) -> Result<(), String> {
    //let identity = id::try_load_single_identity(our_identity_id)?;
    //let claim = 
//}

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

