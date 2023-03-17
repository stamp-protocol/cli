use crate::{
    commands::{
        id,
        dag,
    },
    db,
    util,
};
use stamp_aux::{
    db::{delete_staged_transaction, find_staged_transactions, load_staged_transaction, stage_transaction},
};
use stamp_core::{
    dag::{TransactionID},
    identity::IdentityID,
    util::SerText,
};
use std::convert::TryFrom;

pub fn list(id: &str) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let transactions = find_staged_transactions(identity.id())
        .map_err(|e| format!("Error loading staged transactions: {:?}", e))?;
    dag::print_transactions_table(&transactions);
    Ok(())
}

pub fn view(txid: &str) -> Result<(), String> {
    let transaction_id = TransactionID::try_from(txid)
        .map_err(|e| format!("Error loading transaction id: {:?}", e))?;
    let (_, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| format!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| format!("Transaction {} not found", txid))?;
    let serialized = transaction.serialize_text()
        .map_err(|e| format!("Error serializing staged transaction: {:?}", e))?;
    println!("{}", serialized);
    Ok(())
}

pub fn delete(txid: &str) -> Result<(), String> {
    let transaction_id = TransactionID::try_from(txid)
        .map_err(|e| format!("Error loading transaction id: {:?}", e))?;
    load_staged_transaction(&transaction_id)
        .map_err(|e| format!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| format!("Transaction {} not found", txid))?;
    if !util::yesno_prompt("Do you really want to delete this staged transaction?) [y/N]", "N")? {
        return Ok(());
    }
    delete_staged_transaction(&transaction_id)
        .map_err(|e| format!("Error deleting staged transaction: {:?}", e))?;
    println!("Staged transaction {} deleted!", txid);
    Ok(())
}

pub fn sign(txid: &str, sign_with: &str) -> Result<(), String> {
    let transaction_id = TransactionID::try_from(txid)
        .map_err(|e| format!("Error loading transaction id: {:?}", e))?;
    let (identity_id, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| format!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| format!("Transaction {} not found", txid))?;
    // dumb to keep converting this back and forth but oh well
    let id_str = id_str!(&identity_id)?;
    let transactions = id::try_load_single_identity(&id_str)?;
    let identity = util::build_identity(&transactions)?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    let signed = util::sign_helper(&identity, transaction, &master_key, true, Some(sign_with))?;
    // TODO: do a match here and untangle the various error conditions. for now,
    // we'll just reduce this to a binary.
    let ready = signed.verify(Some(&identity)).is_ok();

    // save it back into staging
    stage_transaction(identity.id(), signed)
        .map_err(|e| format!("Error saving staged transaction: {:?}", e))?;
    if ready {
        let green = dialoguer::console::Style::new().green();
        println!("Transaction signed and saved! {} and the transaction can be applied with:", green.apply_to("All required signatures are present"));
        println!("  stamp stage apply {}", txid);
    } else {
        let yellow = dialoguer::console::Style::new().yellow();
        println!("Transaction signed and saved! {}", yellow.apply_to("This transaction requires more signatures to be valid."));
    }
    Ok(())
}

pub fn apply(txid: &str) -> Result<(), String> {
    let transaction_id = TransactionID::try_from(txid)
        .map_err(|e| format!("Error loading transaction id: {:?}", e))?;
    let (identity_id, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| format!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| format!("Transaction {} not found", txid))?;
    let id_str = id_str!(&identity_id)?;
    let transactions = id::try_load_single_identity(&id_str)?;
    let transactions_mod = transactions.push_transaction(transaction)
        .map_err(|e| format!("Problem saving staged transaction to identity: {:?}", e))?;
    let transactions_mod = db::save_identity(transactions_mod)?;
    println!("Transaction {} has been applied to the identity {}", transaction_id, IdentityID::short(&id_str));
    let trans = transactions_mod.transactions().iter().find(|t| t.id() == &transaction_id)
        .ok_or_else(|| format!("Unable to find saved transaction {}", transaction_id))?;
    let post_save_msg = dag::post_save(&transactions_mod, trans, false)?;
    if let Some(msg) = post_save_msg {
        println!("{}", msg);
    }
    delete_staged_transaction(&transaction_id)
        .map_err(|_| format!("Problem removing staged transaction. The transaction was applied and can be safely removed with:\n  stamp stage delete {}", transaction_id))?;
    Ok(())
}

