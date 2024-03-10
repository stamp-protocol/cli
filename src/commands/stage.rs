use crate::{
    commands::{dag, id},
    db, util,
};
use anyhow::{anyhow, Result};
use prettytable::Table;
use stamp_aux::db::{delete_staged_transaction, find_staged_transactions, load_staged_transaction, stage_transaction};
use stamp_core::{
    crypto::base::rng,
    dag::{Transaction, TransactionID},
    identity::{Identity, IdentityID},
    util::{base64_decode, base64_encode, Public, SerText, SerdeBinary, Timestamp},
};
use std::convert::TryFrom;
use std::str::FromStr;

pub fn list(id: &str) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let transactions = find_staged_transactions(identity.id()).map_err(|e| anyhow!("Error loading staged transactions: {:?}", e))?;
    print_transactions_table(Some(&identity), &transactions);
    Ok(())
}

pub fn view(txid: &str) -> Result<()> {
    let transaction_id = TransactionID::try_from(txid).map_err(|e| anyhow!("Error loading transaction id: {:?}", e))?;
    let (_, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| anyhow!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("Transaction {} not found", txid))?;
    let serialized = transaction
        .serialize_text()
        .map_err(|e| anyhow!("Error serializing staged transaction: {:?}", e))?;
    println!("{}", serialized);
    Ok(())
}

pub fn export(txid: &str, output: &str, base64: bool) -> Result<()> {
    let transaction_id = TransactionID::try_from(txid).map_err(|e| anyhow!("Error loading transaction id: {:?}", e))?;
    let (identity_id, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| anyhow!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("Transaction {} not found", txid))?;
    let transaction = if transaction.has_private() {
        let now = Timestamp::from_str("2020-12-29T07:04:27.000Z").unwrap();
        let mut rng = rng::chacha20();
        let id_str = id_str!(&identity_id)?;
        let transactions = id::try_load_single_identity(&id_str)?;
        let identity = util::build_identity(&transactions)?;
        let master_key =
            util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
        let (_, new_key) =
            util::with_new_passphrase("Your new passphrase to encrypt this transaction", |master_key, _now| Ok(()), Some(now))?;
        transaction
            .reencrypt(&mut rng, &master_key, &new_key)
            .map_err(|e| anyhow!("Error re-encrypting transaction: {}", e))?
    } else {
        transaction
    };
    let serialized = transaction
        .serialize_binary()
        .map_err(|e| anyhow!("Error serializing transaction: {}", e))?;
    if base64 {
        let base64 = base64_encode(serialized.as_slice());
        util::write_file(output, base64.as_bytes())?;
    } else {
        util::write_file(output, serialized.as_slice())?;
    };
    Ok(())
}

pub fn import(id: &str, input: &str) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let trans_bytes = util::read_file(input)?;
    let transaction = Transaction::deserialize_binary(trans_bytes.as_slice())
        .or_else(|_| Transaction::deserialize_binary(&base64_decode(trans_bytes.as_slice())?))
        .map_err(|e| anyhow!("Error reading transaction: {}", e))?;
    let transaction = if transaction.has_private() {
        let now = Timestamp::from_str("2020-12-29T07:04:27.000Z").unwrap();
        let mut rng = rng::chacha20();
        let transactions = id::try_load_single_identity(&id_str)?;
        let identity = util::build_identity(&transactions)?;
        let new_key = util::passphrase_prompt(&format!("The encryption passphrase for this transaction"), &now)?;
        let master_key =
            util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
        identity
            .test_master_key(&master_key)
            .map_err(|e| anyhow!("Incorrect master passphrase: {:?}", e))?;
        transaction
            .reencrypt(&mut rng, &new_key, &master_key)
            .map_err(|e| anyhow!("Error re-encrypting transaction: {}", e))?
    } else {
        transaction
    };
    let txid = transaction.id().clone();
    stage_transaction(identity.id(), transaction).map_err(|e| anyhow!("Error staging transaction: {:?}", e))?;
    println!("Staged transaction {} import into identity {}", txid, IdentityID::short(&id_str));
    Ok(())
}

pub fn delete(txid: &str) -> Result<()> {
    let transaction_id = TransactionID::try_from(txid).map_err(|e| anyhow!("Error loading transaction id: {:?}", e))?;
    load_staged_transaction(&transaction_id)
        .map_err(|e| anyhow!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("Transaction {} not found", txid))?;
    if !util::yesno_prompt("Do you really want to delete this staged transaction?) [y/N]", "N")? {
        return Ok(());
    }
    delete_staged_transaction(&transaction_id).map_err(|e| anyhow!("Error deleting staged transaction: {:?}", e))?;
    println!("Staged transaction {} deleted!", txid);
    Ok(())
}

pub fn sign(txid: &str, sign_with: &str) -> Result<()> {
    let transaction_id = TransactionID::try_from(txid).map_err(|e| anyhow!("Error loading transaction id: {:?}", e))?;
    let (identity_id, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| anyhow!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("Transaction {} not found", txid))?;
    // dumb to keep converting this back and forth but oh well
    let id_str = id_str!(&identity_id)?;
    let transactions = id::try_load_single_identity(&id_str)?;
    let identity = util::build_identity(&transactions)?;
    let master_key =
        util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    let signed = util::sign_helper(&identity, transaction, &master_key, true, Some(sign_with))?;
    // TODO: do a match here and untangle the various error conditions. for now,
    // we'll just reduce this to a binary.
    let ready = signed.verify(Some(&identity)).is_ok();

    // save it back into staging
    stage_transaction(identity.id(), signed).map_err(|e| anyhow!("Error saving staged transaction: {:?}", e))?;
    if ready {
        let green = dialoguer::console::Style::new().green();
        println!(
            "Transaction signed and saved! {} and the transaction can be applied with:",
            green.apply_to("All required signatures are present")
        );
        println!("  stamp stage apply {}", txid);
    } else {
        let yellow = dialoguer::console::Style::new().yellow();
        println!(
            "Transaction signed and saved! {}",
            yellow.apply_to("This transaction requires more signatures to be valid.")
        );
    }
    Ok(())
}

pub fn apply(txid: &str) -> Result<()> {
    let transaction_id = TransactionID::try_from(txid).map_err(|e| anyhow!("Error loading transaction id: {:?}", e))?;
    let (identity_id, transaction) = load_staged_transaction(&transaction_id)
        .map_err(|e| anyhow!("Error loading staged transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("Transaction {} not found", txid))?;
    let id_str = id_str!(&identity_id)?;
    let transactions = id::try_load_single_identity(&id_str)?;
    let transactions_mod = transactions
        .push_transaction(transaction)
        .map_err(|e| anyhow!("Problem saving staged transaction to identity: {:?}", e))?;
    let transactions_mod = db::save_identity(transactions_mod)?;
    println!("Transaction {} has been applied to the identity {}", transaction_id, IdentityID::short(&id_str));
    let trans = transactions_mod
        .transactions()
        .iter()
        .find(|t| t.id() == &transaction_id)
        .ok_or_else(|| anyhow!("Unable to find saved transaction {}", transaction_id))?;
    let post_save_msg = dag::post_save(&transactions_mod, trans, false)?;
    if let Some(msg) = post_save_msg {
        println!("{}", msg);
    }
    delete_staged_transaction(&transaction_id).map_err(|_| {
        anyhow!(
            "Problem removing staged transaction. The transaction was applied and can be safely removed with:\n  stamp stage delete {}",
            transaction_id
        )
    })?;
    Ok(())
}

pub fn print_transactions_table(identity: Option<&Identity>, transactions: &Vec<Transaction>) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type", "Signatures", "Ready", "Created"]);
    for trans in transactions {
        let ty = dag::transaction_to_string(trans);
        let id = id_str!(trans.id()).unwrap_or_else(|e| format!("<bad id {:?} -- {:?}>", trans.id(), e));
        let ready = if trans.verify(identity).is_ok() { "x" } else { "" };
        let created = trans.entry().created().local().format("%b %e, %Y  %H:%M:%S");
        let num_sig = trans.signatures().len();
        table.add_row(row![id, ty, num_sig, ready, created,]);
    }
    table.printstd();
}
