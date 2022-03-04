use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_core::{
    dag::{TransactionBody, TransactionVersioned},
    identity::IdentityID,
};
use std::convert::{TryFrom, From};

pub fn list(id: &str) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    print_transactions_table(transactions.transactions());
    Ok(())
}

pub fn reset(id: &str, txid: &str) -> Result<(), String> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let trans = transactions.transactions().iter()
        .find(|x| String::from(x.id().clone()).starts_with(txid))
        .ok_or(format!("Transaction {} not found for identity {}", txid, IdentityID::short(&id_str)))?;
    let transactions_reset = transactions.clone().reset(trans.id())
        .map_err(|e| format!("Problem resetting transactions: {}", e))?;
    let removed = transactions.transactions().len() - transactions_reset.transactions().len();
    println!("Removed {} transactions from identity {}", removed, IdentityID::short(&id_str));
    db::save_identity(transactions_reset)?;
    Ok(())
}

pub fn print_transactions_table(transactions: &Vec<TransactionVersioned>) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type"]);
    for trans in transactions {
        let ty = match trans.entry().body() {
            TransactionBody::Private => "Private",
            TransactionBody::CreateIdentityV1(..) => "CreateIdentityV1",
            TransactionBody::SetRecoveryPolicyV1(..) => "SetRecoveryPolicyV1",
            TransactionBody::ExecuteRecoveryPolicyV1(..) => "ExecuteRecoveryPolicyV1",
            TransactionBody::MakeClaimV1(..) => "MakeClaimV1",
            TransactionBody::DeleteClaimV1(..) => "DeleteClaimV1",
            TransactionBody::AcceptStampV1(..) => "AcceptStampV1",
            TransactionBody::DeleteStampV1(..) => "DeleteStampV1",
            TransactionBody::SetPolicyKeyV1(..) => "SetPolicyKeyV1",
            TransactionBody::SetPublishKeyV1(..) => "SetPublishKeyV1",
            TransactionBody::SetRootKeyV1(..) => "SetRootKeyV1",
            TransactionBody::AddSubkeyV1(..) => "AddSubkeyV1",
            TransactionBody::EditSubkeyV1(..) => "EditSubkeyV1",
            TransactionBody::RevokeSubkeyV1(..) => "RevokeSubkeyV1",
            TransactionBody::DeleteSubkeyV1(..) => "DeleteSubkeyV1",
            TransactionBody::SetNicknameV1(..) => "SetNicknameV1",
            TransactionBody::AddForwardV1(..) => "AddForwardV1",
            TransactionBody::DeleteForwardV1(..) => "DeleteForwardV1",
        };
        let id = String::from(trans.id().clone());
        table.add_row(row![
            id,
            ty,
        ]);
    }
    table.printstd();
}

