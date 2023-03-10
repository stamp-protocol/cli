use crate::{
    commands::id,
    db,
    util,
};
use prettytable::Table;
use stamp_aux::{
    db::stage_transaction,
};
use stamp_core::{
    crypto::base::KeyID,
    dag::{TransactionBody, Transaction, Transactions},
    identity::{
        Identity,
        IdentityID,
        Claim,
        ClaimSpec,
        keychain::Key,
    },
    private::MaybePrivate,
};
use std::convert::{TryFrom, From};
use tracing::{error};

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
        .find(|x| id_str!(x.id()).map(|id| id.starts_with(txid)).unwrap_or(false))
        .ok_or(format!("Transaction {} not found for identity {}", txid, IdentityID::short(&id_str)))?;
    let transactions_reset = transactions.clone().reset(trans.id())
        .map_err(|e| format!("Problem resetting transactions: {}", e))?;
    let removed = transactions.transactions().len() - transactions_reset.transactions().len();
    println!("Removed {} transactions from identity {}", removed, IdentityID::short(&id_str));
    db::save_identity(transactions_reset)?;
    Ok(())
}

pub fn post_save(identity: &Identity, transaction: &Transaction, stage: bool) -> Option<String> {
    let view_staged = || format!("View the staged transaction with:\n  stamp stage view {}", transaction.id());
    let msg = match transaction.entry().body() {
        TransactionBody::AddAdminKeyV1 { admin_key } => {
            if stage {
                format!("New key staged. {}", view_staged())
            } else {
                format!("New admin key added: {}.", admin_key.key().key_id())
            }
        }
        TransactionBody::EditAdminKeyV1 { id, .. } => {
            if stage {
                format!("Key updated staged. {}", view_staged())
            } else {
                format!("Key {} updated", KeyID::from(id.clone()))
            }
        }
        TransactionBody::RevokeAdminKeyV1 { id, .. } => {
            if stage {
                format!("Key {} revocation staged. {}", KeyID::from(id.clone()), view_staged())
            } else {
                format!("Key {} revoked.", KeyID::from(id.clone()))
            }
        }
        TransactionBody::MakeClaimV1 { spec, name, .. } => {
            if stage {
                format!("Claim staged. {}", view_staged())
            } else {
                match spec {
                    ClaimSpec::Domain(MaybePrivate::Public(domain)) => {
                        let claim_id: stamp_core::identity::ClaimID = transaction.id().clone().into();
                        let claim = identity.claims().iter().find(|c| c.id() == &claim_id)
                            .or_else(|| { error!("Unable to find created claim"); None })?;
                        let instant_values = claim.instant_verify_allowed_values(identity.id())
                            .map_err(|e| error!("Problem grabbing allowed claim values: {}", e))
                            .ok()?;
                        format!(
                            "{}\n  {}\n  {}\n",
                            util::text_wrap(&format!("Claim added. You can finalize this claim and make it verifiable instantly to others by adding a DNS TXT record to the domain {} that contains one of the following two values:\n", domain)),
                            instant_values[0],
                            instant_values[1]
                        )
                    }
                    ClaimSpec::Url(MaybePrivate::Public(url)) => {
                        let claim_id: stamp_core::identity::ClaimID = transaction.id().clone().into();
                        let claim = identity.claims().iter().find(|c| c.id() == &claim_id)
                            .or_else(|| { error!("Unable to find created claim"); None })?;
                        let instant_values = claim.instant_verify_allowed_values(identity.id())
                            .map_err(|e| error!("Problem grabbing allowed claim values: {}", e))
                            .ok()?;
                        format!(
                            "{}\n  {}\n  {}\n",
                            util::text_wrap(&format!("Claim added. You can finalize this claim and make it verifiable instantly to others by updating the URL {} to contain one of the following two values:\n", url)),
                            instant_values[0],
                            instant_values[1]
                        )
                    }
                    _ => {
                        let name_format = name.as_ref()
                            .map(|x| format!(" with name {}", x))
                            .unwrap_or_else(|| String::from(""));
                        format!("Claim{} added.", name_format)
                    }
                }
            }
        }
        TransactionBody::MakeStampV1 { stamp } => {
            if stage {
                format!("Stamp staged for creation. {}", view_staged())
            } else {
                format!("Stamp on claim {} created.", id_str!(stamp.claim_id()).unwrap_or("<bad id>".into()))
            }
        }
        TransactionBody::AddSubkeyV1 { key, .. } => {
            if stage {
                format!("New key staged for creation. {}", view_staged())
            } else {
                let ty = match key {
                    Key::Sign(..) => "sign",
                    Key::Crypto(..) => "crypto",
                    Key::Secret(..) => "secret",
                };
                format!("New {} key added: {}.", ty, key.key_id())
            }
        }
        TransactionBody::EditSubkeyV1 { id, .. } => {
            if stage {
                format!("Key update staged. {}", view_staged())
            } else {
                format!("Key {} updated.", id)
            }
        }
        TransactionBody::DeleteSubkeyV1 { id, .. } => {
            if stage {
                format!("Key {} deletion staged. {}", id, view_staged())
            } else {
                format!("Key {} deleted.", id)
            }
        }
        _ => None?,
    };
    Some(msg)
}

pub fn save_or_stage(transactions: Transactions, transaction: Transaction, stage: bool) -> Result<Transactions, String> {
    let txid = transaction.id().clone();
    let identity_id = transactions.identity_id()
        .ok_or(format!("Unable to generate identity id"))?;
    // had to, sorry...
    let trans_clone = transaction.clone();
    let transactions = if stage {
        let transaction = stage_transaction(&identity_id, transaction)
            .map_err(|e| format!("Error staging transaction: {:?}", e))?;
        transactions
    } else {
        let transactions_mod = transactions.push_transaction(transaction)
            .map_err(|e| format!("Error saving transaction: {:?}", e))?;
        db::save_identity(transactions_mod)?
    };
    let identity = util::build_identity(&transactions)?;
    let msg = post_save(&identity, &trans_clone, stage);
    if let Some(msg) = msg {
        println!("{}", msg);
    }
    Ok(transactions)
}

pub fn print_transactions_table(transactions: &Vec<Transaction>) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type", "Signatures", "Created"]);
    for trans in transactions {
        let ty = match trans.entry().body() {
            TransactionBody::CreateIdentityV1 { .. } => "CreateIdentityV1",
            TransactionBody::ResetIdentityV1 { .. } => "ResetIdentityV1",
            TransactionBody::AddAdminKeyV1 { .. } => "AddAdminKeyV1",
            TransactionBody::EditAdminKeyV1 { .. } => "EditAdminKeyV1",
            TransactionBody::RevokeAdminKeyV1 { .. } => "RevokeAdminKeyV1",
            TransactionBody::AddPolicyV1 { .. } => "AddPolicyV1",
            TransactionBody::DeletePolicyV1 { .. } => "DeletePolicyV1",
            TransactionBody::MakeClaimV1 { .. } => "MakeClaimV1",
            TransactionBody::EditClaimV1 { .. } => "EditClaimV1",
            TransactionBody::DeleteClaimV1 { .. } => "DeleteClaimV1",
            TransactionBody::MakeStampV1 { .. } => "MakeStampV1",
            TransactionBody::RevokeStampV1 { .. } => "RevokeStampV1",
            TransactionBody::AcceptStampV1 { .. } => "AcceptStampV1",
            TransactionBody::DeleteStampV1 { .. } => "DeleteStampV1",
            TransactionBody::AddSubkeyV1 { .. } => "AddSubkeyV1",
            TransactionBody::EditSubkeyV1 { .. } => "EditSubkeyV1",
            TransactionBody::RevokeSubkeyV1 { .. } => "RevokeSubkeyV1",
            TransactionBody::DeleteSubkeyV1 { .. } => "DeleteSubkeyV1",
            // anything below here should not EVER be part of the DAG, but we
            // list these anyway because of ocd
            TransactionBody::PublishV1 { .. } => "PublishV1",
            TransactionBody::SignV1 { .. } => "SignV1",
            TransactionBody::ExtV1 { .. } => "ExtV1",
        };
        let id = id_str!(trans.id())
            .unwrap_or_else(|e| format!("<bad id {:?} -- {:?}>", trans.id(), e));
        let created = trans.entry().created().local().format("%b %e, %Y  %H:%M:%S");
        let num_sig = trans.signatures().len();
        table.add_row(row![
            id,
            ty,
            num_sig,
            created,
        ]);
    }
    table.printstd();
}

