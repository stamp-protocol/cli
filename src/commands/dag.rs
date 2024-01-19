use anyhow::{anyhow, Result};
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
    crypto::{
        base::KeyID,
        private::MaybePrivate,
    },
    dag::{TransactionBody, Transaction, Transactions},
    identity::{
        IdentityID,
        claim::ClaimSpec,
        keychain::Key,
    },
    util::{SerdeBinary, base64_encode},
};
use std::convert::{TryFrom, From};
use std::ops::Deref;

pub fn list(id: &str) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    print_transactions_table(transactions.transactions());
    Ok(())
}

pub fn reset(id: &str, txid: &str) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let trans = transactions.transactions().iter()
        .find(|x| id_str!(x.id()).map(|id| id.starts_with(txid)).unwrap_or(false))
        .ok_or(anyhow!("Transaction {} not found for identity {}", txid, IdentityID::short(&id_str)))?;
    let transactions_reset = transactions.clone().reset(trans.id())
        .map_err(|e| anyhow!("Problem resetting transactions: {}", e))?;
    let removed = transactions.transactions().len() - transactions_reset.transactions().len();
    println!("Removed {} transactions from identity {}", removed, IdentityID::short(&id_str));
    db::save_identity(transactions_reset)?;
    Ok(())
}

pub fn export(id: &str, txid: &str, output: &str, base64: bool) -> Result<()> {
    let transactions = id::try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let trans = transactions.transactions().iter()
        .find(|x| id_str!(x.id()).map(|id| id.starts_with(txid)).unwrap_or(false))
        .ok_or(anyhow!("Transaction {} not found for identity {}", txid, IdentityID::short(&id_str)))?;
    let serialized = trans.serialize_binary()
        .map_err(|e| anyhow!("Problem serializing transaction: {:?}", e))?;
    if base64 {
        let serialized_str = base64_encode(serialized.as_slice());
        util::write_file(output, serialized_str.as_bytes())?;
    } else {
        util::write_file(output, serialized.as_slice())?;
    }
    Ok(())
}

pub fn post_save(transactions: &Transactions, transaction: &Transaction, stage: bool) -> Result<Option<String>> {
    let identity = util::build_identity(transactions)?;
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
                        let claim_id: stamp_core::identity::claim::ClaimID = transaction.id().clone().into();
                        let claim = identity.claims().iter().find(|c| c.id() == &claim_id)
                            .ok_or_else(|| anyhow!("Unable to find created claim"))?;
                        let instant_values = claim.instant_verify_allowed_values(identity.id())
                            .map_err(|e| anyhow!("Problem grabbing allowed claim values: {}", e))?;
                        format!(
                            "{}\n  {}\n  {}\n",
                            util::text_wrap(&format!("Claim added. You can finalize this claim and make it verifiable instantly to others by adding a DNS TXT record to the domain {} that contains one of the following values:\n", domain)),
                            instant_values[0],
                            instant_values[1]
                        )
                    }
                    ClaimSpec::Url(MaybePrivate::Public(url)) => {
                        let claim_id: stamp_core::identity::claim::ClaimID = transaction.id().clone().into();
                        let claim = identity.claims().iter().find(|c| c.id() == &claim_id)
                            .ok_or_else(|| anyhow!("Unable to find created claim"))?;
                        let instant_values = claim.instant_verify_allowed_values(identity.id())
                            .map_err(|e| anyhow!("Problem grabbing allowed claim values: {}", e))?;
                        format!(
                            "{}\n  {}\n  {}\n  {}\n  {}\n",
                            util::text_wrap(&format!("Claim added. You can finalize this claim and make it verifiable instantly to others by updating the URL {} to contain one of the following values:\n", url)),
                            instant_values[0],
                            instant_values[1],
                            instant_values[2],
                            instant_values[3],
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
        TransactionBody::EditClaimV1 { claim_id, name } => {
            if stage {
                format!("Claim rename staged. {}", view_staged())
            } else {
                if let Some(name) = name {
                    format!("Claim {} renamed to {}.", claim_id.deref(), name)
                } else {
                    format!("Claim {} name removed.", claim_id.deref())
                }
            }
        }
        TransactionBody::DeleteClaimV1 { claim_id } => {
            if stage {
                format!("Claim staged for deletion. {}", view_staged())
            } else {
                format!("Claim {} deleted.", claim_id.deref())
            }
        }
        TransactionBody::MakeStampV1 { stamp } => {
            if stage {
                format!("Stamp staged for creation. {}", view_staged())
            } else {
                format!("Stamp on claim {} created.", stamp.claim_id().deref())
            }
        }
        TransactionBody::RevokeStampV1 { stamp_id, .. } => {
            if stage {
                format!("Stamp revocation staged. {}", view_staged())
            } else {
                format!("Stamp {} has been revoked.", stamp_id)
            }
        }
        TransactionBody::AcceptStampV1 { stamp_transaction } => {
            if stage {
                format!("Stamp acceptance staged. {}", view_staged())
            } else {
                format!("Stamp {} has been accepted.", stamp_transaction.id())
            }
        }
        TransactionBody::DeleteStampV1 { stamp_id } => {
            if stage {
                format!("Stamp deletion staged. {}", view_staged())
            } else {
                format!("Stamp {} has been deleted.", stamp_id.deref())
            }
        }
        TransactionBody::AddSubkeyV1 { key, name, .. } => {
            if stage {
                format!("New key staged for creation. {}", view_staged())
            } else {
                let ty = match key {
                    Key::Sign(..) => "sign",
                    Key::Crypto(..) => "crypto",
                    Key::Secret(..) => "secret",
                };
                if ty == "secret" && name == "stamp/sync" {
                    format!("Syncing key created. Run `stamp sync token` to view the token")
                } else {
                    format!("New {} key added: {}.", ty, key.key_id())
                }
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
        _ => { return Ok(None) }
    };
    Ok(Some(msg))
}

pub fn save_or_stage(transactions: Transactions, transaction: Transaction, stage: bool) -> Result<Transactions> {
    let identity_id = transactions.identity_id()
        .ok_or(anyhow!("Unable to generate identity id"))?;
    let trans_clone = transaction.clone();
    let transactions = if stage {
        stage_transaction(&identity_id, transaction)
            .map_err(|e| anyhow!("Error staging transaction: {:?}", e))?;
        transactions
    } else {
        let transactions_mod = transactions.push_transaction(transaction)
            .map_err(|e| anyhow!("Error saving transaction: {:?}", e))?;
        db::save_identity(transactions_mod)?
    };
    let msg = post_save(&transactions, &trans_clone, stage)?;
    if let Some(msg) = msg {
        println!("{}", msg);
    }
    Ok(transactions)
}

pub fn transaction_to_string(trans: &Transaction) -> &'static str {
    match trans.entry().body() {
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
    }
}

pub fn print_transactions_table(transactions: &Vec<Transaction>) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type", "Signatures", "Created"]);
    for trans in transactions {
        let ty = transaction_to_string(trans);
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

