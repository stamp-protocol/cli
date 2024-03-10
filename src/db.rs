use anyhow::{anyhow, Result};
use stamp_aux::db;
use stamp_core::{dag::Transactions, identity::IdentityID};

pub fn ensure_schema() -> Result<()> {
    db::ensure_schema().map_err(|e| anyhow!("Error initializing database: {}", e))
}

pub fn save_identity(transactions: Transactions) -> Result<Transactions> {
    db::save_identity(transactions).map_err(|e| anyhow!("Problem saving identity: {}", e))
}

/// Load an identity by ID.
pub fn load_identity(id: &IdentityID) -> Result<Option<Transactions>> {
    db::load_identity(id).map_err(|e| anyhow!("Problem loading identity: {}", e))
}

/// Load an identity by ID.
pub fn load_identities_by_prefix(id_prefix: &str) -> Result<Vec<Transactions>> {
    db::load_identities_by_prefix(id_prefix).map_err(|e| anyhow!("Problem loading identities: {}", e))
}

/// List identities stored locally.
pub fn list_local_identities(search: Option<&str>) -> Result<Vec<Transactions>> {
    db::list_local_identities(search).map_err(|e| anyhow!("Problem listing identities: {}", e))
}

pub fn find_identity_by_prefix(ty: &str, id_prefix: &str) -> Result<Option<Transactions>> {
    db::find_identity_by_prefix(ty, id_prefix).map_err(|e| anyhow!("Problem finding identity by prefix: {}", e))
}

/// Delete a local identity by id.
pub fn delete_identity(id: &str) -> Result<()> {
    db::delete_identity(id).map_err(|e| anyhow!("Problem deleting identity: {}", e))
}
