use crate::{commands::id, db, util};
use anyhow::{anyhow, Result};
#[cfg(feature = "yaml-export")]
use stamp_core::{
    dag::Transactions,
    util::{text_export, text_import},
};

pub fn resave(id: &str) -> Result<()> {
    let identity = id::try_load_single_identity(id)?;
    db::save_identity(identity)?;
    println!("Identity re-saved");
    Ok(())
}

#[cfg(not(feature = "yaml-export"))]
pub fn export(id: &str) -> Result<()> {
    unimplemented!("Please enable yaml-export feature.");
}

#[cfg(not(feature = "yaml-export"))]
pub fn import(id: &str) -> Result<()> {
    unimplemented!("Please enable yaml-export feature.");
}

#[cfg(feature = "yaml-export")]
pub fn export(id: &str) -> Result<()> {
    let identity = id::try_load_single_identity(id)?;
    let export = text_export(&identity)?;
    println!("{}", export);
    Ok(())
}

#[cfg(feature = "yaml-export")]
pub fn import(export_file: &str) -> Result<()> {
    let yaml = util::read_file(export_file)?;
    let yaml_string = String::from_utf8(yaml).map_err(|e| anyhow!("Error reading YAML file: {}", e))?;
    let identity: Transactions = text_import(&yaml_string)?;
    let identity_id = identity.identity_id()
        // panics are fine and kewl if you are building debug commands...
        .expect("should have identity id");
    db::save_identity(identity)?;
    println!("Identity {} imported.", identity_id);
    Ok(())
}
