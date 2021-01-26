use crate::{
    commands,
    config,
    db,
};
use std::convert::TryFrom;

pub fn set_default(search: &str) -> Result<(), String> {
    let mut conf = config::load()?;
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() > 1 {
        commands::id::print_identities_table(&identities, false);
        Err(format!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(format!("No identities match that search"))?;
    }
    let identity = identities[0].clone();
    let id_str = id_str!(identity.id())?;
    println!("Setting default identity to {}", id_str);
    conf.default_identity = Some(id_str);
    config::save(&conf)
}

