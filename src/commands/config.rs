use crate::{commands, config, db, util};
use anyhow::{anyhow, Result};
use std::convert::TryFrom;

pub fn set_default(search: &str) -> Result<()> {
    let mut conf = config::load()?;
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() > 1 {
        let identities_vec = identities.iter().map(|x| util::build_identity(x)).collect::<Result<Vec<_>>>()?;
        commands::id::print_identities_table(&identities_vec, false);
        Err(anyhow!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(anyhow!("No identities match that search"))?;
    }
    let transactions = identities[0].clone();
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    println!("Setting default identity to {}", id_str);
    conf.default_identity = Some(id_str);
    config::save(&conf)
}
