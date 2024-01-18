use anyhow::{anyhow, Result};
pub use stamp_aux::config::Config;
use stamp_core::crypto::base::HashAlgo;

pub fn load() -> Result<Config> {
    stamp_aux::config::load()
        .map_err(|e| anyhow!("Problem loading config: {}", e))
}

pub fn save(config: &Config) -> Result<()> {
    stamp_aux::config::save(config)
        .map_err(|e| anyhow!("Problem saving config: {}", e))
}

pub fn hash_algo(_identity_id: Option<&str>) -> HashAlgo {
    HashAlgo::Blake3
}

