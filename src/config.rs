use crate::util;
use std::{
    fs::File,
    io::{
        prelude::*,
        BufReader,
    },
};

#[derive(Clone, Debug, Default, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct Config {
    pub default_identity: Option<String>,
}

pub fn load() -> Result<Config, String> {
    let data_dir = util::config_dir()?;
    let mut config_file = data_dir.clone();
    config_file.push("config.toml");
    let config = match File::open(&config_file) {
        Ok(file) => {
            // load and parse
            let mut reader = BufReader::new(file);
            let mut contents = String::new();
            reader.read_to_string(&mut contents)
                .map_err(|e| format!("Problem reading config file: {}: {:?}", config_file.to_string_lossy(), e))?;
            let config: Config = toml::from_str(&contents)
                .map_err(|e| format!("Problem parsing config file: {}: {:?}", config_file.to_string_lossy(), e))?;
            config
        }
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    Config::default()
                }
                _ => Err(format!("Problem loading config: {:?}", e))?,
            }
        }
    };
    Ok(config)
}

pub fn save(config: &Config) -> Result<(), String> {
    let data_dir = util::config_dir()?;
    let mut config_file = data_dir.clone();
    config_file.push("config.toml");
    let serialized = toml::to_string_pretty(config)
        .map_err(|e| format!("Problem serializing configuration: {:?}", e))?;
    let mut handle = File::create(&config_file)
        .map_err(|e| format!("Error opening config file: {}: {:?}", config_file.to_string_lossy(), e))?;
    handle.write_all(serialized.as_bytes())
        .map_err(|e| format!("Error writing to config file: {}: {:?}", config_file.to_string_lossy(), e))?;
    Ok(())
}

