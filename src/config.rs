pub use stamp_aux::config::Config;

pub fn load() -> Result<Config, String> {
    stamp_aux::config::load()
        .map_err(|e| format!("Problem loading config: {}", e))
}

pub fn save(config: &Config) -> Result<(), String> {
    stamp_aux::config::save(config)
        .map_err(|e| format!("Problem saving config: {}", e))
}

