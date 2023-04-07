use anyhow::{anyhow, Result};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .map_err(|e| anyhow!("Error setting up logging/tracing: {:?}", e))?
        )
        .init();
    Ok(())
}
