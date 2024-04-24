use anyhow::{anyhow, Result};
use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter};

pub fn init() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().with_span_events(fmt::format::FmtSpan::CLOSE))
        .with(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("warn"))
                .map_err(|e| anyhow!("Error setting up logging/tracing: {:?}", e))?,
        )
        .init();
    Ok(())
}
