use anyhow::{anyhow, Result};
use crate::{
    SyncToken,
};
use stamp_core::{
    crypto::base::SecretKey,
};
use stamp_net::Multiaddr;

pub fn run(sync_token: Option<SyncToken>, sync_bind: Multiaddr, sync_join: Vec<Multiaddr>, net_bind: Multiaddr, net_join: Vec<Multiaddr>, agent_port: Option<u32>, agent_lock_after: Option<u64>) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            if let Some(sync_token) = sync_token {
                let shared_key = if let Some(base64_key) = sync_token.shared_key.as_ref() {
                    let bytes = stamp_core::util::base64_decode(base64_key)
                        .map_err(|e| anyhow!("Error decoding shared key: {}", e))?;
                    let key = SecretKey::new_xchacha20poly1305_from_slice(&bytes[..])
                        .map_err(|e| anyhow!("Error decoding shared key: {}", e))?;
                    Some(key)
                } else {
                    None
                };
                stamp_aux::sync::listen(&sync_token.identity_id, &sync_token.channel, shared_key, sync_bind, sync_join).await
                    .map_err(|e| anyhow!("Problem starting listener: {}", e))?;
            }
            Ok(())
        })
}
