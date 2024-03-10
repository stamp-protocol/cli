use crate::SyncToken;
use anyhow::{anyhow, Result};
use stamp_aux::util::UIMessage;
use stamp_core::crypto::base::SecretKey;
//use stamp_net::Multiaddr;
use tokio::{sync::mpsc as channel, task};
use tracing::warn;

/*
pub fn run(bind: Multiaddr, sync_token: Option<SyncToken>, sync_join: Vec<Multiaddr>, agent_port: u32, agent_lock_after: u64, net: bool, net_join: Vec<Multiaddr>) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let mut task_set = task::JoinSet::new();
            if let Some(sync_token) = sync_token {
                task_set.spawn(async move {
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
                        .map_err(|e| anyhow!("Problem running sync listener: {}", e))
                });
            };
            let (tx, mut rx) = channel::channel::<UIMessage>(4);
            task_set.spawn(async move {
                while let Some(message) = rx.recv().await {
                    match message {
                        UIMessage::Notification { title, body, icon } => {
                            let mut notif = notify_rust::Notification::new();
                            notif
                                .summary(&title)
                                .body(&body)
                                .timeout(notify_rust::Timeout::Milliseconds(30000));
                            if let Some(icon) = icon.as_ref() {
                                notif.image_path(icon);
                            }
                            match notif.show() {
                                Ok(_handle) => {}
                                Err(e) => warn!("Problem showing desktop notification: {}", e),
                            }
                        }
                        UIMessage::UnlockIdentity(identity_id) => {
                        }
                    }
                }
                Ok(())
            });
            task_set.spawn(async move {
                stamp_aux::agent::run(agent_port, agent_lock_after, tx).await
                    .map_err(|e| anyhow!("Problem running agent: {}", e))
            });
            while let Some(res) = task_set.join_next().await {
                res??;
            }
            Ok(())
        })
}
*/
