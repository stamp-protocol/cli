use crate::{commands::id::try_load_single_identity, config, db, util};
use anyhow::{anyhow, Result};
use indicatif::{ProgressBar, ProgressStyle};
use stamp_aux::id::sign_with_optimal_key;
use stamp_core::{
    dag::{Transaction, Transactions},
    identity::{Identity, IdentityID},
    util::{base64_decode, SerText, SerdeBinary, Timestamp},
};
use stamp_net::{
    agent::{self, random_peer_key, Agent, DHTMode, Event, Quorum, RelayMode},
    Multiaddr,
};
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task,
};
use tracing::log::{trace, warn};

async fn event_sink(mut events: mpsc::Receiver<Event>, tx_ident: mpsc::Sender<()>, min_idents: usize) -> stamp_net::error::Result<()> {
    let mut num_idents = 0;
    loop {
        match events.recv().await {
            Some(Event::Quit) => break,
            Some(Event::IdentifyRecv) => {
                num_idents += 1;
                if num_idents >= min_idents {
                    let _ = tx_ident.try_send(());
                }
            }
            Some(ev) => trace!("event_sink: {:?}", ev),
            _ => {}
        }
    }
    Ok(())
}

pub fn get_stampnet_joinlist(join: Vec<Multiaddr>) -> Result<Vec<Multiaddr>> {
    if join.len() > 0 {
        return Ok(join);
    }
    let config = config::load()?;
    let join_list = match config.net {
        Some(net) => net.join_list.clone(),
        None => {
            vec![
                "/dns/join01.stampid.net/tcp/5757".parse()?,
                "/dns/join02.stampid.net/tcp/5757".parse()?,
            ]
        }
    };
    Ok(join_list)
}

#[tokio::main(flavor = "current_thread")]
pub async fn publish(id: &str, publish_transaction_file: Option<&str>, join: Vec<Multiaddr>) -> Result<()> {
    let hash_with = config::hash_algo(Some(&id));
    let transactions = try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let signed_publish_transaction = if let Some(publish_transaction_file) = publish_transaction_file {
        let contents = util::load_file(publish_transaction_file)?;
        Transaction::deserialize_binary(&contents).or_else(|_| Transaction::deserialize_binary(&base64_decode(&contents)?))?
    } else {
        let master_key =
            util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
        let now = Timestamp::now();
        let transaction = transactions
            .publish(&hash_with, now)
            .map_err(|e| anyhow!("Error creating publish transaction: {:?}", e))?;
        sign_with_optimal_key(&identity, &master_key, transaction).map_err(|e| anyhow!("Error signing transaction: {:?}", e))?
    };
    let (_, identity) = signed_publish_transaction.clone().validate_publish_transaction()?;

    let join = get_stampnet_joinlist(join)?;
    let join_len = join.len();
    let bind: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;
    let peer_key = random_peer_key();
    let peer_id = stamp_net::PeerId::from(peer_key.public());
    let (agent, events) = Agent::new(peer_key, agent::memory_store(&peer_id), RelayMode::Client, DHTMode::Client)?;
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(250);
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["*     ", " *    ", "  *   ", "   *  ", "    * ", "     *", "     *"])
            .template("[{spinner:.green}] {msg}"),
    );
    spinner.set_message("Connecting to StampNet...");
    let agent = Arc::new(agent);
    let mut task_set = task::JoinSet::new();
    let (tx_ident, mut rx_ident) = mpsc::channel::<()>(1);
    task_set.spawn(event_sink(events, tx_ident, join_len));
    let agent2 = agent.clone();
    task_set.spawn(async move { agent2.run(bind.clone(), join).await });
    match rx_ident.recv().await {
        Some(_) => {}
        None => warn!("ident sender dropped"),
    }
    agent.dht_bootstrap().await?;
    spinner.set_message("Joined StampNet. Publishing identity...");
    let quorum = std::num::NonZeroUsize::new(std::cmp::max(join_len, 1)).ok_or(anyhow!("bad non-zero usize"))?;
    agent.publish_identity(signed_publish_transaction, Quorum::N(quorum)).await?;
    spinner.set_message("Identity published!");
    agent.quit().await?;
    spinner.finish();
    while let Some(res) = task_set.join_next().await {
        res??;
    }
    let green = dialoguer::console::Style::new().green();
    println!("{} stamp://{}", green.apply_to("Published identity"), identity.id());
    Ok(())
}

pub async fn get_identity(id: &str, join: Vec<Multiaddr>) -> Result<(Transactions, Identity)> {
    let identity_id = IdentityID::try_from(id)?;
    let join = get_stampnet_joinlist(join)?;
    let join_len = join.len();
    let bind: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;
    let peer_key = random_peer_key();
    let peer_id = stamp_net::PeerId::from(peer_key.public());
    let (agent, events) = Agent::new(peer_key, agent::memory_store(&peer_id), RelayMode::Client, DHTMode::Client)?;
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(250);
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["*     ", " *    ", "  *   ", "   *  ", "    * ", "     *", "     *"])
            .template("[{spinner:.green}] {msg}"),
    );
    spinner.set_message("Connecting to StampNet...");
    let agent = Arc::new(agent);
    let mut task_set = task::JoinSet::new();
    let (tx_ident, mut rx_ident) = mpsc::channel::<()>(1);
    task_set.spawn(event_sink(events, tx_ident, join_len));
    let agent2 = agent.clone();
    task_set.spawn(async move { agent2.run(bind.clone(), join).await });
    match rx_ident.recv().await {
        Some(_) => {}
        None => warn!("ident sender dropped"),
    }
    agent.dht_bootstrap().await?;
    spinner.set_message("Joined StampNet. Searching for identity...");
    let lookup_res = agent.lookup_identity(identity_id.clone()).await;
    spinner.set_message("Search completed.");
    agent.quit().await?;
    spinner.finish();
    while let Some(res) = task_set.join_next().await {
        res??;
    }

    let publish_transaction = match lookup_res {
        Ok(Some(trans)) => trans,
        Ok(None) => Err(anyhow!("Identity {} not found", identity_id))?,
        Err(e) => Err(anyhow!("Problem looking up identity {}: {}", identity_id, e))?,
    };
    Ok(publish_transaction.validate_publish_transaction()?)
}

#[tokio::main(flavor = "current_thread")]
pub async fn get(id: &str, join: Vec<Multiaddr>) -> Result<()> {
    let (transactions, identity) = get_identity(id, join).await?;
    let exists = db::load_identity(identity.id())?;
    let identity = util::build_identity(&transactions)?;
    if exists.is_some() {
        if !util::yesno_prompt("The identity you're importing already exists locally. Overwrite? [y/N]", "n")? {
            return Ok(());
        }
    }
    db::save_identity(transactions)?;
    let green = dialoguer::console::Style::new().green();
    println!("{} {}", green.apply_to("Imported identity"), identity.id());
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn node(bind: Multiaddr, join: Vec<Multiaddr>) -> Result<()> {
    let join = get_stampnet_joinlist(join)?;
    let peer_key = random_peer_key();
    let peer_id = stamp_net::PeerId::from(peer_key.public());
    let (agent, events) = Agent::new(peer_key, agent::memory_store(&peer_id), RelayMode::Server, DHTMode::Server)?;
    let agent = Arc::new(agent);
    let mut task_set = task::JoinSet::new();
    let (tx_ident, mut rx_ident) = mpsc::channel::<()>(1);
    task_set.spawn(event_sink(events, tx_ident, 1));
    let agent2 = agent.clone();
    let bind2 = bind.clone();
    task_set.spawn(async move { agent2.run(bind2.clone(), join).await });
    match rx_ident.recv().await {
        Some(_) => {}
        None => warn!("ident sender dropped"),
    }
    agent.dht_bootstrap().await?;
    while let Some(res) = task_set.join_next().await {
        res??;
    }
    Ok(())
}
