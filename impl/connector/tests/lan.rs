//! Recherche des Nœuds du réseau local (`network.bootstrap` § réseau local).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use s3m_connector::lan::scan;
use s3m_node::exchange::NodeService;
use s3m_node::net::{start, NetConfig, RelayLimits};

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn local_node_is_found_by_mdns_and_confirmed_by_probe() {
    let seed = [0x5A; 32];
    let _node = start(NetConfig {
        node_seed: seed,
        listen: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        vdf: Arc::new(|_, _| Ok(true)),
        clock: Arc::new(|| 1),
        service: Arc::new(Mutex::new(NodeService::new(seed))),
        upnp: false,
        relay_server: false,
        relay_limits: RelayLimits::default(),
        relays: vec![],
        force_relay: false,
        external: vec![],
        assume_listen_public: false,
        mdns: true,
        records_file: None,
    })
    .await
    .unwrap();
    let found = scan(Duration::from_secs(5)).await.unwrap();
    assert!(
        found.iter().any(|n| n.node_id == pk(&seed)),
        "nœud local introuvable : {found:?}"
    );
}

/// Recherches répétées (Nœud injoignable : toutes les 2 minutes) : aucune
/// tâche mDNS ne survit à une recherche.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_scans_leave_no_task_behind() {
    let metrics = tokio::runtime::Handle::current().metrics();
    let before = metrics.num_alive_tasks();
    for _ in 0..3 {
        scan(Duration::from_millis(500)).await.unwrap();
    }
    // Les clients réseau abandonnés s'arrêtent en tâche de fond.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = metrics.num_alive_tasks();
    assert!(after <= before, "tâches restées vivantes : {before} → {after}");
}
