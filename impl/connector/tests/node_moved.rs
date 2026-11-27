//! Le Nœud change d'adresse sur le réseau local : le Connecteur le retrouve
//! par mDNS grâce à son identité et retient la nouvelle adresse
//! (`network.bootstrap` § Découverte sur le réseau local) ; « Changer de
//! Nœud » met l'ancienne configuration de côté (`deploiement.packaging`).

use std::sync::{Arc, Mutex};

use libp2p::Multiaddr;
use s3m_connector::daemon::*;
use s3m_connector::setup::{config_path, set_aside_config};
use s3m_node::exchange::{NodeService, UserAccount};
use s3m_node::net::{start as node_start, NetConfig, RelayLimits};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x6B; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn temp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("s3m-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn connector_finds_its_node_again_after_an_address_change() {
    let dir = temp("moved");
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    let (_, pub_user) = user_keys(MNEMONIC, 0).unwrap();
    let mut ns = NodeService::new(NODE);
    ns.users.insert(
        pub_user,
        UserAccount {
            salt: vec![7; 16],
            quota_bytes: 1 << 20,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let node = node_start(NetConfig {
        node_seed: NODE,
        listen: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        vdf: Arc::new(|_, _| Ok(true)),
        clock: Arc::new(|| 1),
        service: Arc::new(Mutex::new(ns)),
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
    let peer = libp2p::PeerId::from(libp2p::identity::PublicKey::from(
        libp2p::identity::ed25519::PublicKey::try_from_bytes(&pk(&NODE)).unwrap(),
    ));
    let _node = node;
    // Adresse configurée périmée (ancienne IP du Nœud).
    let stale: Multiaddr = format!("/ip4/127.0.0.1/tcp/9/p2p/{peer}").parse().unwrap();
    let config = Config {
        seed_file: dir.join("user.seed"),
        identity_index: 0,
        data_dir: dir.join("data"),
        node: NodeLink {
            addr: stale.to_string(),
            node_id: hex::encode(pk(&NODE)),
            salt: hex::encode([7u8; 16]),
        },
        api_port: 0,
        q_max_bytes: DEFAULT_Q_MAX_BYTES,
        watch_interval_s: 3600,
        mount_point: None,
        access: None,
        folder: None,
        dht_bootstrap: vec![],
        auto_attach: false,
        emergency_write: false,
        n_secours: 4,
        free_after_days: 0,
        always_free: false,
        keep_offline: vec![],
        source: None,
    };
    let (shared, _) = start(config, Arc::new(|| 1_000_000)).await.unwrap();
    // L'annonce mDNS d'un Nœud tout juste démarré peut manquer une recherche :
    // comme en production (nouvelle recherche toutes les 2 min), on réessaie.
    for _ in 0..4 {
        watch_once(&shared).await;
        if shared.health.lock().unwrap().reachable == Some(true) {
            break;
        }
        *shared.last_lan_search.lock().unwrap() = None;
    }
    assert_eq!(
        shared.health.lock().unwrap().reachable,
        Some(true),
        "Nœud retrouvé"
    );
    let now = shared.session.node_addr();
    assert_ne!(now, stale);
    // Adresse retenue pour le prochain démarrage, seulement pour ce Nœud.
    assert_eq!(learned_node_addr(&dir.join("data"), &stale), Some(now));
    let other: Multiaddr = format!("/ip4/127.0.0.1/tcp/9/p2p/{}", libp2p::PeerId::random())
        .parse()
        .unwrap();
    assert_eq!(learned_node_addr(&dir.join("data"), &other), None);
}

#[test]
fn changing_node_sets_the_old_configuration_aside_and_keeps_the_identity() {
    let dir = temp("change");
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    std::fs::write(config_path(&dir), "{}").unwrap();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    set_aside_config(&dir, 42).unwrap();
    assert!(!config_path(&dir).exists() && !dir.join("data").exists());
    assert!(dir.join("connector.42.json").exists() && dir.join("data.42").exists());
    assert!(dir.join("user.seed").exists(), "identité conservée");
}
