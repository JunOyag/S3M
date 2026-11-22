//! Identité dupliquée (`securite.incidents-compromissions#identite-dupliquee`) :
//! un Nœud déjà annoncé sur le réseau local est repéré avant le démarrage
//! d'un second Nœud de même identité ; avertissement sur relecture de
//! l'annuaire.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use s3m_node::exchange::NodeService;
use s3m_node::net::{start, NetConfig, RelayLimits};
use s3m_node::publish::NodeEntryState;
use s3m_node::twin::{message, peer_id_of, scan, twins};

#[test]
fn only_announcements_of_our_own_identity_count() {
    let me = peer_id_of([0x41; 32]).unwrap();
    let other = peer_id_of([0x42; 32]).unwrap();
    let a = |s: &str| s.parse().unwrap();
    let found = vec![
        (other, a("/ip4/192.168.0.9/tcp/4001")),
        (me, a("/ip4/192.168.0.7/tcp/4011")),
        (me, a("/ip4/192.168.0.7/tcp/4011")),
    ];
    assert_eq!(
        twins(&found, &me),
        vec!["/ip4/192.168.0.7/tcp/4011".to_string()]
    );
    assert!(twins(&found[..1], &me).is_empty());
    assert!(message(&["x".into()]).contains("déjà utilisée"));
}

#[test]
fn foreign_entry_under_our_key_warns_after_two_readbacks() {
    use s3m_core::vdf::VdfProof;
    use s3m_protocol::entries::{node_entry_envelope, NodeEntryParams};
    let seed = [0x43; 32];
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let proof = VdfProof {
        y: vec![1; 100],
        pi: vec![2; 100],
    };
    let env = |addrs: &[String]| {
        node_entry_envelope(
            &seed,
            &NodeEntryParams {
                ip: "",
                port: 0,
                timestamp: 5,
                proof: &proof,
                pub_node_recovery: &pk,
                snapshot_pointer: None,
                addrs,
                pub_node_announce: None,
                name: None,
            },
            &[0; 12],
        )
        .unwrap()
    };
    let mine = env(&["/ip4/192.168.0.7/tcp/4001".to_string()]);
    let foreign = env(&["/ip4/192.168.0.8/tcp/4001".to_string()]);
    let mut s = NodeEntryState {
        last_envelope: Some(mine.clone()),
        published_addrs: vec!["/ip4/192.168.0.7/tcp/4001".into()],
        ..Default::default()
    };
    s.check_readback(&mine);
    assert!(s.twin_warning.is_none());
    s.check_readback(&foreign);
    assert!(s.twin_warning.is_none(), "une seule relecture : pas encore");
    s.check_readback(&foreign);
    assert!(s.twin_warning.is_some());
    s.check_readback(&mine);
    assert!(s.twin_warning.is_none(), "l'avertissement disparaît");
}

/// Un Nœud réel annoncé par mDNS : sa propre identité est repérée par
/// l'écoute d'avant-démarrage.
#[tokio::test(flavor = "multi_thread")]
async fn running_node_with_the_same_identity_is_detected_on_the_lan() {
    let seed = [0x44; 32];
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let _first = start(NetConfig {
        node_seed: seed,
        listen: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        vdf: Arc::new(|_, _| Ok(true)),
        clock,
        service: Arc::new(Mutex::new(NodeService::new(seed))),
        upnp: false,
        relay_server: false,
        relay_limits: RelayLimits::default(),
        relays: vec![],
        force_relay: false,
        external: vec![],
        mdns: true,
        assume_listen_public: false,
    })
    .await
    .unwrap();
    let me = peer_id_of(seed).unwrap();
    let mut found = Vec::new();
    for _ in 0..3 {
        found = scan(me, Duration::from_secs(3)).await.unwrap();
        if !found.is_empty() {
            break;
        }
    }
    assert!(!found.is_empty(), "identité annoncée non repérée");
    // Une autre identité n'est pas signalée.
    let other = peer_id_of([0x45; 32]).unwrap();
    assert!(scan(other, Duration::from_secs(2))
        .await
        .unwrap()
        .is_empty());
}
