//! Nœud arrêté : après un premier échec réseau, les requêtes échouent
//! aussitôt (pas d'attente de l'abandon de connexion par le système) ; la
//! sonde continue de tester le Nœud.

use std::time::{Duration, Instant};

use s3m_connector::exchange::{BlockClient, ExchangeError, NodeSession};

#[tokio::test(flavor = "multi_thread")]
async fn requests_to_a_stopped_node_fail_fast_after_the_first_failure() {
    let client = BlockClient::start().unwrap();
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let pub_node = key.public().try_into_ed25519().unwrap().to_bytes();
    // Port fermé : le Nœud est arrêté.
    let addr = format!("/ip4/127.0.0.1/tcp/9/p2p/{peer}").parse().unwrap();
    let s = NodeSession::new(client, addr, &[1; 32], &[2; 32], &pub_node, &[4; 16]).unwrap();
    assert!(matches!(s.get_block(&[5; 32]).await, Err(ExchangeError::Network(_))));
    assert!(s.is_down());
    let t = Instant::now();
    for _ in 0..20 {
        assert!(matches!(s.get_block(&[5; 32]).await, Err(ExchangeError::Network(_))));
    }
    assert!(t.elapsed() < Duration::from_millis(200), "court-circuit : {:?}", t.elapsed());
    // La sonde essaie vraiment.
    assert!(matches!(s.probe().await, Err(ExchangeError::Network(_))));
}
