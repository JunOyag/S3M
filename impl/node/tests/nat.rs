//! Traversée de NAT (`network.traversee-nat`) : pile réseau unique (DHT et
//! échange de blocs sur un même swarm), relais circuit v2 et joignabilité
//! d'un Nœud par sa seule adresse via relais. UPnP désactivé : les tests ne
//! touchent jamais la box de la machine.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use s3m_node::exchange::NodeService;
use s3m_node::net::{start, NatState, NetConfig, NodeNet, RelayLimits};
use s3m_protocol::exchange::{Body, Request, Response};

const NOW: u64 = 1_000_000;

async fn node(
    seed: u8,
    bootstrap: Vec<Multiaddr>,
    relays: Vec<Multiaddr>,
    force_relay: bool,
) -> NodeNet {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    start(NetConfig {
        node_seed: [seed; 32],
        // N (0x73) n'écoute nulle part : comme derrière un NAT, il n'est
        // joignable que par son relais.
        listen: if seed == 0x73 {
            vec![]
        } else {
            vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
        },
        bootstrap,
        vdf: Arc::new(|_, _| Ok(true)),
        clock,
        service: Arc::new(Mutex::new(NodeService::new([seed; 32]))),
        upnp: false,
        relay_server: true,
        relay_limits: RelayLimits::default(),
        relays,
        force_relay,
        external: vec![],
        mdns: false,
        records_file: None,
        assume_listen_public: seed == 0x71,
    })
    .await
    .unwrap()
}

fn probe() -> Request {
    Request {
        credential: None,
        body: Body::Probe { nonce: vec![5; 16] },
    }
}

async fn wait(nat: &Arc<Mutex<NatState>>, f: impl Fn(&NatState) -> bool) -> bool {
    for _ in 0..100 {
        if f(&nat.lock().unwrap()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn one_swarm_carries_dht_blocks_and_relayed_reachability() {
    // Pile unique : l'adresse d'échange est aussi celle de la DHT.
    let r = node(0x71, vec![], vec![], false).await;
    let r_addr = r.blocks.listen_addr().await.unwrap();
    assert_eq!(
        r_addr,
        r.dht.listen_addr().await.unwrap(),
        "un seul point d'accès"
    );
    assert!(
        wait(&r.nat, |n| n.listen.iter().any(|a| a.contains("/quic-v1"))).await,
        "QUIC écoute aussi"
    );
    let a = node(0x72, vec![r_addr.clone()], vec![], false).await;
    a.dht.put(b"cle".to_vec(), vec![]).await.ok(); // enveloppe invalide : refusée, sans panique
    let resp = a.blocks.request(r_addr.clone(), probe()).await.unwrap();
    assert!(matches!(resp, Response::ProbeReply { .. }));

    // N réserve une place chez R et annonce une adresse via relais.
    let n = node(0x73, vec![r_addr.clone()], vec![r_addr.clone()], true).await;
    assert!(
        wait(&n.nat, |s| !s.relayed.is_empty()).await,
        "réservation de relais : {:?}",
        n.nat.lock().unwrap()
    );
    let relayed: Multiaddr = n.nat.lock().unwrap().relayed[0].parse().unwrap();
    assert!(relayed.iter().any(|p| matches!(p, Protocol::P2pCircuit)));
    assert!(n
        .nat
        .lock()
        .unwrap()
        .announced()
        .iter()
        .any(|x| x.contains("p2p-circuit")));

    // C joint N uniquement par l'adresse via relais.
    let c = node(0x74, vec![r_addr], vec![], false).await;
    let mut resp = None;
    let mut last = String::new();
    for _ in 0..10 {
        match tokio::time::timeout(
            Duration::from_secs(10),
            c.blocks.request(relayed.clone(), probe()),
        )
        .await
        {
            Ok(Ok(r)) => {
                resp = Some(r);
                break;
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "délai".into(),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let resp = resp.unwrap_or_else(|| panic!("via relais : {last}"));
    assert_eq!(
        resp,
        Response::ProbeReply {
            nonce: vec![5; 16],
            accepting_partners: true,
            node_name: None,
            accepting_users: false,
        }
    );
    assert!(
        wait(&r.nat, |s| s.relay_circuits_served >= 1).await,
        "circuit relayé par R"
    );
}

#[test]
fn announced_addresses_put_direct_tcp_first_then_quic_then_relays() {
    let me = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let relay = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let n = NatState {
        external: vec![
            format!("/ip4/203.0.113.9/udp/4002/quic-v1/p2p/{me}"),
            format!("/ip4/203.0.113.9/tcp/4002/p2p/{me}"),
        ],
        relayed: vec![format!(
            "/ip4/198.51.100.1/tcp/4002/p2p/{relay}/p2p-circuit/p2p/{me}"
        )],
        ..Default::default()
    };
    let a = n.announced();
    assert!(a[0].contains("/tcp/") && a[1].contains("/quic-v1") && a[2].contains("p2p-circuit"));
    assert_eq!(n.direct_tcp(), Some(("203.0.113.9".into(), 4002)));
}
