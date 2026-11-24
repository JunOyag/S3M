//! Traversée de NAT côté Connecteur (`network.traversee-nat`) : joindre un
//! Nœud qui n'écoute nulle part, par sa seule adresse via relais.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use s3m_connector::exchange::{BlockClient, ExchangeError, NodeSession};
use s3m_node::exchange::{NodeService, UserAccount};
use s3m_node::net::{start, NetConfig, NodeNet, RelayLimits};
use s3m_protocol::exchange::Refusal;

const USER: [u8; 32] = [0x40; 32];
const SALT: [u8; 16] = [7; 16];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

async fn node(
    seed: u8,
    listen: bool,
    relays: Vec<libp2p::Multiaddr>,
    service: NodeService,
) -> NodeNet {
    start(NetConfig {
        node_seed: [seed; 32],
        listen: if listen {
            vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
        } else {
            vec![]
        },
        bootstrap: relays.clone(),
        vdf: Arc::new(|_, _| Ok(true)),
        clock: Arc::new(|| 1_000_000),
        service: Arc::new(Mutex::new(service)),
        upnp: false,
        relay_server: true,
        relay_limits: RelayLimits::default(),
        force_relay: !relays.is_empty(),
        relays,
        external: vec![],
        mdns: false,
        records_file: None,
        assume_listen_public: listen,
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn connector_reaches_a_node_behind_nat_through_its_relay() {
    let r = node(0x71, true, vec![], NodeService::new([0x71; 32])).await;
    let r_addr = r.blocks.listen_addr().await.unwrap();
    let mut ns = NodeService::new([0x73; 32]);
    ns.users.insert(
        pk(&USER),
        UserAccount {
            salt: SALT.to_vec(),
            quota_bytes: 1 << 20,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let n = node(0x73, false, vec![r_addr], ns).await;
    let mut relayed = None;
    for _ in 0..100 {
        if let Some(a) = n.nat.lock().unwrap().relayed.first() {
            relayed = Some(a.parse().unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let relayed = relayed.expect("adresse via relais");

    let session = NodeSession::new(
        BlockClient::start().unwrap(),
        relayed,
        &USER,
        &pk(&USER),
        &pk(&[0x73; 32]),
        &SALT,
    )
    .unwrap();
    // `NotFound` sur un hash nul : Nœud joint et identifiant accepté.
    let mut last = None;
    for _ in 0..10 {
        match session.get_block(&[0; 32]).await {
            Err(ExchangeError::Refused(Refusal::NotFound)) => {
                last = None;
                break;
            }
            other => last = Some(format!("{other:?}")),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(last.is_none(), "via relais : {last:?}");
}
