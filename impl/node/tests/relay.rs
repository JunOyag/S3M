//! Relais (`network.traversee-nat`) au-delà de l'heureux chemin : relais
//! choisi automatiquement (aucun relais imposé) et circuits coupés par les
//! limites du relais (volume, durée), qui doivent se rétablir d'eux-mêmes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::Multiaddr;
use s3m_node::exchange::NodeService;
use s3m_node::net::{start, NatState, NetConfig, NodeNet, RelayLimits};
use s3m_protocol::exchange::{Body, Request, Response};

const NOW: u64 = 1_000_000;

async fn node(
    seed: u8,
    listen: bool,
    bootstrap: Vec<Multiaddr>,
    limits: RelayLimits,
    force_relay: bool,
) -> NodeNet {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    start(NetConfig {
        node_seed: [seed; 32],
        listen: if listen {
            vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
        } else {
            vec![]
        },
        bootstrap,
        vdf: Arc::new(|_, _| Ok(true)),
        clock,
        service: Arc::new(Mutex::new(NodeService::new([seed; 32]))),
        upnp: false,
        relay_server: true,
        relay_limits: limits,
        relays: vec![],
        force_relay,
        external: vec![],
        mdns: false,
        records_file: None,
        assume_listen_public: listen,
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

async fn wait(nat: &Arc<Mutex<NatState>>, secs: u64, f: impl Fn(&NatState) -> bool) -> bool {
    for _ in 0..secs * 10 {
        if f(&nat.lock().unwrap()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Sonde via `addr`, avec quelques nouvelles tentatives (circuit à rouvrir).
/// Rend le nombre d'échecs avant succès, ou `None`.
async fn reach(c: &NodeNet, addr: &Multiaddr) -> Option<usize> {
    for fails in 0..10 {
        if let Ok(Ok(Response::ProbeReply { .. })) =
            tokio::time::timeout(Duration::from_secs(10), c.blocks.request(addr.clone(), probe()))
                .await
        {
            return Some(fails);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    None
}

async fn relayed_of(n: &NodeNet) -> Multiaddr {
    assert!(
        wait(&n.nat, 30, |s| !s.relayed.is_empty()).await,
        "aucune réservation : {:?}",
        n.nat.lock().unwrap()
    );
    n.nat.lock().unwrap().relayed[0].parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_is_found_without_configuration() {
    let r = node(0x81, true, vec![], RelayLimits::default(), false).await;
    let r_addr = r.blocks.listen_addr().await.unwrap();
    // N n'écoute nulle part et n'a aucun relais imposé : il le découvre.
    let n = node(0x82, false, vec![r_addr.clone()], RelayLimits::default(), true).await;
    let relayed = relayed_of(&n).await;
    let c = node(0x83, true, vec![r_addr], RelayLimits::default(), false).await;
    assert!(reach(&c, &relayed).await.is_some(), "N joint via le relais découvert");
}

#[tokio::test(flavor = "multi_thread")]
async fn circuits_cut_by_relay_limits_are_reopened() {
    // Relais très limité : 4 Kio et 2 s par circuit.
    let limits = RelayLimits {
        max_circuit_bytes: 4 << 10,
        max_circuit_duration_s: 2,
        ..RelayLimits::default()
    };
    let r = node(0x91, true, vec![], limits, false).await;
    let r_addr = r.blocks.listen_addr().await.unwrap();
    let n = node(0x92, false, vec![r_addr.clone()], RelayLimits::default(), true).await;
    let relayed = relayed_of(&n).await;
    let c = node(0x93, true, vec![r_addr], RelayLimits::default(), false).await;

    // Volume : bien plus que 4 Kio en sondes successives. Moins de 30
    // circuits : au-delà, le relais n'en rouvre plus qu'un toutes les 4 s
    // par pair source (limiteur libp2p, voir traversee-nat#limites).
    let (mut ok, mut retries) = (0, 0);
    for _ in 0..40 {
        match reach(&c, &relayed).await {
            Some(f) => {
                ok += 1;
                retries += f;
            }
            None => break,
        }
    }
    assert_eq!(ok, 40,"sondes abouties malgré la limite de volume ({retries} nouvel(s) essai(s))");
    // Durée : circuit expiré, puis nouvelle sonde.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(reach(&c, &relayed).await.is_some(), "circuit rouvert après expiration");
    let served = r.nat.lock().unwrap().relay_circuits_served;
    assert!(served >= 2, "le relais a ouvert plusieurs circuits ({served})");
    eprintln!("circuits ouverts : {served}, nouveaux essais : {retries}");
}
