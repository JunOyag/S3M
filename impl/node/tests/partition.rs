//! Partition puis réunion de l'annuaire (cahier de tests DHT-05), sur la
//! pile réseau de production (`crate::net` : Kademlia + identify).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flatbuffers::FlatBufferBuilder;
use libp2p::Multiaddr;
use s3m_node::exchange::NodeService;
use s3m_node::net::{start, NetConfig, NodeNet, RelayLimits};
use s3m_protocol::dht::{build_envelope, sign, EntryKind};
use s3m_protocol::fb::dht as fb;

const NOW: u64 = 1_800_000_000;

async fn node(seed: u8, bootstrap: Vec<Multiaddr>) -> NodeNet {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    start(NetConfig {
        node_seed: [seed; 32],
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap,
        vdf: Arc::new(|_, _| Ok(true)),
        clock,
        service: Arc::new(Mutex::new(NodeService::new([seed; 32]))),
        upnp: false,
        relay_server: false,
        relay_limits: RelayLimits::default(),
        relays: vec![],
        force_relay: false,
        external: vec![],
        mdns: false,
        records_file: None,
        assume_listen_public: true,
    })
    .await
    .unwrap()
}

fn envelope(seed: &[u8; 32]) -> Vec<u8> {
    let pk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&pk);
    let e = fb::DispersalEntry::create(
        &mut fbb,
        &fb::DispersalEntryArgs { sig_pub_dispersal: Some(key), timestamp: NOW, ciphertext: None },
    );
    fb::finish_dispersal_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(&payload, &sign(seed, EntryKind::Dispersal.signature_label(), &payload))
}

async fn read(n: &NodeNet, key: &[u8]) -> Option<Vec<u8>> {
    for _ in 0..10 {
        if let Ok(Ok(Some(e))) = tokio::time::timeout(Duration::from_secs(5), n.dht.get(key.to_vec())).await {
            return Some(e);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn a_partitioned_directory_converges_once_reconnected() {
    let a1 = node(0x41, vec![]).await;
    let a_addr = a1.dht.listen_addr().await.unwrap();
    let a2 = node(0x42, vec![a_addr.clone()]).await;
    let b1 = node(0x43, vec![]).await;
    let b_addr = b1.dht.listen_addr().await.unwrap();
    let b2 = node(0x44, vec![b_addr.clone()]).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let env = envelope(&[0x51; 32]);
    a2.dht.put(b"cle-partition".to_vec(), env.clone()).await.expect("put");
    let isolated = tokio::time::timeout(Duration::from_secs(5), b2.dht.get(b"cle-partition".to_vec())).await;
    assert!(!matches!(isolated, Ok(Ok(Some(_)))), "partition : invisible");
    // Réunion : un Nœud joint les deux groupes.
    let _bridge = node(0x45, vec![a_addr, b_addr]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(read(&b2, b"cle-partition").await, Some(env.clone()), "sans republication");
}
