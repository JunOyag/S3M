//! Publication de l'entrée DHT Node (`network.dht-directory`).

use std::sync::{Arc, Mutex};

use p2p_storage_core::vdf::VdfProof;
use p2p_storage_node::dht_directory::{DhtConfig, DhtNode};
use p2p_storage_node::publish::*;
use p2p_storage_protocol::entries::{encode_proof, node_identity};
use p2p_storage_protocol::fb::dht as fb;

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn node_entry_is_published_cached_proof_reused_and_republished_on_schedule() {
    let seed = [0x10; 32];
    let pub_node = pk(&seed);
    let want = node_identity(&pub_node).unwrap();
    let dht = DhtNode::start(DhtConfig {
        node_seed: seed,
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootstrap: vec![],
        vdf: Arc::new(move |id, _| Ok(*id == want)),
        clock: Arc::new(|| 1_000),
    })
    .await
    .unwrap();

    // Preuve déjà en cache : aucun calcul.
    let dir = std::env::temp_dir().join(format!("p2p-publish-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("vdf_proof.bin");
    let fake = VdfProof {
        y: vec![1; 100],
        pi: vec![2; 100],
    };
    std::fs::write(&cache, encode_proof(&fake)).unwrap();
    let proof = ensure_node_proof(&cache, &pub_node).await.unwrap();
    assert_eq!(proof.y, fake.y);

    let state = Mutex::new(NodeEntryState::default());
    let addr = ("203.0.113.9".to_string(), 4002);
    publish_if_due(
        &dht,
        &seed,
        &pub_node,
        &[7; 32],
        addr.clone(),
        &proof,
        None,
        &state,
        1_000,
    )
    .await;
    let s = state.lock().unwrap().clone();
    assert_eq!(s.published_at, Some(1_000), "{:?}", s.last_error);
    assert!(s.next_republish > 1_000);

    let env = dht.get(pub_node.to_vec()).await.unwrap().unwrap();
    let e = flatbuffers::root::<fb::DhtEnvelope>(&env).unwrap();
    let n = fb::root_as_node_entry(e.payload().unwrap().bytes()).unwrap();
    assert_eq!((n.ip(), n.port()), (Some("203.0.113.9"), 4002));

    // Pas due : rien ; nouvelle adresse : republication.
    publish_if_due(
        &dht, &seed, &pub_node, &[7; 32], addr, &proof, None, &state, 1_001,
    )
    .await;
    assert_eq!(state.lock().unwrap().published_at, Some(1_000));
    publish_if_due(
        &dht,
        &seed,
        &pub_node,
        &[7; 32],
        ("203.0.113.10".into(), 4002),
        &proof,
        None,
        &state,
        1_002,
    )
    .await;
    assert_eq!(state.lock().unwrap().published_at, Some(1_002));
}
