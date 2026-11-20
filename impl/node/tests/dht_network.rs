//! `network.dht-directory`, component `node` : plusieurs Nœuds réels
//! (libp2p TCP sur 127.0.0.1) — publication, lecture à travers le réseau,
//! rejet des entrées invalides avant stockage.

use std::sync::Arc;
use std::time::Duration;

use flatbuffers::FlatBufferBuilder;
use s3m_core::vdf::VdfProof;
use s3m_core::CoreError;
use s3m_node::dht_directory::{DhtConfig, DhtNode, DhtNodeError, SharedVdfVerifier};
use s3m_protocol::dht::{build_envelope, sign, DhtError, EntryKind};
use s3m_protocol::fb::dht as fb;

const NOW: u64 = 1_800_000_000;

fn vdf(accept: bool) -> SharedVdfVerifier {
    Arc::new(move |_: &[u8; 33], _: &VdfProof| Ok::<bool, CoreError>(accept))
}

fn pub_of(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

async fn node(seed: u8, bootstrap: Vec<libp2p::Multiaddr>, accept_vdf: bool) -> DhtNode {
    DhtNode::start(DhtConfig {
        node_seed: [seed; 32],
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootstrap,
        vdf: vdf(accept_vdf),
        clock: Arc::new(|| NOW),
    })
    .await
    .expect("démarrage")
}

fn dispersal_envelope(seed: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&pub_of(seed));
    let e = fb::DispersalEntry::create(
        &mut fbb,
        &fb::DispersalEntryArgs {
            sig_pub_dispersal: Some(key),
            timestamp: ts,
            ciphertext: None,
        },
    );
    fb::finish_dispersal_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(seed, EntryKind::Dispersal.signature_label(), &payload),
    )
}

fn user_envelope(seed: &[u8; 32]) -> Vec<u8> {
    let pk = pub_of(seed);
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&pk);
    let mut id = vec![0u8];
    id.extend_from_slice(&pk);
    let identity = fbb.create_vector(&id);
    let y = fbb.create_vector(&[1u8; 100]);
    let pi = fbb.create_vector(&[2u8; 100]);
    let proof = fb::VdfProof::create(
        &mut fbb,
        &fb::VdfProofArgs {
            identity: Some(identity),
            y: Some(y),
            pi: Some(pi),
        },
    );
    let e = fb::UserEntry::create(
        &mut fbb,
        &fb::UserEntryArgs {
            sig_pub_user: Some(key),
            timestamp: NOW,
            vdf_proof: Some(proof),
            ciphertext: None,
        },
    );
    fb::finish_user_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(seed, EntryKind::User.signature_label(), &payload),
    )
}

async fn mesh(accept: [bool; 3]) -> (DhtNode, DhtNode, DhtNode) {
    let a = node(1, vec![], accept[0]).await;
    let addr = a.listen_addr().await.expect("adresse d'écoute");
    let b = node(2, vec![addr.clone()], accept[1]).await;
    let c = node(3, vec![addr], accept[2]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    (a, b, c)
}

#[tokio::test(flavor = "multi_thread")]
async fn entry_published_on_one_node_is_read_from_another() {
    let (_a, b, c) = mesh([true; 3]).await;
    let seed = [0x31; 32];
    let env = dispersal_envelope(&seed, NOW);
    c.put(b"cle-dispersal".to_vec(), env.clone())
        .await
        .expect("put");
    let got = tokio::time::timeout(Duration::from_secs(10), b.get(b"cle-dispersal".to_vec()))
        .await
        .expect("délai")
        .expect("get");
    assert_eq!(got, Some(env));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_entries_are_refused_before_storage() {
    let (a, _b, _c) = mesh([true; 3]).await;
    let mut tampered = dispersal_envelope(&[0x31; 32], NOW);
    let n = tampered.len();
    tampered[n - 20] ^= 1;
    assert!(matches!(
        a.put(b"k1".to_vec(), tampered).await,
        Err(DhtNodeError::Rejected(_))
    ));
    let expired = dispersal_envelope(&[0x31; 32], NOW - 15_552_001);
    assert!(matches!(
        a.put(b"k2".to_vec(), expired).await,
        Err(DhtNodeError::Rejected(DhtError::Expired))
    ));
}

/// Un Nœud dont la vérification VDF échoue ne rend jamais l'entrée, même si
/// d'autres pairs la détiennent.
#[tokio::test(flavor = "multi_thread")]
async fn node_never_returns_an_entry_it_cannot_verify() {
    let (a, b, _c) = mesh([true, false, true]).await;
    let env = user_envelope(&[0x41; 32]);
    a.put(b"cle-user".to_vec(), env.clone()).await.expect("put");
    let got = tokio::time::timeout(Duration::from_secs(10), b.get(b"cle-user".to_vec()))
        .await
        .expect("délai")
        .expect("get");
    assert_eq!(got, None);
    assert!(matches!(
        b.put(b"cle-user".to_vec(), env).await,
        Err(DhtNodeError::Rejected(DhtError::InvalidVdf))
    ));
}

/// `protocols.suppression-dispersal` : le Nœud publie une suppression
/// signée (entrée vide, plus récente) ; l'ancienne entrée ne peut plus être
/// réinjectée.
#[tokio::test(flavor = "multi_thread")]
async fn node_deletes_dispersal_entry_and_old_entry_cannot_come_back() {
    use s3m_node::dht_directory::delete_dispersal_entry;
    use s3m_protocol::dht::is_dispersal_deletion;
    let (a, b, _c) = mesh([true; 3]).await;
    let seed = [0x31; 32];
    let old = dispersal_envelope(&seed, NOW - 10);
    a.put(b"cle-d".to_vec(), old.clone()).await.unwrap();
    delete_dispersal_entry(&a, b"cle-d".to_vec(), &seed, NOW)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), b.get(b"cle-d".to_vec()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(is_dispersal_deletion(&got));
    assert!(matches!(
        a.put(b"cle-d".to_vec(), old).await,
        Err(DhtNodeError::Rejected(DhtError::StaleTimestamp))
    ));
}
