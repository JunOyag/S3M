//! `network.dht-directory`, component `connector` : un Connecteur client face
//! à des Nœuds réels (libp2p TCP sur 127.0.0.1).

use std::sync::Arc;
use std::time::Duration;

use flatbuffers::FlatBufferBuilder;
use s3m_connector::dht_directory::{DhtClient, DhtClientConfig, DhtClientError};
use s3m_core::vdf::VdfProof;
use s3m_core::CoreError;
use s3m_node::dht_directory::{DhtConfig, DhtNode};
use s3m_protocol::dht::{build_envelope, sign, DhtError, EntryKind};
use s3m_protocol::fb::dht as fb;

const NOW: u64 = 1_800_000_000;

type Vdf = Arc<dyn Fn(&[u8; 33], &VdfProof) -> Result<bool, CoreError> + Send + Sync>;

fn vdf(accept: bool) -> Vdf {
    Arc::new(move |_: &[u8; 33], _: &VdfProof| Ok::<bool, CoreError>(accept))
}

fn pub_of(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn dispersal_envelope(seed: &[u8; 32]) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&pub_of(seed));
    let e = fb::DispersalEntry::create(
        &mut fbb,
        &fb::DispersalEntryArgs {
            sig_pub_dispersal: Some(key),
            timestamp: NOW,
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

async fn nodes() -> (DhtNode, DhtNode, libp2p::Multiaddr) {
    let start = |seed, bootstrap| {
        DhtNode::start(DhtConfig {
            node_seed: [seed; 32],
            listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            bootstrap,
            vdf: vdf(true),
            clock: Arc::new(|| NOW),
        })
    };
    let a = start(1, vec![]).await.unwrap();
    let addr = a.listen_addr().await.unwrap();
    let b = start(2, vec![addr.clone()]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    (a, b, addr)
}

async fn client(addr: libp2p::Multiaddr, accept_vdf: bool) -> DhtClient {
    let c = DhtClient::start(DhtClientConfig {
        bootstrap: vec![addr],
        vdf: vdf(accept_vdf),
        clock: Arc::new(|| NOW),
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    c
}

async fn get(c: &DhtClient, key: &[u8]) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(10), c.get(key.to_vec()))
        .await
        .expect("délai")
        .expect("get")
}

/// Le Connecteur n'écoute sur aucune adresse et sa session a un `PeerId`
/// éphémère, différent à chaque démarrage.
#[tokio::test(flavor = "multi_thread")]
async fn connector_is_client_only_with_ephemeral_identity() {
    let (_a, _b, addr) = nodes().await;
    let c1 = client(addr.clone(), true).await;
    let c2 = client(addr, true).await;
    assert_eq!(c1.listener_count().await.unwrap(), 0);
    assert_ne!(c1.peer_id(), c2.peer_id());
    assert!(matches!(
        DhtClient::start(DhtClientConfig {
            bootstrap: vec![],
            vdf: vdf(true),
            clock: Arc::new(|| NOW)
        })
        .await,
        Err(DhtClientError::NoBootstrap)
    ));
}

/// Publication par le Connecteur, lecture par un Nœud ; publication par un
/// Nœud, lecture par le Connecteur.
#[tokio::test(flavor = "multi_thread")]
async fn connector_and_nodes_exchange_entries() {
    let (a, b, addr) = nodes().await;
    let c = client(addr, true).await;
    let from_client = dispersal_envelope(&[0x51; 32]);
    c.put(b"cle-client".to_vec(), from_client.clone())
        .await
        .expect("put client");
    let seen = tokio::time::timeout(Duration::from_secs(10), b.get(b"cle-client".to_vec()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen, Some(from_client));
    let from_node = dispersal_envelope(&[0x52; 32]);
    a.put(b"cle-noeud".to_vec(), from_node.clone())
        .await
        .unwrap();
    assert_eq!(get(&c, b"cle-noeud").await, Some(from_node));
}

/// Le Connecteur applique la même règle que le Nœud : une entrée qu'il ne
/// peut pas vérifier n'est ni rendue ni publiée.
#[tokio::test(flavor = "multi_thread")]
async fn connector_refuses_entries_it_cannot_verify() {
    let (a, _b, addr) = nodes().await;
    let c = client(addr, false).await;
    let env = user_envelope(&[0x61; 32]);
    a.put(b"cle-user".to_vec(), env.clone()).await.unwrap();
    assert_eq!(get(&c, b"cle-user").await, None);
    assert!(matches!(
        c.put(b"cle-user".to_vec(), env).await,
        Err(DhtClientError::Rejected(DhtError::InvalidVdf))
    ));
}
