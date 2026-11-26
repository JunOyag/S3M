//! `network.bootstrap`, component `connector` : résolution depuis la seed et
//! chemin rapide par cache, face à des Nœuds réels sur 127.0.0.1.

use std::sync::Arc;
use std::time::Duration;

use flatbuffers::FlatBufferBuilder;
use s3m_connector::bootstrap::{resolve, BootstrapError, LocalCache, Migration, Source};
use s3m_connector::dht_directory::{DhtClient, DhtClientConfig};
use s3m_core::k_self::derive_k_self;
use s3m_core::keys::{derive_sig_priv_user, derive_sig_pub_user, derive_user_dht_key};
use s3m_core::vdf::VdfProof;
use s3m_core::CoreError;
use s3m_node::dht_directory::{DhtConfig, DhtNode};
use s3m_protocol::dht::{build_envelope, seal_blob, sign, EntryKind, SIG_LABEL_MIGRATION_POINTER};
use s3m_protocol::fb::dht as fb;

const NOW: u64 = 1_800_000_000;
const PRIV_USER: [u8; 32] = [0x60; 32];
const PUB_USER: [u8; 32] = [0x80; 32];

type Vdf = Arc<dyn Fn(&[u8; 33], &VdfProof) -> Result<bool, CoreError> + Send + Sync>;

fn vdf() -> Vdf {
    Arc::new(|_: &[u8; 33], _: &VdfProof| Ok::<bool, CoreError>(true))
}

fn pub_of(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn vdf_proof<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    key: &[u8; 32],
) -> flatbuffers::WIPOffset<fb::VdfProof<'a>> {
    let mut id = vec![0u8];
    id.extend_from_slice(key);
    let identity = fbb.create_vector(&id);
    let y = fbb.create_vector(&[1u8; 100]);
    let pi = fbb.create_vector(&[2u8; 100]);
    fb::VdfProof::create(
        fbb,
        &fb::VdfProofArgs {
            identity: Some(identity),
            y: Some(y),
            pi: Some(pi),
        },
    )
}

/// Entrée User : attachements (node_id, timestamp), racine FS chiffrée sous K_self.
fn user_envelope(attachments: &[([u8; 32], u64)], fs_root: &[u8], ts: u64) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let recs: Vec<_> = attachments
        .iter()
        .map(|(node, t)| {
            let n = fbb.create_vector(node);
            fb::AttachmentRecord::create(
                &mut fbb,
                &fb::AttachmentRecordArgs {
                    node_id: Some(n),
                    timestamp: *t,
                    ..Default::default()
                },
            )
        })
        .collect();
    let recs = fbb.create_vector(&recs);
    let root = fbb.create_vector(fs_root);
    let salt = fbb.create_vector(&[0xA0u8; 16]);
    let p = fb::UserEntryPlaintext::create(
        &mut fbb,
        &fb::UserEntryPlaintextArgs {
            fs_root_hash: Some(root),
            encryption_salt: Some(salt),
            key_version: 3,
            attachments: Some(recs),
            master_key_chain: None,
            schema_version: 1,
            pseudo: None,
            contacts: None,
            padding: None,
            devices: None,
        },
    );
    fbb.finish_minimal(p);
    let clear = fbb.finished_data().to_vec();
    let blob = seal_blob(
        &derive_k_self(&PRIV_USER).unwrap(),
        EntryKind::User.blob_aad_label(),
        &[7; 12],
        &clear,
    )
    .unwrap();

    let seed = derive_sig_priv_user(&PRIV_USER, &PUB_USER).unwrap();
    let sig_pub = derive_sig_pub_user(&seed);
    let mut fbb = FlatBufferBuilder::new();
    let key = fbb.create_vector(&sig_pub);
    let proof = vdf_proof(&mut fbb, &sig_pub);
    let ct = fbb.create_vector(&blob);
    let e = fb::UserEntry::create(
        &mut fbb,
        &fb::UserEntryArgs {
            sig_pub_user: Some(key),
            timestamp: ts,
            vdf_proof: Some(proof),
            ciphertext: Some(ct),
        },
    );
    fb::finish_user_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(&seed, EntryKind::User.signature_label(), &payload),
    )
}

/// Entrée Node d'identité `seed`, avec pointeur de migration optionnel vers `to`.
fn node_envelope(seed: &[u8; 32], port: u16, to: Option<[u8; 32]>) -> Vec<u8> {
    let node_id = pub_of(seed);
    let recovery_seed = [seed[0] ^ 0xFF; 32];
    let mut fbb = FlatBufferBuilder::new();
    let mp = to.map(|new_id| {
        let mut inner = FlatBufferBuilder::new();
        let o = inner.create_vector(&node_id);
        let n = inner.create_vector(&new_id);
        let p = fb::MigrationPointerPayload::create(
            &mut inner,
            &fb::MigrationPointerPayloadArgs {
                old_node_id: Some(o),
                new_node_id: Some(n),
                seq: 1,
                timestamp: NOW,
            },
        );
        inner.finish_minimal(p);
        let bytes = inner.finished_data().to_vec();
        let sig = sign(&recovery_seed, SIG_LABEL_MIGRATION_POINTER, &bytes);
        let pv = fbb.create_vector(&bytes);
        let sv = fbb.create_vector(&sig);
        fb::SignedMigrationPointer::create(
            &mut fbb,
            &fb::SignedMigrationPointerArgs {
                payload: Some(pv),
                signature: Some(sv),
            },
        )
    });
    let proof = vdf_proof(&mut fbb, &node_id);
    let ip = fbb.create_string("192.0.2.10");
    let rec = fbb.create_vector(&pub_of(&recovery_seed));
    let e = fb::NodeEntry::create(
        &mut fbb,
        &fb::NodeEntryArgs {
            ip: Some(ip),
            port,
            timestamp: NOW,
            vdf_proof: Some(proof),
            pub_node_recovery: Some(rec),
            migration_pointer: mp,
            snapshot_ciphertext: None,
            addrs: None,
            pub_node_announce: None,
            name: None,
        },
    );
    fb::finish_node_entry_buffer(&mut fbb, e);
    let payload = fbb.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(seed, EntryKind::Node.signature_label(), &payload),
    )
}

async fn setup() -> (DhtNode, DhtClient) {
    let start = |seed, bootstrap| {
        DhtNode::start(DhtConfig {
            node_seed: [seed; 32],
            listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            bootstrap,
            vdf: vdf(),
            clock: Arc::new(|| NOW),
        })
    };
    let a = start(1, vec![]).await.unwrap();
    let addr = a.listen_addr().await.unwrap();
    let _b = start(2, vec![addr.clone()]).await.unwrap();
    let c = DhtClient::start(DhtClientConfig {
        bootstrap: vec![addr],
        vdf: vdf(),
        clock: Arc::new(|| NOW),
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    std::mem::forget(_b);
    (a, c)
}

async fn publish_user(a: &DhtNode, env: Vec<u8>) {
    let key = derive_user_dht_key(&PRIV_USER, &PUB_USER).unwrap();
    a.put(key.to_vec(), env).await.unwrap();
}

const HOST_SEED: [u8; 32] = [0x21; 32];

/// Chemin à froid : seed seule → entrée User → K_self → Nœud courant (le
/// plus récent des attachements) → adresse du Nœud.
#[tokio::test(flavor = "multi_thread")]
async fn cold_path_resolves_current_node_from_seed_alone() {
    let (a, c) = setup().await;
    let host = pub_of(&HOST_SEED);
    let old_host = pub_of(&[0x22; 32]);
    publish_user(
        &a,
        user_envelope(&[(old_host, 10), (host, 20)], b"racine", NOW),
    )
    .await;
    a.put(host.to_vec(), node_envelope(&HOST_SEED, 4001, None))
        .await
        .unwrap();
    let r = resolve(&c, &PRIV_USER, &PUB_USER, None).await.unwrap();
    assert_eq!(r.source, Source::Dht);
    assert_eq!(r.node_id, host);
    assert_eq!(
        (r.node_ip.as_deref(), r.node_port),
        (Some("192.0.2.10"), 4001)
    );
    assert_eq!(r.fs_root_hash, b"racine");
    assert_eq!(r.root_encryption_salt.as_deref(), Some(&[0xA0u8; 16][..]));
    assert_eq!(r.key_version, Some(3));
    assert_eq!(r.migration, Migration::None);
}

/// Chemin rapide : une entrée DHT plus récente que le cache (autre
/// Connecteur) fait adopter sa racine ; sinon le cache fait foi.
#[tokio::test(flavor = "multi_thread")]
async fn fast_path_adopts_newer_dht_entry_otherwise_keeps_cache() {
    let (a, c) = setup().await;
    let host = pub_of(&HOST_SEED);
    publish_user(&a, user_envelope(&[(host, 1)], b"racine-dht", NOW)).await;
    a.put(host.to_vec(), node_envelope(&HOST_SEED, 4001, None))
        .await
        .unwrap();
    let older = LocalCache {
        node_id: host,
        fs_root_hash: b"racine-cache".to_vec(),
        timestamp: NOW - 10,
    };
    let r = resolve(&c, &PRIV_USER, &PUB_USER, Some(&older))
        .await
        .unwrap();
    assert_eq!(
        (r.source, r.fs_root_hash.as_slice()),
        (Source::Dht, &b"racine-dht"[..])
    );
    let newer = LocalCache {
        timestamp: NOW + 10,
        ..older
    };
    let r = resolve(&c, &PRIV_USER, &PUB_USER, Some(&newer))
        .await
        .unwrap();
    assert_eq!(
        (r.source, r.fs_root_hash.as_slice()),
        (Source::Cache, &b"racine-cache"[..])
    );
}

/// Sans entrée User ni cache : erreur explicite.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_user_without_cache_is_an_explicit_error() {
    let (_a, c) = setup().await;
    assert!(matches!(
        resolve(&c, &PRIV_USER, &PUB_USER, None).await,
        Err(BootstrapError::UserNotFound)
    ));
}

/// `migration_pointer` : jamais suivi seul, proposé à l'utilisateur
/// (vers une entrée Node valide) ; chaîne signalée.
#[tokio::test(flavor = "multi_thread")]
async fn migration_pointer_is_only_proposed_never_followed() {
    let (a, c) = setup().await;
    let (s1, s2, s3) = ([0x31; 32], [0x32; 32], [0x33; 32]);
    let (n1, n2, n3) = (pub_of(&s1), pub_of(&s2), pub_of(&s3));
    publish_user(&a, user_envelope(&[(n1, 1)], b"r", NOW)).await;

    // n1 → n2 (valide, sans pointeur) : suivi.
    a.put(n1.to_vec(), node_envelope(&s1, 1, Some(n2)))
        .await
        .unwrap();
    a.put(n2.to_vec(), node_envelope(&s2, 2, None))
        .await
        .unwrap();
    let r = resolve(&c, &PRIV_USER, &PUB_USER, None).await.unwrap();
    assert_eq!((r.node_id, r.node_port), (n1, 1), "pas de suivi sans accord");
    assert_eq!(r.migration, Migration::Proposed { to: n2, chained: false });

    // n2 → n3 → … : le second saut demande confirmation, on reste sur n2.
    let ext = [0x44; 32];
    let s4 = [0x34; 32];
    let n4 = pub_of(&s4);
    publish_user(&a, user_envelope(&[(n4, 3)], b"r", NOW + 2)).await;
    a.put(n4.to_vec(), node_envelope(&s4, 4, Some(n3)))
        .await
        .unwrap();
    a.put(n3.to_vec(), node_envelope(&s3, 3, Some(pub_of(&ext))))
        .await
        .unwrap();
    let r = resolve(&c, &PRIV_USER, &PUB_USER, None).await.unwrap();
    assert_eq!(r.node_id, n4);
    assert_eq!(r.migration, Migration::Proposed { to: n3, chained: true });
}

#[test]
fn local_cache_roundtrips_and_rejects_corruption() {
    let c = LocalCache {
        node_id: [9; 32],
        fs_root_hash: vec![1, 2, 3],
        timestamp: 42,
    };
    assert_eq!(LocalCache::decode(&c.encode()).unwrap(), c);
    let mut bad = c.encode();
    bad.pop();
    assert!(LocalCache::decode(&bad).is_err());
    let dir = std::env::temp_dir().join(format!("p2p-cache-{}", std::process::id()));
    assert_eq!(LocalCache::load(&dir).unwrap(), None);
    c.save(&dir).unwrap();
    assert_eq!(LocalCache::load(&dir).unwrap(), Some(c));
    let _ = std::fs::remove_file(dir);
}
