//! Entrée DHT User (`network.dht-directory`) et restauration de la racine
//! sur un nouvel appareil (`deploiement.disaster-recovery`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p2p_storage_connector::access::Root;
use p2p_storage_connector::dht_directory::{DhtClient, DhtClientConfig};
use p2p_storage_connector::drive::{BlockIo, Drive};
use p2p_storage_connector::fs::BlockHash;
use p2p_storage_connector::publish::*;
use p2p_storage_core::vdf::VdfProof;
use p2p_storage_node::dht_directory::{DhtConfig, DhtNode};
use p2p_storage_protocol::entries::{user_identity, Attachment, UserPlain};

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[derive(Default)]
struct MemNode(Mutex<HashMap<BlockHash, Vec<u8>>>, Mutex<BlockHash>);

impl BlockIo for MemNode {
    fn get(&self, h: &BlockHash) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(h).cloned()
    }
    fn put(&self, h: &BlockHash, f: Vec<u8>) -> Result<(), String> {
        self.0.lock().unwrap().insert(*h, f);
        Ok(())
    }
    fn commit(&self, base: &BlockHash, new: &BlockHash) -> Result<Option<BlockHash>, String> {
        let mut r = self.1.lock().unwrap();
        if *r != *base {
            return Ok(Some(*r));
        }
        *r = *new;
        Ok(None)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn user_entry_is_published_on_new_roots_and_restores_a_new_device() {
    let (priv_user, pub_user) = ([0x40; 32], pk(&[0x40; 32]));
    let want = user_identity(&priv_user, &pub_user).unwrap();
    let vdf =
        Arc::new(move |id: &[u8; 33], _: &VdfProof| Ok(*id == want || id[1..] == pk(&[0x10; 32])));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000);
    let node = DhtNode::start(DhtConfig {
        node_seed: [0x10; 32],
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootstrap: vec![],
        vdf: vdf.clone(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let client = DhtClient::start(DhtClientConfig {
        bootstrap: vec![node.listen_addr().await.unwrap()],
        vdf,
        clock,
    })
    .await
    .unwrap();

    // Appareil d'origine : des fichiers, une racine validée.
    let mem = Arc::new(MemNode::default());
    let ws = std::env::temp_dir().join(format!("p2p-pub-a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    let mut a = Drive::open(mem.clone(), [9; 32], ws, Arc::new(|| 1)).unwrap();
    a.create("/note.txt", false).unwrap();
    a.write("/note.txt", 0, b"restaurable").unwrap();
    a.sync().unwrap();
    let r = a.root();
    let plain = |r: &Root| UserPlain {
        fs_root_hash: r.fs_root_hash,
        encryption_salt: r.encryption_salt,
        key_version: r.key_version,
        attachments: vec![Attachment {
            node_id: [0x11; 32],
            salt: vec![7; 16],
            timestamp: 5,
            inactivity_detected_at: 0,
        }],
    };
    let proof = VdfProof {
        y: vec![1; 100],
        pi: vec![2; 100],
    };
    let state = Mutex::new(UserEntryState::default());
    publish_if_changed(
        &client,
        &priv_user,
        &pub_user,
        &proof,
        &plain(&r),
        &state,
        1_000,
    )
    .await;
    assert_eq!(
        state.lock().unwrap().published_root,
        Some(r.fs_root_hash),
        "{:?}",
        state.lock().unwrap().last_error
    );
    let read = read_user_entry(&client, &priv_user, &pub_user)
        .await
        .unwrap();
    assert_eq!(read, plain(&r));

    // Même racine : pas de republication ; nouvelle racine : horodatage croissant.
    publish_if_changed(
        &client,
        &priv_user,
        &pub_user,
        &proof,
        &plain(&r),
        &state,
        1_000,
    )
    .await;
    assert_eq!(state.lock().unwrap().last_timestamp, 1_000);
    a.create("/b", false).unwrap();
    a.sync().unwrap();
    let r2 = a.root();
    publish_if_changed(
        &client,
        &priv_user,
        &pub_user,
        &proof,
        &plain(&r2),
        &state,
        1_000,
    )
    .await;
    assert_eq!(state.lock().unwrap().last_timestamp, 1_001);

    // Nouvel appareil, seule la phrase : la racine vient de la DHT.
    let ws = std::env::temp_dir().join(format!("p2p-pub-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    let mut b = Drive::open(mem, [9; 32], ws, Arc::new(|| 1)).unwrap();
    let read = read_user_entry(&client, &priv_user, &pub_user)
        .await
        .unwrap();
    let adopted = b
        .adopt_root(Root {
            fs_root_hash: read.fs_root_hash,
            encryption_salt: read.encryption_salt,
            key_version: read.key_version,
        })
        .unwrap();
    assert!(adopted);
    assert_eq!(b.read("/note.txt", 0, 100).unwrap(), b"restaurable");
    assert!(b.stat("/b").unwrap().is_some());
}
