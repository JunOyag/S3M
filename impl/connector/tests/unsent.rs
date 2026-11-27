//! Copie locale des blocs jusqu'à leur dispersion
//! (`protocols.dispersion-transactionnelle#copie-locale`).

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x14; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_block_lost_before_dispersal_is_sent_again() {
    let dir = std::env::temp_dir().join(format!("p2p-unsent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    let (_, pub_user) = user_keys(MNEMONIC, 0).unwrap();
    let salt = [7u8; 16];
    let mut ns = NodeService::new(NODE);
    ns.users.insert(
        pub_user,
        UserAccount {
            salt: salt.to_vec(),
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let service = Arc::new(Mutex::new(ns));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    let node = BlockServer::start(
        NODE,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        service.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    let addr = node.listen_addr().await.unwrap();
    let config = Config {
        seed_file: dir.join("user.seed"),
        identity_index: 0,
        data_dir: dir.join("data"),
        node: NodeLink {
            addr: addr.to_string(),
            node_id: hex::encode(pk(&NODE)),
            salt: hex::encode(salt),
        },
        api_port: 0,
        q_max_bytes: DEFAULT_Q_MAX_BYTES,
        watch_interval_s: 3600,
        mount_point: Some("Z:".into()),
        access: Some("lecteur".into()),
        folder: None,
        dht_bootstrap: vec![],
        auto_attach: true,
        emergency_write: false,
        n_secours: 4,
        free_after_days: 0,
        always_free: false,
        keep_offline: vec![],
        source: None,
    };
    let (sh, _) = start(config, clock).await.unwrap();
    let sh2 = sh.clone();
    tokio::task::spawn_blocking(move || {
        let mut d = sh2.drive.as_ref().unwrap().lock().unwrap();
        d.create("/a.txt", false).unwrap();
        d.write("/a.txt", 0, b"contenu").unwrap();
        drop(d);
        sync_drive(&sh2).unwrap().unwrap();
    })
    .await
    .unwrap();
    let unsent = sh.unsent.clone().unwrap();
    let kept = unsent.usage().0;
    assert!(kept > 0, "blocs gardés tant qu'ils ne sont pas dispersés");

    // Le Nœud perd ses blocs non dispersés (volume effacé) : renvoyés.
    let held: Vec<[u8; 32]> = {
        let mut s = service.lock().unwrap();
        let q: Vec<[u8; 32]> = s.dispersal_queue.iter().map(|(_, h)| *h).collect();
        for h in &q {
            s.store.remove(s3m_node::chunk_store::Space::UserBlock, &pub_user, h);
        }
        s.dispersal_queue.clear();
        q
    };
    assert!(!held.is_empty());
    unsent_tick(&sh).await;
    assert_eq!(unsent.resent.load(std::sync::atomic::Ordering::Relaxed) as usize, held.len());
    {
        let s = service.lock().unwrap();
        for h in &held {
            assert!(s.store.get(s3m_node::chunk_store::Space::UserBlock, h).is_some());
        }
    }
    // Dispersés (plus en attente) : copies supprimées.
    service.lock().unwrap().dispersal_queue.clear();
    unsent_tick(&sh).await;
    assert_eq!(unsent.usage().0, 0);
    s3m_connector::daemon::stop(sh).await;
    let _ = std::fs::remove_dir_all(&dir);
}
