//! Nœud recréé sans restauration : la racine du Connecteur n'est pas
//! transmise et l'Utilisateur est invité à créer une nouvelle identité.

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};
use serde_json::json;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x12; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_unknown_to_the_node_is_not_committed() {
    let dir = std::env::temp_dir().join(format!("p2p-missing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data/workspace")).unwrap();
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    // Racine gardée de l'ancien Nœud.
    std::fs::write(
        dir.join("data/workspace/journal.json"),
        format!(
            r#"{{"fs_root_hash":"{}","encryption_salt":"{}","key_version":1,"changes":{{}},"next_file":0,"revision":0,"emergency":null,"to_release":[]}}"#,
            hex::encode([0x51u8; 32]),
            hex::encode([0x6cu8; 16])
        ),
    )
    .unwrap();
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
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    let service = Arc::new(Mutex::new(ns));
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
    watch_once(&sh).await;
    assert!(sh.health.lock().unwrap().files_missing);
    assert_eq!(service.lock().unwrap().users[&pub_user].root, [0; 32]);
    let sh2 = sh.clone();
    let view = tokio::task::spawn_blocking(move || tray_view(&sh2)).await.unwrap();
    assert!(view.files_missing);
    assert_eq!(view.text, FILES_MISSING);
    let err = s3m_connector::explorer::action(&sh, "explorer_list", &json!({ "chemin": "/" }))
        .unwrap()
        .unwrap_err();
    assert_eq!(err, FILES_MISSING);
    let _ = std::fs::remove_dir_all(&dir);
}
