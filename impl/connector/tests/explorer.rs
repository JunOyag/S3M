//! Page « Explorateur » du dashboard Connecteur : actions sur l'espace.

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};
use serde_json::{json, Value};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x11; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn explorer_creates_uploads_reads_moves_and_deletes() {
    let dir = std::env::temp_dir().join(format!("p2p-explorer-{}", std::process::id()));
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
        // Lecteur (pas monté dans les tests) : l'espace est ouvert.
        mount_point: Some("Z:".into()),
        access: Some("lecteur".into()),
        folder: None,
        dht_bootstrap: vec![],
        auto_attach: true,
        emergency_write: false,
        n_secours: 4,
        free_after_days: 0,
        keep_offline: vec![],
        source: None,
    };
    let (sh, _) = start(config, clock).await.unwrap();
    let act = |name: &str, v: Value| -> Result<Value, String> {
        s3m_connector::explorer::action(&sh, name, &v).expect("action de l'explorateur")
    };
    let names = |p: &str| -> Vec<String> {
        act("explorer_list", json!({ "chemin": p })).unwrap()["entrées"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["nom"].as_str().unwrap().to_string())
            .collect()
    };

    act("explorer_mkdir", json!({ "chemin": "/Photos" })).unwrap();
    act("explorer_mkdir", json!({ "chemin": "/Photos/2026" })).unwrap();
    // Envoi en deux morceaux, puis remplacement par un contenu plus court.
    let a = vec![1u8; s3m_connector::explorer::CHUNK];
    let b = vec![2u8; 1000];
    act(
        "explorer_write",
        json!({ "chemin": "/Photos/a.bin", "offset": 0, "données": hex::encode(&a), "fin": false }),
    )
    .unwrap();
    act("explorer_write", json!({ "chemin": "/Photos/a.bin", "offset": a.len(), "données": hex::encode(&b), "fin": true })).unwrap();
    let r1 = act(
        "explorer_read",
        json!({ "chemin": "/Photos/a.bin", "offset": 0 }),
    )
    .unwrap();
    assert_eq!(r1["fin"], false);
    let r2 = act(
        "explorer_read",
        json!({ "chemin": "/Photos/a.bin", "offset": a.len() }),
    )
    .unwrap();
    assert_eq!(r2["fin"], true);
    let mut got = hex::decode(r1["données"].as_str().unwrap()).unwrap();
    got.extend(hex::decode(r2["données"].as_str().unwrap()).unwrap());
    assert_eq!(got, [a.clone(), b.clone()].concat());
    act(
        "explorer_write",
        json!({ "chemin": "/Photos/a.bin", "offset": 0, "données": "0303", "fin": true }),
    )
    .unwrap();
    let r = act(
        "explorer_read",
        json!({ "chemin": "/Photos/a.bin", "offset": 0 }),
    )
    .unwrap();
    assert_eq!(r["données"], "0303", "remplacé, pas complété");

    // Liste : dossiers d'abord.
    assert_eq!(names("/Photos"), vec!["2026", "a.bin"]);
    // Déplacement, refus de déplacer un dossier dans lui-même.
    act(
        "explorer_move",
        json!({ "de": "/Photos/a.bin", "vers": "/Photos/2026/a.bin" }),
    )
    .unwrap();
    assert_eq!(names("/Photos/2026"), vec!["a.bin"]);
    assert!(act(
        "explorer_move",
        json!({ "de": "/Photos", "vers": "/Photos/2026/x" })
    )
    .is_err());
    // « Partagés avec moi » : lecture seule.
    assert!(act(
        "explorer_mkdir",
        json!({ "chemin": "/Partagés avec moi/x" })
    )
    .is_err());
    // Suppression d'un dossier non vide, contenu compris.
    // Synchronisation : blocs envoyés et comptés chez le Nœud.
    let sync = |sh: &Arc<Shared>| {
        let sh = sh.clone();
        async move {
            tokio::task::spawn_blocking(move || sync_drive(&sh))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        }
    };
    sync(&sh).await;
    let used = |s: &Arc<Mutex<NodeService>>| s.lock().unwrap().users[&pub_user].used_bytes;
    let before = used(&service);
    assert!(before > 0);
    act("explorer_delete", json!({ "chemin": "/Photos" })).unwrap();
    assert!(!names("/").contains(&"Photos".to_string()));
    // Suppression synchronisée : anciens blocs libérés, quota rendu.
    sync(&sh).await;
    let after = used(&service);
    assert!(after < before, "quota rendu : {after} < {before}");
    s3m_connector::daemon::stop(sh.clone()).await;
}
