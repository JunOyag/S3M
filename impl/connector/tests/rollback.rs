//! Retour arrière (`protocols.historique-versions#retour-arriere`) : tout
//! l'espace rétabli à une version ; ancienne version imposée par le Nœud
//! refusée.

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};
use serde_json::{json, Value};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x16; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_whole_space_goes_back_and_a_node_rollback_is_refused() {
    let dir = std::env::temp_dir().join(format!("p2p-rollback-{}", std::process::id()));
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
        keep_offline: vec![],
        source: None,
    };
    let (sh, _) = start(config, clock).await.unwrap();
    let s = sh.clone();
    let svc = service.clone();
    tokio::task::spawn_blocking(move || {
        let act = |name: &str, v: Value| -> Result<Value, String> {
            s3m_connector::explorer::action(&s, name, &v).expect("action")
        };
        let put = |p: &str, text: &str| {
            act("explorer_write", json!({ "chemin": p, "offset": 0, "données": hex::encode(text), "fin": true })).unwrap();
            sync_drive(&s).unwrap().unwrap();
        };
        let names = || -> Vec<String> {
            act("explorer_list", json!({ "chemin": "/" })).unwrap()["entrées"].as_array().unwrap()
                .iter().map(|e| e["nom"].as_str().unwrap().to_string()).collect()
        };
        put("/a.txt", "propre");
        let clean = s.drive.as_ref().unwrap().lock().unwrap().root_hash();
        put("/b.txt", "chiffré par un rançongiciel");
        assert!(names().contains(&"b.txt".to_string()));
        // Tout l'espace revient à la version propre.
        let r = act("explorer_versions", json!({ "chemin": "/" })).unwrap();
        let v = r["versions"].as_array().unwrap().iter()
            .find(|x| x["version"] == hex::encode(clean)).expect("version propre").clone();
        act("explorer_restore_all", json!({ "version": v["version"] })).unwrap();
        assert!(names().contains(&"a.txt".to_string()) && !names().contains(&"b.txt".to_string()));
        assert_eq!(svc.lock().unwrap().users.values().next().unwrap().root, clean);

        // Nœud malveillant : ressert une racine plus ancienne en effaçant la
        // trace de la plus récente.
        put("/c.txt", "nouveau");
        let ours = s.drive.as_ref().unwrap().lock().unwrap().root_hash();
        {
            let mut n = svc.lock().unwrap();
            let u = *n.users.keys().next().unwrap();
            n.users.get_mut(&u).unwrap().root = clean;
            n.root_history.get_mut(&u).unwrap().retain(|x| x.root != ours.to_vec());
        }
        *s.history.lock().unwrap() = None;
    })
    .await
    .unwrap();
    watch_once(&sh).await;
    assert!(sh.health.lock().unwrap().rollback);
    let sh2 = sh.clone();
    let view = tokio::task::spawn_blocking(move || tray_view(&sh2)).await.unwrap();
    assert_eq!(view.text, ROLLBACK_TEXT);
    s3m_connector::daemon::stop(sh).await;
    let _ = std::fs::remove_dir_all(&dir);
}
