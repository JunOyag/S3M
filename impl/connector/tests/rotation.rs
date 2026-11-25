//! Rotation d'identité après compromission de la phrase
//! (`securite.incidents-compromissions#rotation-user`) : compte transféré,
//! anciens fichiers lisibles, rechiffrement, appareil neuf.

use std::path::Path;
use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};
use serde_json::json;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x15; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

fn write_config(dir: &Path, addr: &str, salt: &str) -> std::path::PathBuf {
    let path = dir.join("connector.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "seed_file": "user.seed", "identity_index": 0, "data_dir": "data",
            "node": { "addr": addr, "node_id": hex::encode(pk(&NODE)), "salt": salt },
            "api_port": 0, "q_max_bytes": DEFAULT_Q_MAX_BYTES, "watch_interval_s": 3600,
            "mount_point": "Z:", "access": "lecteur", "dht_bootstrap": [],
            "auto_attach": true, "emergency_write": false, "n_secours": 4,
            "free_after_days": 0, "keep_offline": []
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

async fn open(path: &Path) -> Arc<Shared> {
    let mut c = Config::load(path).unwrap();
    c.source = Some(path.to_path_buf());
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    start(c, clock).await.unwrap().0
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

fn read(sh: &Arc<Shared>, p: &str) -> String {
    let r = s3m_connector::explorer::action(sh, "explorer_read", &json!({ "chemin": p, "offset": 0 }))
        .unwrap()
        .unwrap();
    String::from_utf8(hex::decode(r["données"].as_str().unwrap()).unwrap()).unwrap()
}

fn put(sh: &Arc<Shared>, p: &str, text: &str) {
    let mut d = sh.drive.as_ref().unwrap().lock().unwrap();
    d.create(p, false).unwrap();
    d.write(p, 0, text.as_bytes()).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_compromised_phrase_is_replaced_without_losing_files() {
    let dir = std::env::temp_dir().join(format!("p2p-rotation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    let (_, old_user) = user_keys(MNEMONIC, 0).unwrap();
    let salt = [7u8; 16];
    let mut ns = NodeService::new(NODE);
    ns.history_retention_s = 0;
    ns.users.insert(
        old_user,
        UserAccount {
            salt: salt.to_vec(),
            quota_bytes: 1 << 30,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let service = Arc::new(Mutex::new(ns));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    let node = BlockServer::start(NODE, "/ip4/127.0.0.1/tcp/0".parse().unwrap(), service.clone(), clock)
        .await
        .unwrap();
    let addr = node.listen_addr().await.unwrap().to_string();
    let path = write_config(&dir, &addr, &hex::encode(salt));

    // Ancienne identité : deux fichiers.
    let sh = open(&path).await;
    let s = sh.clone();
    let words = blocking(move || {
        put(&s, "/a.txt", "contenu A");
        put(&s, "/b.txt", "contenu B");
        sync_drive(&s).unwrap().unwrap();
        let r = rotate_identity(&s, &json!({ "je confirme": true })).unwrap();
        r["24 mots"].as_str().unwrap().to_string()
    })
    .await;
    stop(sh).await;
    assert_eq!(words.split_whitespace().count(), 24);
    let (_, new_user) = user_keys(&words, 0).unwrap();
    {
        let s = service.lock().unwrap();
        assert!(s.users.contains_key(&new_user) && !s.users.contains_key(&old_user));
        assert!(s.revoked_users.contains(&old_user));
    }

    // Redémarrage sous la nouvelle identité : anciens fichiers lisibles,
    // rechiffrement proposé et appliqué.
    let sh = open(&path).await;
    let s = sh.clone();
    blocking(move || {
        sync_drive(&s).unwrap().unwrap();
        assert_eq!(read(&s, "/a.txt"), "contenu A");
        let listed = s3m_connector::explorer::action(&s, "explorer_list", &json!({ "chemin": "/" }))
            .unwrap()
            .unwrap();
        assert_eq!(listed["rechiffrer"], true);
        let names: Vec<&str> = listed["entrées"].as_array().unwrap().iter().map(|e| e["nom"].as_str().unwrap()).collect();
        assert!(names.contains(&"a.txt") && !names.contains(&".s3m"), "trousseau masqué : {names:?}");
        s3m_connector::explorer::action(&s, "explorer_reencrypt", &json!({ "chemin": "/a.txt" }))
            .unwrap()
            .unwrap();
        sync_drive(&s).unwrap().unwrap();
        assert_eq!(read(&s, "/a.txt"), "contenu A");
    })
    .await;
    stop(sh).await;

    // Appareil neuf avec la seule nouvelle phrase : clés retrouvées, le
    // fichier jamais rechiffré (ancienne clé) reste lisible.
    let fresh = dir.join("neuf");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(dir.join("user.seed"), fresh.join("user.seed")).unwrap();
    let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let p2 = write_config(&fresh, &addr, cfg["node"]["salt"].as_str().unwrap());
    let sh = open(&p2).await;
    let s = sh.clone();
    blocking(move || {
        assert_eq!(read(&s, "/b.txt"), "contenu B");
        assert_eq!(read(&s, "/a.txt"), "contenu A");
    })
    .await;
    stop(sh).await;
    let _ = std::fs::remove_dir_all(&dir);
}
