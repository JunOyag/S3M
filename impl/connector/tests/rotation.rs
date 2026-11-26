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
        s.drive.as_ref().unwrap().lock().unwrap().create("/d", true).unwrap();
        put(&s, "/d/x.txt", "contenu X");
        put(&s, "/d/y.txt", "contenu Y");
        sync_drive(&s).unwrap().unwrap();
        // 2FA activé : la rotation est immédiate avec un code.
        security_action(&s, "prepare_2fa", &json!({})).unwrap();
        let secret = s.twofa_setup.lock().unwrap().clone().unwrap().0;
        let code = |step: u64| format!("{:06}", s3m_node::admin::hotp(&secret, step, 6));
        security_action(&s, "confirm_2fa", &json!({ "code": code(1_000_000 / 30) })).unwrap();
        assert_eq!(s.security.lock().unwrap().as_ref().map(|x| x.0), Some(true));
        assert!(rotate_identity(&s, &json!({ "je confirme": true })).is_err(), "sans code : refusé");
        let r = rotate_identity(&s, &json!({ "je confirme": true, "code 2FA": code(1_000_000 / 30 + 1) })).unwrap();
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
        let old = |l: &serde_json::Value, n: &str| {
            l["entrées"].as_array().unwrap().iter().find(|e| e["nom"] == n).unwrap()["ancienne clé"] == true
        };
        assert!(old(&listed, "a.txt") && old(&listed, "b.txt"), "marqués : ancienne clé");
        assert_eq!(listed["éléments à l'ancienne clé"], 3, "a.txt, b.txt et le dossier d");
        assert!(names.contains(&"a.txt") && !names.contains(&".s3m"), "trousseau masqué : {names:?}");
        s3m_connector::explorer::action(&s, "explorer_reencrypt", &json!({ "chemin": "/a.txt" }))
            .unwrap()
            .unwrap();
        sync_drive(&s).unwrap().unwrap();
        assert_eq!(read(&s, "/a.txt"), "contenu A");
        let listed = s3m_connector::explorer::action(&s, "explorer_list", &json!({ "chemin": "/" }))
            .unwrap()
            .unwrap();
        assert!(!old(&listed, "a.txt") && old(&listed, "b.txt"), "a.txt rechiffré, b.txt non");
        let again = s3m_connector::explorer::action(&s, "explorer_reencrypt", &json!({ "chemin": "/a.txt" }))
            .unwrap()
            .unwrap();
        assert!(again["message"].as_str().unwrap().contains("rien à rechiffrer"));
        // Un seul fichier d'un dossier rechiffré : le dossier est reconstruit
        // sous la nouvelle clé, son voisin reste lisible.
        s3m_connector::explorer::action(&s, "explorer_reencrypt", &json!({ "chemin": "/d/x.txt" }))
            .unwrap()
            .unwrap();
        sync_drive(&s).unwrap().unwrap();
        assert_eq!(read(&s, "/d/x.txt"), "contenu X");
        assert_eq!(read(&s, "/d/y.txt"), "contenu Y");
        // Nouvelle phrase réaffichée jusqu'à confirmation.
        let st = status(&s);
        assert_eq!(st["nouvelle phrase de récupération"]["_contenu"]["24 mots"].as_str().unwrap().split_whitespace().count(), 24);
        // Nœud qui ne connaît plus le 2FA (changement de Nœud, Nœud
        // reconstruit) : rappel de réactivation, en tête de l'accueil.
        assert!(st.get("2FA à réactiver").is_none());
        *s.security.lock().unwrap() = Some((false, Vec::new()));
        let st = status(&s);
        assert!(st.get("2FA à réactiver").is_some());
        assert_eq!(st["pages simples"][0]["sections"][0], "2FA à réactiver");
        security_action(&s, "forget_2fa", &json!({})).unwrap();
        assert!(status(&s).get("2FA à réactiver").is_none());
        // Remplaçant annoncé par le Nœud (N1) : proposé, jamais suivi seul.
        *s.migration_offer.lock().unwrap() =
            (s3m_connector::bootstrap::Migration::Proposed { to: [9; 32], chained: true }, 1_000_000);
        let st = status(&s);
        let m = &st["remplacement de mon nœud annoncé"];
        assert_eq!(m["_contenu"]["identifiant du nouveau Nœud"], hex::encode([9u8; 32]));
        assert!(m["_contenu"]["_note"].as_str().unwrap().contains("redoublez"));
        assert_eq!(st["pages simples"][0]["sections"][0], "remplacement de mon nœud annoncé");
        security_action(&s, "ignore_migration", &json!({ "noeud": hex::encode([9u8; 32]) })).unwrap();
        assert!(status(&s).get("remplacement de mon nœud annoncé").is_none());
    })
    .await;
    stop(sh).await;
    assert!(dir.join("data").join(NEW_PHRASE_FILE).exists());
    assert!(!dir.join("data").join("vdf_proof.id").exists()
        || std::fs::read_to_string(dir.join("data").join("vdf_proof.id")).unwrap().trim()
            == hex::encode(s3m_protocol::entries::user_identity(&user_keys(&words, 0).unwrap().0, &new_user).unwrap()),
        "preuve d'identité de la nouvelle identité");

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

/// Sans 2FA : changement programmé (72 h), exécuté par le Nœud à
/// l'échéance puis appliqué par le Connecteur.
#[tokio::test(flavor = "multi_thread")]
async fn without_2fa_the_rotation_is_deferred_then_applied() {
    let dir = std::env::temp_dir().join(format!("p2p-rotation-d-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    let (_, old_user) = user_keys(MNEMONIC, 0).unwrap();
    let salt = [7u8; 16];
    let mut ns = NodeService::new(NODE);
    ns.users.insert(old_user, UserAccount { salt: salt.to_vec(), quota_bytes: 1 << 30, used_bytes: 0, root: [0; 32] });
    let service = Arc::new(Mutex::new(ns));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    let node = BlockServer::start(NODE, "/ip4/127.0.0.1/tcp/0".parse().unwrap(), service.clone(), clock).await.unwrap();
    let addr = node.listen_addr().await.unwrap().to_string();
    let path = write_config(&dir, &addr, &hex::encode(salt));
    let sh = open(&path).await;
    let s = sh.clone();
    let r = blocking(move || rotate_identity(&s, &json!({ "je confirme": true })).unwrap()).await;
    assert!(r["message"].as_str().unwrap().contains("programmé"), "{r}");
    assert!(dir.join("data").join(PENDING_ROTATION_FILE).exists());
    assert!(service.lock().unwrap().users.contains_key(&old_user), "rien avant l'échéance");
    // Échéance : le Nœud exécute, le Connecteur applique.
    assert_eq!(service.lock().unwrap().run_due_ops(1_000_000 + s3m_node::user2fa::DEFER_S), 1);
    rotation_tick(&sh).await;
    assert!(!dir.join("data").join(PENDING_ROTATION_FILE).exists());
    assert!(sh.restart_identity.load(std::sync::atomic::Ordering::SeqCst));
    let words = std::fs::read_to_string(dir.join("user.seed")).unwrap();
    let (_, new_user) = user_keys(&words, 0).unwrap();
    assert!(service.lock().unwrap().users.contains_key(&new_user));
    stop(sh).await;
    let _ = std::fs::remove_dir_all(&dir);
}
