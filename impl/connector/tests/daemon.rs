//! `deploiement.packaging` (partie connector) : exécutable relié à un vrai
//! Nœud sur TCP local.

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x10; 32];
const NOW: u64 = 1_000_000;

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

async fn http_get(port: u16, path: &str, token: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[test]
fn user_identity_comes_from_the_recovery_phrase() {
    let (a, pa) = user_keys(MNEMONIC, 0).unwrap();
    let (b, _) = user_keys(MNEMONIC, 1).unwrap();
    assert_ne!(a, b);
    assert_eq!(pa, pk(&a));
    assert!(user_keys("not a phrase", 0).is_err());
    assert_eq!(generate_mnemonic().unwrap().split_whitespace().count(), 24);
}

#[tokio::test(flavor = "multi_thread")]
async fn connector_watches_its_node_keeps_a_rescue_grant_and_serves_its_dashboard() {
    let dir = std::env::temp_dir().join(format!("p2p-conn-{}", std::process::id()));
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
            quota_bytes: 1 << 20,
            used_bytes: 0,
            root: [0; 32],
        },
    );
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
    let node = BlockServer::start(
        NODE,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        Arc::new(Mutex::new(ns)),
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
        mount_point: None,
        access: None,
        folder: None,
        dht_bootstrap: vec![],
        auto_attach: true,
        emergency_write: false,
        n_secours: 4,
        free_after_days: 0,
        source: None,
    };
    let (shared, url) = start(config, clock).await.unwrap();
    // Vue de la barre des tâches : calculée sans se bloquer (un seul verrou
    // du canal à la fois).
    let sh2 = shared.clone();
    let view = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || s3m_connector::daemon::tray_view(&sh2)),
    )
    .await
    .expect("tray_view ne doit pas se bloquer")
    .unwrap();
    assert_eq!(view.unread_messages, 0);
    watch_once(&shared).await;
    {
        let h = shared.health.lock().unwrap();
        assert_eq!(h.reachable, Some(true), "{:?}", h.last_error);
    }
    assert_eq!(*shared.grant_expiry.lock().unwrap(), Some(NOW + 15_552_000));
    assert!(dir.join("data/grant.bin").exists());
    assert!(dir.join("data/device.key").exists());

    let (base, token) = url.split_once("/#token=").unwrap();
    let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();
    let ok = http_get(port, "/api/status", token).await;
    assert!(
        ok.starts_with("HTTP/1.1 200") && ok.contains("Connecteur"),
        "{ok}"
    );
    assert!(http_get(port, "/api/status", "00")
        .await
        .starts_with("HTTP/1.1 403"));

    // Nœud arrêté : indisponibilité détectée, autorisation conservée.
    drop(node);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    watch_once(&shared).await;
    {
        let h = shared.health.lock().unwrap();
        assert_eq!(h.reachable, Some(false));
        assert_eq!(h.inactivity_detected_at, Some(NOW));
    }

    // Arrêt de l'identité sans quitter le processus (changement de Nœud) :
    // plus aucune référence, port du tableau de bord libéré, configuration
    // et données déplaçables.
    std::fs::write(dir.join("connector.json"), "{}").unwrap();
    let weak = Arc::downgrade(&shared);
    s3m_connector::daemon::stop(shared).await;
    assert!(weak.upgrade().is_none(), "identité encore retenue");
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "port du tableau de bord libéré"
    );
    s3m_connector::setup::set_aside_config(&dir, 42).unwrap();
    assert!(dir.join("data.42").exists() && dir.join("connector.42.json").exists());
}

#[test]
fn drive_letter_is_normalised_and_system_disk_refused() {
    use s3m_connector::daemon::parse_drive_letter;
    for s in ["s", "S:", " s:\\ ", "S:/"] {
        assert_eq!(parse_drive_letter(s).unwrap(), "S:");
    }
    assert!(parse_drive_letter("C").is_err());
    assert!(parse_drive_letter("SS").is_err());
    assert!(parse_drive_letter("1").is_err());
    assert!(parse_drive_letter("").is_err());
}

#[test]
fn stale_folders_spares_folders_in_use() {
    use s3m_connector::daemon::{stale_folders, LAST_FOLDER_FILE};
    use std::path::PathBuf;
    let dir = std::env::temp_dir().join(format!("s3m-stale-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(LAST_FOLDER_FILE), r"D:\Cloud\Titi").unwrap();
    let cfg = |name: &str, folder: &str| {
        std::fs::write(
            dir.join(name),
            serde_json::json!({ "folder": folder }).to_string(),
        )
        .unwrap()
    };
    cfg("connector.17.json", r"D:\Cloud\Toto");
    // Parent d'un dossier en usage, dossier en usage (casse, barre finale).
    cfg("connector.18.json", r"D:\Cloud");
    cfg("connector.19.json", r"D:\Cloud\2\");
    // Configuration active : pas un ancien dossier.
    cfg("connector.json", r"D:\Cloud\Zut");
    let mut got = stale_folders(
        &dir,
        &[PathBuf::from(r"D:\Cloud\1"), PathBuf::from(r"d:\cloud\2")],
    );
    got.sort();
    assert_eq!(
        got,
        vec![
            PathBuf::from(r"D:\Cloud\Titi"),
            PathBuf::from(r"D:\Cloud\Toto")
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
