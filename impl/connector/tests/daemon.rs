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
        dht_bootstrap: vec![],
        auto_attach: true,
        emergency_write: false,
        n_secours: 4,
    };
    let (shared, url) = start(config, clock).await.unwrap();
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
    let h = shared.health.lock().unwrap();
    assert_eq!(h.reachable, Some(false));
    assert_eq!(h.inactivity_detected_at, Some(NOW));
}
