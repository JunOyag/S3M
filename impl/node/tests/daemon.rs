//! `deploiement.packaging` (partie node) : exécutable, API locale, état.

use std::path::PathBuf;

use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_node::daemon::*;
use p2p_storage_node::exchange::{NodeService, PartnerState};
use p2p_storage_protocol::exchange::{Body, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("p2p-node-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn config(dir: &std::path::Path) -> Config {
    std::fs::write(dir.join("node.seed"), MNEMONIC).unwrap();
    Config {
        seed_file: dir.join("node.seed"),
        identity_index: 0,
        data_dir: dir.join("data"),
        volumes: vec![VolumeSpec {
            volume_id: 1,
            mount_path: dir.join("vol"),
            max_capacity_bytes: 1 << 30,
        }],
        dht_listen: "/ip4/127.0.0.1/tcp/0".into(),
        blocks_listen: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap: vec![],
        api_port: 0,
        dispersal: Default::default(),
        upkeep: Default::default(),
    }
}

async fn http(port: u16, req: String) -> String {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

fn get(port: u16, path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}Connection: close\r\n\r\n")
}

#[test]
fn mnemonic_is_validated_and_generated_phrases_are_usable() {
    assert!(node_seed_from_mnemonic(MNEMONIC, 0).is_ok());
    assert!(node_seed_from_mnemonic("abandon abandon", 0).is_err());
    let m = generate_mnemonic().unwrap();
    assert_eq!(m.split_whitespace().count(), 24);
    assert_ne!(
        node_seed_from_mnemonic(&m, 0).unwrap(),
        node_seed_from_mnemonic(MNEMONIC, 0).unwrap()
    );
}

#[test]
fn saved_state_roundtrips_users_partners_and_addresses() {
    let mut s = NodeService::new([1; 32]);
    s.users.insert(
        [2; 32],
        p2p_storage_node::exchange::UserAccount {
            salt: vec![3; 16],
            quota_bytes: 10,
            used_bytes: 4,
            root: [5; 32],
        },
    );
    s.partners.insert(
        [6; 32],
        PartnerState {
            allowance: 7,
            last_seen: 8,
            ..Default::default()
        },
    );
    s.previous_node_ids = vec![[9; 32]];
    let addrs = [([6; 32], "/ip4/1.2.3.4/tcp/4002".to_string())].into();
    let saved = SavedState::capture(&s, &addrs);
    let mut back = NodeService::new([1; 32]);
    assert_eq!(saved.restore(&mut back).unwrap(), addrs);
    assert_eq!(SavedState::capture(&back, &addrs), saved);
}

/// Démarrage réel : stockage disque, API protégée, état restauré au
/// redémarrage.
#[tokio::test(flavor = "multi_thread")]
async fn node_starts_serves_a_guarded_dashboard_and_persists_its_state() {
    let dir = temp_dir("daemon");
    let (shared, url) = start(config(&dir)).await.unwrap();
    let (base, frag) = url.split_once("/#token=").unwrap();
    let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();

    let page = http(port, get(port, "/", "")).await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("app.js"));
    let anonymous = http(port, get(port, "/api/status", "")).await;
    assert!(anonymous.starts_with("HTTP/1.1 403"));
    let auth = format!("Authorization: Bearer {frag}\r\n");
    let ok = http(port, get(port, "/api/status", &auth)).await;
    assert!(
        ok.starts_with("HTTP/1.1 200") && ok.contains("partenaires"),
        "{ok}"
    );
    let rebound = format!(
        "GET /api/status HTTP/1.1\r\nHost: evil.example:{port}\r\n{auth}Connection: close\r\n\r\n"
    );
    assert!(http(port, rebound).await.starts_with("HTTP/1.1 403"));

    // Action du dashboard : rattachement d'un utilisateur.
    let body = format!(
        r#"{{"user_id":"{}","salt":"{}","quota_bytes":"200000"}}"#,
        "11".repeat(32),
        "22".repeat(16)
    );
    let post = format!(
        "POST /api/action/attach_user HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    assert!(http(port, post).await.starts_with("HTTP/1.1 200"));

    // Le service écrit sur disque (blocs de 64 Kio exactement).
    {
        let mut s = shared.service.lock().unwrap();
        s.partners.insert(
            [0x33; 32],
            PartnerState {
                allowance: 2,
                ..Default::default()
            },
        );
        let data = vec![7u8; 65_536];
        let r = s.handle(
            b"x",
            Some([0x33; 32]),
            b"me",
            Request {
                credential: None,
                body: Body::StoreFragment { data: data.clone() },
            },
            1,
        );
        assert!(matches!(r, Response::FragmentReceipt { .. }), "{r:?}");
        let small = Request {
            credential: None,
            body: Body::StoreFragment { data: vec![1; 10] },
        };
        assert!(matches!(
            s.handle(b"x", Some([0x33; 32]), b"me", small, 1),
            Response::Failure(_)
        ));
        let fetch = Request {
            credential: None,
            body: Body::FetchFragment {
                hash: hash_sha256(&data).to_vec(),
            },
        };
        assert_eq!(
            s.handle(b"x", Some([0x33; 32]), b"me", fetch, 1),
            Response::BlockData(data)
        );
    }
    save(&shared).unwrap();
    let saved = load_state(&dir.join("data/state.json")).unwrap();
    assert_eq!(saved.users.len(), 1);
    assert_eq!(saved.users[0].quota_bytes, 200_000);
    assert_eq!(saved.partners[0].hosted_by_partner, 1);
}
