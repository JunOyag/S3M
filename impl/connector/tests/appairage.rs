//! `deploiement.appairage-admin` de bout en bout sur libp2p : un Nœud sous
//! identité temporaire est configuré depuis un Connecteur par appairage, puis
//! administré à distance avec le code 2FA.

use std::sync::Arc;
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use s3m_connector::admin_client::AdminClient;
use s3m_node::admin::{hotp, serve, Mode, SecretFn, TOTP_STEP};
use s3m_node::daemon::Config;
use s3m_node::local_http::{ActionFn, StatusFn, Switch};
use serde_json::json;

fn admin_addr(listen: &[Multiaddr], peer: libp2p::PeerId) -> Multiaddr {
    listen[0].clone().with(Protocol::P2p(peer))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_temporary_node_is_configured_remotely_with_its_pairing_code() {
    let dir = std::env::temp_dir().join(format!("s3m-pair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config: Config = serde_json::from_value(json!({
        "seed_file": dir.join("node.seed"), "data_dir": dir.join("data"), "volumes": [],
        "dht_listen": "/ip4/127.0.0.1/tcp/0", "blocks_listen": "/ip4/127.0.0.1/tcp/0",
        "admin_listen": "/ip4/127.0.0.1/tcp/0", "mdns": false,
    }))
    .unwrap();
    let switch = Switch::new();
    // L'assistant écrit son code d'appairage dans son statut local.
    let (sw, cfg) = (switch.clone(), config.clone());
    let setup = tokio::spawn(async move { s3m_node::setup::run(&cfg, &sw).await });
    let mut code = String::new();
    for _ in 0..100 {
        let st = switch.status_fn()();
        if let Some(c) = st
            .pointer("/identité/code d'appairage")
            .and_then(|c| c.as_str())
        {
            code = c.to_string();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(code.len(), 9);
    let addr: Multiaddr = switch.status_fn()()["identité"]["adresses d'administration"][0]
        .as_str()
        .expect("adresse d'administration affichée")
        .parse()
        .unwrap();
    let client = AdminClient::start().unwrap();
    assert_eq!(client.hello(&addr).await.unwrap(), "setup");
    assert!(
        client.pair(&addr, "AAAA-AAAA").await.is_err(),
        "mauvais code refusé"
    );
    let session = client.pair(&addr, &code.to_lowercase()).await.unwrap();
    let st = session.status().await.unwrap();
    assert!(st["actions"].to_string().contains("new_identity"));
    session.action("new_identity", json!({})).await.unwrap();
    let st = session.status().await.unwrap();
    let words = st.pointer("/1. code de récupération (à imprimer, ne pas photographier)/24 mots");
    assert_eq!(
        words.and_then(|w| w.as_str()).unwrap().split(' ').count(),
        24
    );
    assert!(st.to_string().contains("<svg"), "QR codes fournis");
    assert!(
        !config.seed_file.exists(),
        "rien n'est écrit avant confirmation"
    );
    session.action("confirm", json!({})).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), setup)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(config.seed_file.exists(), "identité définitive enregistrée");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_configured_node_is_administered_with_the_totp_code_only() {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let secret: SecretFn = Arc::new(|| Some([5u8; 20]));
    let st: StatusFn = Arc::new(|| json!({ "titre": "Nœud", "carte": true }));
    let act: ActionFn = Arc::new(|n, _| Ok(json!({ "fait": n })));
    let server = serve(
        key,
        "/ip4/127.0.0.1/tcp/0",
        false,
        Mode::Node { secret },
        st,
        act,
    )
    .await
    .unwrap();
    let addr = admin_addr(&server.listen.lock().unwrap().clone(), peer);
    let client = AdminClient::start().unwrap();
    assert_eq!(client.hello(&addr).await.unwrap(), "node");
    assert!(
        client.pair(&addr, "AAAA-AAAA").await.is_err(),
        "plus d'appairage"
    );
    assert!(client.login(&addr, "000000").await.is_err() || hotp(&[5u8; 20], 0, 6) == 0);
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = format!("{:06}", hotp(&[5u8; 20], unix / TOTP_STEP, 6));
    let session = client.login(&addr, &code).await.unwrap();
    let v = session.status().await.unwrap();
    assert!(v.get("carte").is_none());
    assert_eq!(
        session.action("set_quota", json!({})).await.unwrap()["fait"],
        "set_quota"
    );
    assert!(
        session.action("regenerate_totp", json!({})).await.is_err(),
        "réservée au local"
    );
    // Le dashboard distant relaie statut et actions.
    let url = s3m_connector::remote::serve_remote(session).await.unwrap();
    assert!(url.starts_with("http://127.0.0.1:"));
    server.stop().await;
}
