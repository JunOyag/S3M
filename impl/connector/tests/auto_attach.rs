//! Rattachement automatique (`protocols.partenariat-automatique`) : un
//! Connecteur jamais rattaché se rattache seul à un vrai Nœud qui l'autorise.

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_core::vdf::VdfProof;
use s3m_node::exchange::{AttachPolicy, BlockServer, NodeService};
use s3m_protocol::entries::encode_proof;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x10; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn unattached_connector_attaches_itself_with_the_node_policy_quota() {
    let dir = std::env::temp_dir().join(format!("p2p-auto-attach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("user.seed"), MNEMONIC).unwrap();
    // Preuve VDF déjà en cache (calcul réel hors de ce test).
    let proof = VdfProof {
        y: vec![1; 100],
        pi: vec![2; 100],
    };
    std::fs::write(dir.join("data/vdf_proof.bin"), encode_proof(&proof)).unwrap();

    let mut ns = NodeService::new(NODE);
    ns.vdf = Some(Arc::new(|_, _| true));
    ns.attach_policy = AttachPolicy {
        enabled: true,
        quota_bytes: 5 << 30,
        max_users: 3,
        budget_bytes: 20 << 30,
    };
    let ns = Arc::new(Mutex::new(ns));
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 1_000_000);
    let node = BlockServer::start(
        NODE,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        ns.clone(),
        clock.clone(),
    )
    .await
    .unwrap();

    let config = Config {
        seed_file: dir.join("user.seed"),
        identity_index: 0,
        data_dir: dir.join("data"),
        node: NodeLink {
            addr: node.listen_addr().await.unwrap().to_string(),
            node_id: hex::encode(pk(&NODE)),
            salt: hex::encode([9u8; 16]),
        },
        api_port: 0,
        q_max_bytes: DEFAULT_Q_MAX_BYTES,
        watch_interval_s: 3600,
        mount_point: None,
        dht_bootstrap: vec![],
        auto_attach: true,
    };
    let (shared, _) = start(config, clock).await.unwrap();
    // Un premier tour peut échouer côté réseau (connexion en cours) : la
    // surveillance réessaie à chaque tour, comme en production.
    for _ in 0..5 {
        watch_once(&shared).await;
        if shared.attach.lock().unwrap().attached_quota.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let a = shared.attach.lock().unwrap().clone();
    assert_eq!(a.attached_quota, Some(5 << 30), "{:?}", a.last_error);
    assert_eq!(shared.health.lock().unwrap().reachable, Some(true));
    let (_, pub_user) = user_keys(MNEMONIC, 0).unwrap();
    let s = ns.lock().unwrap();
    assert!(s.auto_attached.contains(&pub_user));
    assert_eq!(s.users[&pub_user].salt, vec![9; 16]);
    assert!(
        s.last_user_ip.contains_key(&pub_user),
        "adresse vue pour la carte"
    );
}
