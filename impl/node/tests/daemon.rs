//! `deploiement.packaging` (partie node) : exécutable, API locale, état.

use std::path::PathBuf;

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::daemon::*;
use s3m_node::exchange::{NodeService, PartnerState};
use s3m_protocol::exchange::{Body, Request, Response};
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
            max_capacity_bytes: 100 << 30,
            draining: false,
        }],
        listen: "/ip4/127.0.0.1/tcp/0".into(),
        dht_listen: None,
        blocks_listen: None,
        bootstrap: vec![],
        api_port: 0,
        dispersal: Default::default(),
        upkeep: Default::default(),
        public_ip: None,
        public_port: None,
        partnering: Default::default(),
        partner_policy: Default::default(),
        attach: Default::default(),
        record_user_ips: true,
        history_days: 30,
        alerts: Default::default(),
        journal_days: 90,
        upnp: false,
        relay_server: true,
        relay_limits: Default::default(),
        relays: vec![],
        force_relay: false,
        mdns: false,
        remote_admin: false,
        admin_listen: "/ip4/127.0.0.1/tcp/0".into(),
        admin_totp_serial: 0,
        source: None,
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
        s3m_node::exchange::UserAccount {
            salt: vec![3; 16],
            quota_bytes: 10,
            used_bytes: 4,
            root: [5; 32],
        },
    );
    s.partners.insert(
        [6; 32],
        PartnerState {
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
    // Ligne d'utilisateur : bouton « Éditer » et panneau (quota, étiquette).
    let st = http(port, get(port, "/api/status", &auth)).await;
    assert!(
        st.contains("edit_user") && st.contains("panneau") && st.contains("set_user_label"),
        "{st}"
    );
    assert!(
        !st.contains("Changer le quota d'un utilisateur"),
        "formulaire en doublon retiré"
    );
    // Mode simple : cinq écrans, voyants, chaque action citée existe.
    let body: serde_json::Value = serde_json::from_str(st.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let simple = body["pages simples"].as_array().unwrap();
    assert_eq!(simple.len(), 5);
    assert_eq!(body["santé du nœud"].as_array().unwrap().len(), 5);
    // Équilibre (100 Gio ; 10 × 10 Gio autorisés ; 20 Gio de secours ; 2 % de
    // système) : il manque 22 Gio aux partenaires, alerte et solutions.
    let bal = &body["équilibre du stockage"];
    assert_eq!(bal["espace restant pour les partenaires"], "−22.0 Gio", "{bal}");
    assert!(bal["espace des utilisateurs"].as_str().unwrap().ends_with("/ 100.0 Gio"));
    assert!(bal["à corriger"].as_array().unwrap().len() >= 4);
    let names: Vec<&str> = body["actions"].as_array().unwrap().iter().filter_map(|a| a["nom"].as_str()).collect();
    for p in simple {
        for a in p["actions"].as_array().unwrap() {
            // Actions présentes seulement en situation (liste de volumes en
            // cours, messages non lus).
            let conditional = ["volume_apply", "volume_draft_clear", "mark_all_user_messages_read", "set_config"];
            let n = a.as_str().unwrap();
            assert!(names.contains(&n) || conditional.contains(&n), "action {a} absente");
        }
    }

    // Le service écrit sur disque (blocs de 64 Kio exactement).
    {
        let mut s = shared.service.lock().unwrap();
        s.partners.insert([0x33; 32], PartnerState::default());
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

/// Configuration modifiée depuis le dashboard : seuls les champs changés sont
/// écrits, la validation refuse une valeur invalide, les réglages non
/// applicables à chaud sont signalés.
#[test]
fn settings_apply_edits_file() {
    use s3m_node::settings::{apply, forms};
    let dir = temp_dir("settings");
    let path = dir.join("node.json");
    let running = config(&dir);
    std::fs::write(&path, serde_json::to_string_pretty(&running).unwrap()).unwrap();
    let a = apply(
        &path,
        &serde_json::json!({ "partenaires au plus": "7", "ouverture de port UPnP": true,
                             "nœuds d'amorçage": "/ip4/1.2.3.4/tcp/1, /ip4/5.6.7.8/tcp/2" }),
    )
    .unwrap();
    assert_eq!(a.live, vec!["partenaires au plus"]);
    assert_eq!(a.restart.len(), 2);
    assert_eq!(a.config.partner_policy.max_partners, 7);
    assert!(a.config.upnp);
    assert_eq!(a.config.bootstrap.len(), 2);
    // Relecture : plus rien à changer ; réglages en attente de redémarrage.
    let again = apply(&path, &serde_json::json!({ "partenaires au plus": "7" })).unwrap();
    assert!(again.live.is_empty() && again.restart.is_empty());
    let file = serde_json::to_value(Config::load(&path).unwrap()).unwrap();
    let (f, pending) = forms(&file, &serde_json::to_value(&running).unwrap());
    assert!(!f.is_empty());
    assert!(pending.contains(&"ouverture de port UPnP".to_string()));
    assert!(apply(
        &path,
        &serde_json::json!({ "partenaires au plus": "beaucoup" })
    )
    .is_err());
    assert_eq!(Config::load(&path).unwrap().partner_policy.max_partners, 7);
    // Ports d'écoute réglables (plusieurs Nœuds sur une machine).
    let a = apply(
        &path,
        &serde_json::json!({ "adresse d'écoute (blocs et annuaire)": "/ip4/0.0.0.0/tcp/4011",
                             "adresse d'écoute": "/ip4/0.0.0.0/tcp/4013" }),
    )
    .unwrap();
    assert_eq!(
        a.config.listen_addrs(),
        vec!["/ip4/0.0.0.0/tcp/4011".to_string()]
    );
    assert_eq!(a.config.admin_listen, "/ip4/0.0.0.0/tcp/4013");
    assert!(apply(
        &path,
        &serde_json::json!({ "adresse d'écoute (blocs et annuaire)": "4011" })
    )
    .is_err());
    assert!(apply(
        &path,
        &serde_json::json!({ "adresse d'écoute": "/ip4/0.0.0.0/udp/4013" })
    )
    .is_err());
}

#[test]
fn listen_setting_is_single_and_old_files_still_load() {
    let mut c = config(&temp_dir("listen"));
    c.listen = "/ip4/0.0.0.0/tcp/4001".into();
    assert_eq!(c.listen_addrs(), vec!["/ip4/0.0.0.0/tcp/4001".to_string()]);
    let v = serde_json::to_value(&c).unwrap();
    assert!(v.get("dht_listen").is_none() && v.get("blocks_listen").is_none());
    // Fichier d'avant la pile unique : ses deux ports restent ceux écoutés.
    let mut old = v.clone();
    old["dht_listen"] = "/ip4/0.0.0.0/tcp/4001".into();
    old["blocks_listen"] = "/ip4/0.0.0.0/tcp/4002".into();
    old.as_object_mut().unwrap().remove("listen");
    let old: Config = serde_json::from_value(old).unwrap();
    assert_eq!(
        old.listen_addrs(),
        vec![
            "/ip4/0.0.0.0/tcp/4002".to_string(),
            "/ip4/0.0.0.0/tcp/4001".to_string()
        ]
    );
}

/// 2FA du Nœud (`deploiement.packaging#2fa-noeud`) : bandeau tant qu'il n'est
/// pas activé ; une action critique sans code est différée de 72 h,
/// annulable, puis exécutée à échéance ; avec un code valide, aussitôt.
#[tokio::test(flavor = "multi_thread")]
async fn critical_actions_need_the_node_2fa_or_wait_72_hours() {
    use std::sync::atomic::Ordering::SeqCst;
    let dir = temp_dir("node2fa");
    let (sh, _url) = start(config(&dir)).await.unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let st = status(&sh, now);
    assert!(st["bandeau"]["texte"].as_str().unwrap().contains("2FA"));
    // Le formulaire d'une action critique porte le champ « code 2FA ».
    assert!(st.to_string().contains("code 2FA"));
    // Sans code : différée, puis annulée.
    let r = act(&sh, "regenerate_totp", serde_json::json!({})).unwrap();
    assert!(r["message"].as_str().unwrap().contains("72 h"), "{r}");
    assert_eq!(sh.admin_serial.load(SeqCst), 0, "rien d'exécuté");
    let id = sh.node2fa.lock().unwrap().pending[0].id;
    act(&sh, "cancel_node_op", serde_json::json!({ "id": id.to_string() })).unwrap();
    assert!(sh.node2fa.lock().unwrap().pending.is_empty());
    // Activation par un code, puis code exigé et vérifié.
    let secret = admin_secret(&sh).unwrap();
    let code = |t: u64| format!("{:06}", s3m_node::admin::hotp(&secret, t / 30, 6));
    act(&sh, "enable_node_2fa", serde_json::json!({ "code": code(now - 30) })).unwrap();
    assert!(status(&sh, now).get("bandeau").is_none(), "bandeau retiré");
    assert!(act(&sh, "regenerate_totp", serde_json::json!({ "code 2FA": "000000" })).is_err());
    // Différée puis exécutée à échéance : nouvelle série, 2FA à réactiver.
    act(&sh, "regenerate_totp", serde_json::json!({})).unwrap();
    run_due_node_ops(&sh, now + 71 * 3600);
    assert_eq!(sh.admin_serial.load(SeqCst), 0);
    run_due_node_ops(&sh, now + 73 * 3600);
    assert_eq!(sh.admin_serial.load(SeqCst), 1, "exécutée à échéance");
    assert!(status(&sh, now).get("bandeau").is_some(), "2FA à réactiver");
    // État conservé sur disque.
    assert_eq!(s3m_node::node2fa::load(&dir.join("data")).enabled_serial, Some(0));
}
