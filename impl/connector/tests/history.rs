//! Historique des versions (`protocols.historique-versions`) : version
//! passée parcourue, lue, restaurée ; blocs gardés puis libérés à la purge.

use std::sync::{Arc, Mutex};

use s3m_connector::daemon::*;
use s3m_node::exchange::{BlockServer, NodeService, UserAccount};
use serde_json::{json, Value};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NODE: [u8; 32] = [0x13; 32];

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s)
        .verifying_key()
        .to_bytes()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_past_version_is_browsed_restored_then_purged() {
    let dir = std::env::temp_dir().join(format!("p2p-history-{}", std::process::id()));
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
    let sh2 = sh.clone();
    let used = {
        let service = service.clone();
        move || service.lock().unwrap().users[&pub_user].used_bytes
    };
    tokio::task::spawn_blocking(move || {
        let sh = sh2;
        let act = |name: &str, v: Value| -> Result<Value, String> {
            s3m_connector::explorer::action(&sh, name, &v).expect("action de l'explorateur")
        };
        let put = |text: &str| {
            act(
                "explorer_write",
                json!({ "chemin": "/a.txt", "offset": 0, "données": hex::encode(text), "fin": true }),
            )
            .unwrap();
            sync_drive(&sh).unwrap().unwrap();
        };
        let read = |version: Option<&str>| -> String {
            let mut v = json!({ "chemin": "/a.txt", "offset": 0 });
            if let Some(x) = version {
                v["version"] = json!(x);
            }
            let r = act("explorer_read", v).unwrap();
            String::from_utf8(hex::decode(r["données"].as_str().unwrap()).unwrap()).unwrap()
        };
        put("version 1");
        put("version 2");
        let before_purge = used();

        // Une version passée, lisible ; la version actuelle inchangée.
        let r = act("explorer_versions", json!({ "chemin": "/a.txt" })).unwrap();
        let versions = r["versions"].as_array().unwrap().clone();
        assert_eq!(versions.len(), 1, "{r}");
        assert_eq!(r["conservation (jours)"], 30);
        let id = versions[0]["version"].as_str().unwrap().to_string();
        assert_eq!(read(Some(&id)), "version 1");
        assert_eq!(read(None), "version 2");
        let listed = act("explorer_list", json!({ "chemin": "/", "version": id })).unwrap();
        assert_eq!(listed["lecture seule"], true);
        assert_eq!(listed["entrées"][0]["nom"], "a.txt");

        // Blocs remplacés gardés pour l'historique (comptés dans le quota).
        let st = status(&sh);
        let held = st["historique des versions"]["_contenu"]["espace occupé par l'historique (octets)"]
            .as_u64()
            .unwrap();
        assert!(held > 0, "{st}");

        // Restauration : la version 1 redevient l'actuelle, la 2 entre dans
        // l'historique.
        act("explorer_restore", json!({ "chemin": "/a.txt", "version": id })).unwrap();
        sync_drive(&sh).unwrap().unwrap();
        assert_eq!(read(None), "version 1");
        let r = act("explorer_versions", json!({ "chemin": "/a.txt" })).unwrap();
        assert_eq!(r["versions"].as_array().unwrap().len(), 2);
        // Espace entier : version actuelle en tête, décomptes par version.
        let all = act("explorer_versions", json!({ "chemin": "/" })).unwrap();
        let rows = all["versions"].as_array().unwrap();
        assert_eq!(rows[0]["actuelle"], true);
        assert_eq!((rows[0]["ajouts"].as_u64(), rows[0]["modifications"].as_u64()), (Some(0), Some(1)));
        // Favori en un clic, éléments récents sur l'accueil.
        let r = act("explorer_favorite", json!({ "chemin": "/a.txt" })).unwrap();
        assert_eq!(r["favori"], true);
        let listed = act("explorer_list", json!({ "chemin": "/" })).unwrap();
        assert!(listed["entrées"].as_array().unwrap().iter().any(|e| e["nom"] == "a.txt" && e["favori"] == true));
        act("explorer_fav_rename", json!({ "chemin": "/a.txt", "nom": "Mon fichier" })).unwrap();
        let st = status(&sh);
        assert_eq!(st["favoris"]["_contenu"][0]["nom"], "Mon fichier");
        assert_eq!(st["favoris"]["_contenu"][0]["_explorer"], "/");
        assert_eq!(st["récents"]["_contenu"][0]["emplacement"], "/a.txt");
        assert_eq!(st["pages simples"][0]["sections"].as_array().unwrap().iter().filter(|x| *x == "favoris").count(), 1);

        // Purge : plus aucune version, blocs gardés libérés chez le Nœud.
        let msg = purge_versions(&sh, &json!({ "avant": "0" }))
            .unwrap();
        assert!(msg["message"].as_str().unwrap().contains("Historique purgé"), "{msg}");
        let r = act("explorer_versions", json!({ "chemin": "/a.txt" })).unwrap();
        assert!(r["versions"].as_array().unwrap().is_empty());
        assert_eq!(read(None), "version 1");
        assert!(used() < before_purge, "quota rendu");

        // Garde-fou : modification massive de fichiers existants
        // (rançongiciel ?) : synchronisation suspendue jusqu'à l'accord.
        use std::sync::atomic::Ordering::Relaxed;
        // Écritures directes dans le lecteur (sans relancer la surveillance).
        let write_all = |tag: &str| {
            let mut d = sh.drive.as_ref().unwrap().lock().unwrap();
            for i in 0..MASS_CHANGE {
                let p = format!("/m/{i}.txt");
                if d.stat(&p).unwrap().is_none() {
                    d.create(&p, false).unwrap();
                }
                d.set_size(&p, 0).unwrap();
                d.write(&p, 0, format!("{tag} {i}").as_bytes()).unwrap();
            }
        };
        sh.drive.as_ref().unwrap().lock().unwrap().create("/m", true).unwrap();
        write_all("clair");
        sync_drive(&sh).unwrap().unwrap();
        write_all("chiffré");
        assert_eq!(sync_drive(&sh).unwrap().unwrap(), 0);
        assert!(sh.paused.load(Relaxed) && sh.mass_change.load(Relaxed));
        assert_eq!(tray_view(&sh).text, MASS_CHANGE_TEXT);
        // L'Utilisateur reprend : la synchronisation passe.
        sh.paused.store(false, Relaxed);
        assert!(sync_drive(&sh).unwrap().unwrap() > 0);
        assert!(!sh.mass_change.load(Relaxed));
    })
    .await
    .unwrap();
    s3m_connector::daemon::stop(sh).await;
    let _ = std::fs::remove_dir_all(&dir);
}
