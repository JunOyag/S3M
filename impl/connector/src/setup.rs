//! Assistant de premier lancement — id `deploiement.packaging` § Application
//! de la barre des tâches. Sans configuration dans `%APPDATA%\S3m` : phrase de
//! récupération créée et affichée (à recopier), Nœuds du réseau local
//! recherchés (`lan`), choix d'un Nœud ou saisie de son adresse, puis
//! écriture de `connector.json` ; le démarrage normal suit, avec rattachement
//! automatique.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::daemon::{
    generate_mnemonic, random32, user_keys, Config, NodeLink, DEFAULT_Q_MAX_BYTES,
    DEFAULT_WATCH_INTERVAL_S,
};
use crate::lan::{node_id_of, scan, FoundNode};
use crate::local_http::{self, ActionFn, Asset, StatusFn};

/// Répertoire de l'application : `%APPDATA%\S3m` (sinon `./S3m`).
pub fn app_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("S3m")
}

/// Fichier de configuration du Connecteur.
pub fn config_path(dir: &Path) -> PathBuf {
    dir.join("connector.json")
}

/// Identité préparée avant le choix du Nœud.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub mnemonic: String,
    pub user_id: String,
    pub salt: String,
}

/// Crée (ou relit) la phrase de récupération et le sel d'attachement.
pub fn prepare(dir: &Path) -> Result<Prepared, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let seed = dir.join("user.seed");
    let mnemonic = match std::fs::read_to_string(&seed) {
        Ok(m) => m.trim().to_string(),
        Err(_) => {
            let m = generate_mnemonic().map_err(|e| e.to_string())?;
            std::fs::write(&seed, format!("{m}\n")).map_err(|e| e.to_string())?;
            m
        }
    };
    let salt_file = dir.join("attach.salt");
    let salt = match std::fs::read_to_string(&salt_file) {
        Ok(s) if s.trim().len() == 32 => s.trim().to_string(),
        _ => {
            let s = hex::encode(&random32().map_err(|e| e.to_string())?[..16]);
            std::fs::write(&salt_file, &s).map_err(|e| e.to_string())?;
            s
        }
    };
    let (_, pub_user) = user_keys(&mnemonic, 0).map_err(|e| e.to_string())?;
    Ok(Prepared {
        mnemonic,
        user_id: hex::encode(pub_user),
        salt,
    })
}

/// Première lettre de lecteur libre, de P: à Z:.
pub fn free_drive_letter() -> String {
    for c in 'P'..='Z' {
        if !Path::new(&format!("{c}:\\")).exists() {
            return format!("{c}:");
        }
    }
    "P:".into()
}

/// Écrit la configuration pour le Nœud `addr` (`…/p2p/<PeerId>`).
pub fn write_config(dir: &Path, prepared: &Prepared, addr: &str) -> Result<PathBuf, String> {
    let m: Multiaddr = addr
        .trim()
        .parse()
        .map_err(|e| format!("adresse invalide : {e}"))?;
    let Some(Protocol::P2p(peer)) = m.iter().last() else {
        return Err("l'adresse doit se terminer par /p2p/<identifiant du Nœud>".into());
    };
    let node_id = node_id_of(&peer).ok_or("identifiant de Nœud invalide")?;
    let config = Config {
        seed_file: "user.seed".into(),
        identity_index: 0,
        data_dir: "data".into(),
        node: NodeLink {
            addr: m.to_string(),
            node_id: hex::encode(node_id),
            salt: prepared.salt.clone(),
        },
        api_port: 0,
        q_max_bytes: DEFAULT_Q_MAX_BYTES,
        watch_interval_s: DEFAULT_WATCH_INTERVAL_S,
        mount_point: Some(free_drive_letter()),
        // DHT et échange de blocs partagent la pile du Nœud.
        dht_bootstrap: vec![m.to_string()],
        auto_attach: true,
    };
    let path = config_path(dir);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&config).expect("sérialisable"),
    )
    .map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(Default)]
struct SetupState {
    found: Vec<FoundNode>,
    scanning: bool,
    message: Option<String>,
    done: Option<PathBuf>,
    notify: Option<oneshot::Sender<PathBuf>>,
}

const ASSETS: &[Asset] = &[
    (
        "logo.png",
        "image/png",
        include_bytes!("../dashboard/logo.png"),
    ),
    (
        "index.html",
        "text/html; charset=utf-8",
        include_bytes!("../dashboard/index.html"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../dashboard/app.js"),
    ),
];

fn rescan(state: Arc<Mutex<SetupState>>) {
    state.lock().unwrap().scanning = true;
    tokio::spawn(async move {
        let found = scan(Duration::from_secs(4)).await.unwrap_or_default();
        let mut s = state.lock().unwrap();
        s.found = found;
        s.scanning = false;
    });
}

/// Sert l'assistant ; rend l'URL à ouvrir et le chemin de la configuration
/// écrite une fois le Nœud choisi.
pub async fn serve_setup(dir: PathBuf) -> Result<(String, oneshot::Receiver<PathBuf>), String> {
    let prepared = prepare(&dir)?;
    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(SetupState {
        notify: Some(tx),
        ..Default::default()
    }));
    rescan(state.clone());
    let st_fn: StatusFn = {
        let (state, p) = (state.clone(), prepared.clone());
        Arc::new(move || {
            let s = state.lock().unwrap();
            if let Some(path) = &s.done {
                return json!({ "titre": "S3m — configuration terminée",
                    "état": format!("Configuration enregistrée ({}). S3m démarre : vous pouvez fermer cette page.", path.display()) });
            }
            let found: Vec<Value> = s
                .found
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    json!({
                        "numéro": i + 1,
                        "nœud": format!("{}…", &hex::encode(n.node_id)[..16]),
                        "adresse": n.addr,
                        "accepte de nouveaux partenaires": n.accepting_partners,
                    })
                })
                .collect();
            json!({
                "titre": "S3m — premier lancement",
                "1. votre phrase de récupération": {
                    "phrase (24 mots)": p.mnemonic,
                    "important": "Recopiez-la sur papier et gardez-la hors de cet ordinateur : elle seule permet de retrouver vos fichiers.",
                },
                "2. nœuds trouvés sur le réseau local": if s.scanning { json!("recherche en cours…") } else if found.is_empty() { json!("aucun (le Nœud est-il allumé, sur le même réseau, mDNS actif ?)") } else { json!(found) },
                "3. si le Nœud n'accepte pas le rattachement automatique, transmettez à son opérateur": {
                    "user_id": p.user_id,
                    "salt": p.salt,
                },
                "message": s.message,
                "actions": [
                    { "nom": "choose", "libellé": "Utiliser le nœud n°", "champs": ["numéro"] },
                    { "nom": "manual", "libellé": "Utiliser l'adresse", "champs": ["adresse"] },
                    { "nom": "scan", "libellé": "Rechercher à nouveau", "champs": [] }
                ]
            })
        })
    };
    let act_fn: ActionFn = {
        let (state, p, dir) = (state.clone(), prepared, dir.clone());
        Arc::new(move |name, v| {
            let addr = match name {
                "scan" => {
                    rescan(state.clone());
                    return Ok(json!({ "ok": true }));
                }
                "choose" => {
                    let n: usize = v
                        .get("numéro")
                        .and_then(|x| x.as_str())
                        .and_then(|x| x.trim().parse().ok())
                        .ok_or("numéro invalide")?;
                    let s = state.lock().unwrap();
                    s.found
                        .get(n.wrapping_sub(1))
                        .ok_or("numéro hors de la liste")?
                        .addr
                        .clone()
                }
                "manual" => v
                    .get("adresse")
                    .and_then(|x| x.as_str())
                    .ok_or("adresse manquante")?
                    .to_string(),
                _ => return Err(format!("action inconnue : {name}")),
            };
            match write_config(&dir, &p, &addr) {
                Ok(path) => {
                    let mut s = state.lock().unwrap();
                    s.done = Some(path.clone());
                    if let Some(tx) = s.notify.take() {
                        let _ = tx.send(path);
                    }
                    Ok(json!({ "ok": true }))
                }
                Err(e) => {
                    state.lock().unwrap().message = Some(e.clone());
                    Err(e)
                }
            }
        })
    };
    let url = local_http::serve(0, st_fn, act_fn, ASSETS)
        .await
        .map_err(|e| e.to_string())?;
    Ok((url, rx))
}
