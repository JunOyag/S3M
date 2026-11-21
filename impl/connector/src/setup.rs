//! Assistant de premier lancement — id `deploiement.packaging` § Application
//! de la barre des tâches. Sans configuration dans `%APPDATA%\S3m` : phrase de
//! récupération créée et affichée (à recopier), Nœuds du réseau local
//! recherchés (`lan`), choix d'un Nœud ou saisie de son adresse, puis
//! écriture de `connector.json` ; le démarrage normal suit, avec rattachement
//! automatique. La phrase s'affiche en code de récupération (QR code) ; une
//! identité existante peut être reprise ; un Nœud « à configurer » se
//! configure par appairage (`deploiement.appairage-admin`).

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

/// « Changer de Nœud » : `connector.json` et `data` sont renommés
/// (suffixe horodaté) ; l'identité (`user.seed`, `attach.salt`) reste.
/// L'assistant s'ouvre au démarrage suivant.
pub fn set_aside_config(dir: &Path, stamp: u64) -> std::io::Result<()> {
    let cfg = config_path(dir);
    if cfg.exists() {
        std::fs::rename(&cfg, dir.join(format!("connector.{stamp}.json")))?;
    }
    let data = dir.join("data");
    if data.exists() {
        std::fs::rename(&data, dir.join(format!("data.{stamp}")))?;
    }
    Ok(())
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

/// QR code SVG d'un texte (correction d'erreur M).
pub fn qr_svg(text: &str) -> String {
    match qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M) {
        Ok(c) => c
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

/// Code de récupération d'Utilisateur (`S3M1:U:…`) d'une phrase.
pub fn user_recovery_code(mnemonic: &str) -> Result<String, String> {
    let m = bip39::Mnemonic::parse_normalized(mnemonic).map_err(|e| e.to_string())?;
    s3m_core::identity_derivation::recovery_code_encode(
        s3m_core::identity_derivation::RecoveryRole::User,
        &m.to_entropy(),
    )
    .map_err(|e| e.to_string())
}

/// Saisie d'une identité existante : code `S3M1:U:…` ou 12 à 24 mots.
pub fn parse_user_recovery(input: &str) -> Result<String, String> {
    use s3m_core::identity_derivation::{recovery_code_decode, RecoveryRole};
    let t = input.trim();
    if t.to_ascii_uppercase().starts_with("S3M1") {
        let (role, entropy) = recovery_code_decode(t).map_err(|e| e.to_string())?;
        if role != RecoveryRole::User {
            return Err("code de Nœud : un code d'Utilisateur (S3M1:U:…) est attendu".into());
        }
        return bip39::Mnemonic::from_entropy(&entropy)
            .map(|m| m.to_string())
            .map_err(|e| e.to_string());
    }
    let words = t
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    bip39::Mnemonic::parse_normalized(&words)
        .map(|m| m.to_string())
        .map_err(|e| format!("phrase de récupération : {e}"))
}

/// Remplace l'identité préparée par une identité existante.
pub fn restore(dir: &Path, input: &str) -> Result<Prepared, String> {
    let mnemonic = parse_user_recovery(input)?;
    std::fs::write(dir.join("user.seed"), format!("{mnemonic}\n")).map_err(|e| e.to_string())?;
    prepare(dir)
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
        emergency_write: true,
        n_secours: crate::emergency::DEFAULT_N_SECOURS,
        source: None,
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
    let prepared = Arc::new(Mutex::new(prepare(&dir)?));
    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(SetupState {
        notify: Some(tx),
        ..Default::default()
    }));
    rescan(state.clone());
    let st_fn: StatusFn = {
        let (state, p) = (state.clone(), prepared.clone());
        Arc::new(move || {
            let p = p.lock().unwrap().clone();
            let s = state.lock().unwrap();
            if let Some(path) = &s.done {
                return json!({ "titre": "S3m — configuration terminée",
                    "état": format!("Configuration enregistrée ({}). S3m démarre et ouvre le tableau de bord : vous pouvez fermer cette page.", path.display()) });
            }
            let found: Vec<Value> = s
                .found
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    if n.to_configure {
                        return json!({
                            "numéro": i + 1,
                            "nœud": format!("{}…", &hex::encode(n.node_id)[..16]),
                            "adresse": n.addr,
                            "état": "à configurer (code d'appairage)",
                        });
                    }
                    json!({
                        "numéro": i + 1,
                        "nœud": format!("{}…", &hex::encode(n.node_id)[..16]),
                        "adresse": n.addr,
                        "état": if n.accepting_partners { "prêt" } else { "prêt (n'accepte pas de partenaires)" },
                        "_actions": [{ "nom": "choose", "libellé": "Se rattacher",
                                       "valeurs": { "numéro": (i + 1).to_string() } }],
                    })
                })
                .collect();
            json!({
                "titre": "S3m — premier lancement",
                "1. votre code de récupération (à imprimer, ne pas photographier)": {
                    "QR code": user_recovery_code(&p.mnemonic).map(|c| qr_svg(&c)).unwrap_or_default(),
                    "code": user_recovery_code(&p.mnemonic).unwrap_or_default(),
                    "24 mots": p.mnemonic,
                    "important": "Gardez-le hors de cet ordinateur : lui seul permet de retrouver vos fichiers.",
                },
                "2. nœuds trouvés sur le réseau local": if s.scanning { json!("recherche en cours…") } else if found.is_empty() { json!("aucun (le Nœud est-il allumé, sur le même réseau, mDNS actif ?)") } else { json!(found) },
                "3. si le Nœud n'accepte pas le rattachement automatique, transmettez à son opérateur": {
                    "user_id": p.user_id,
                    "salt": p.salt,
                },
                "message": s.message,
                "actions": [
                    { "nom": "restore", "titre": "J'ai déjà une identité S3m",
                      "libellé": "Reprendre cette identité", "champs": ["code de récupération ou phrase"],
                      "aide": { "code de récupération ou phrase": "Code S3M1:U:… (QR code) ou les 24 mots" } },
                    { "nom": "configure_node", "titre": "Configurer un Nœud « à configurer »",
                      "libellé": "Ouvrir son assistant", "champs": ["numéro ou adresse", "code d'appairage"],
                      "aide": { "numéro ou adresse": "Numéro dans la liste, ou adresse d'administration affichée par le Nœud",
                                "code d'appairage": "Affiché par le Nœud (console, journaux ou son tableau de bord)" } },
                    { "nom": "manual", "titre": "Nœud absent de la liste : saisir son adresse",
                      "libellé": "Se rattacher", "champs": ["adresse"] },
                    { "nom": "scan", "libellé": "Rechercher à nouveau", "champs": [] }
                ]
            })
        })
    };
    let act_fn: ActionFn = {
        let (state, p, dir) = (state.clone(), prepared, dir.clone());
        Arc::new(move |name, v| {
            let addr = match name {
                "restore" => {
                    let input = v
                        .get("code de récupération ou phrase")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default();
                    *p.lock().unwrap() = restore(&dir, input)?;
                    return Ok(
                        json!({ "ok": true, "message": "Identité reprise : choisissez maintenant votre Nœud" }),
                    );
                }
                "configure_node" => {
                    let which = v
                        .get("numéro ou adresse")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    let code = v
                        .get("code d'appairage")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let addr: Multiaddr = match which.parse::<usize>() {
                        Ok(n) => {
                            let node = state
                                .lock()
                                .unwrap()
                                .found
                                .get(n.wrapping_sub(1))
                                .cloned()
                                .ok_or("numéro hors de la liste")?;
                            if !node.to_configure {
                                return Err("ce Nœud est déjà configuré : « Se rattacher »".into());
                            }
                            node.addr.parse().map_err(|e| format!("{e}"))?
                        }
                        Err(_) => which.parse().map_err(|e| format!("adresse : {e}"))?,
                    };
                    return tokio::runtime::Handle::current().block_on(async move {
                        let client = crate::admin_client::AdminClient::start()?;
                        let session = client.pair(&addr, &code).await?;
                        let url = crate::remote::serve_remote(session).await?;
                        Ok(json!({ "ok": true, "message": "Nœud appairé : son assistant s'ouvre", "ouvrir": url }))
                    });
                }
                "scan" => {
                    rescan(state.clone());
                    return Ok(
                        json!({ "ok": true, "message": "Recherche des Nœuds du réseau local…" }),
                    );
                }
                "choose" => {
                    let n: usize = v
                        .get("numéro")
                        .and_then(|x| x.as_str())
                        .and_then(|x| x.trim().parse().ok())
                        .ok_or("numéro invalide")?;
                    let s = state.lock().unwrap();
                    let f = s
                        .found
                        .get(n.wrapping_sub(1))
                        .ok_or("numéro hors de la liste")?;
                    if f.to_configure {
                        return Err(
                            "Nœud à configurer : configurez-le d'abord avec son code d'appairage"
                                .into(),
                        );
                    }
                    f.addr.clone()
                }
                "manual" => v
                    .get("adresse")
                    .and_then(|x| x.as_str())
                    .ok_or("adresse manquante")?
                    .to_string(),
                _ => return Err(format!("action inconnue : {name}")),
            };
            let p = p.lock().unwrap().clone();
            match write_config(&dir, &p, &addr) {
                Ok(path) => {
                    let mut s = state.lock().unwrap();
                    s.done = Some(path.clone());
                    if let Some(tx) = s.notify.take() {
                        let _ = tx.send(path);
                    }
                    Ok(json!({ "ok": true, "message": "Configuration enregistrée : S3m démarre" }))
                }
                // L'erreur s'affiche dans un message éphémère.
                Err(e) => Err(e),
            }
        })
    };
    let url = local_http::serve(0, st_fn, act_fn, ASSETS)
        .await
        .map_err(|e| e.to_string())?;
    Ok((url, rx))
}
