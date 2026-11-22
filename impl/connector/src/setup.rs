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

/// Saisie d'une identité existante : phrase de 12 à 24 mots (casse et
/// espaces indifférents).
pub fn parse_user_recovery(input: &str) -> Result<String, String> {
    let words = input
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

/// Accès aux fichiers choisi dans l'assistant
/// (`protocols.acces-applicatif#mode-dossier`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessChoice {
    /// `lecteur` ou `dossier` ; absent : automatique.
    pub access: Option<String>,
    /// Emplacement du dossier synchronisé.
    pub folder: Option<PathBuf>,
    /// Lettre (Windows) ou point de montage (Linux, macOS) du lecteur.
    pub mount: Option<String>,
}

/// Dossier synchronisé proposé pour l'identité rangée dans `dir`.
pub fn default_folder(dir: &Path) -> PathBuf {
    let name = crate::daemon::identity_number(&config_path(dir))
        .map(|n| format!("S3m {n}"))
        .unwrap_or_else(|| "S3m".into());
    s3m_protocol::local_fs::home().join(name)
}

/// Lecteur ou dossier possibles sur cette machine.
pub fn drive_possible() -> bool {
    !cfg!(windows) || crate::daemon::winfsp_installed()
}

/// Valide le choix saisi dans l'assistant.
pub fn parse_access(v: &Value) -> Result<AccessChoice, String> {
    let text = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let access = text("accès").to_lowercase();
    match access.as_str() {
        "dossier" => {
            let f = PathBuf::from(text("dossier"));
            if !f.is_absolute() {
                return Err("dossier : chemin complet attendu (bouton « Parcourir… »)".into());
            }
            Ok(AccessChoice {
                access: Some(access),
                folder: Some(f),
                mount: None,
            })
        }
        "lecteur" => {
            if !drive_possible() {
                return Err(
                    "WinFsp n'est pas installé sur cet ordinateur : choisissez « Dossier »".into(),
                );
            }
            let mount = if cfg!(windows) {
                crate::daemon::parse_drive_letter(&text("lettre"))?
            } else {
                let p = text("point de montage");
                if !Path::new(&p).is_absolute() {
                    return Err("point de montage : chemin complet attendu".into());
                }
                p
            };
            Ok(AccessChoice {
                access: Some(access),
                folder: None,
                mount: Some(mount),
            })
        }
        _ => Err("accès attendu : « Dossier » ou « Périphérique »".into()),
    }
}

/// Écrit la configuration pour le Nœud `addr` (`…/p2p/<PeerId>`).
pub fn write_config(
    dir: &Path,
    prepared: &Prepared,
    addr: &str,
    choice: &AccessChoice,
) -> Result<PathBuf, String> {
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
        mount_point: Some(choice.mount.clone().unwrap_or_else(free_drive_letter)),
        access: choice.access.clone(),
        folder: choice.folder.clone(),
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
    /// Accès aux fichiers choisi, sinon automatique.
    access: AccessChoice,
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
        let (state, p, dir) = (state.clone(), prepared.clone(), dir.clone());
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
                            "_actions": [{ "nom": "configure_node", "libellé": "Ouvrir son assistant",
                                           "champs": ["code d'appairage"],
                                           "valeurs": { "numéro ou adresse": (i + 1).to_string() } }],
                        });
                    }
                    json!({
                        "numéro": i + 1,
                        "nœud": s3m_protocol::pseudo::display(&[n.name.as_deref()], &n.node_id),
                        "adresse": n.addr,
                        "état": if n.accepting_partners { "prêt" } else { "prêt (n'accepte pas de partenaires)" },
                        "_actions": [{ "nom": "choose", "libellé": "Se rattacher",
                                       "valeurs": { "numéro": (i + 1).to_string() } }],
                    })
                })
                .collect();
            json!({
                "titre": "S3m — premier lancement",
                "votre phrase de récupération (à noter sur papier, ne pas photographier)": {
                    "24 mots": p.mnemonic,
                    "important": "Gardez-la hors de cet ordinateur : elle seule permet de retrouver vos fichiers.",
                },
                "j'ai déjà une identité S3m": {
                    "_contenu": "Reprenez-la avec sa phrase de 24 mots au lieu d'en créer une nouvelle.",
                    "_formulaires": [
                        { "nom": "restore", "libellé": "Reprendre cette identité", "champs": ["phrase de récupération"],
                          "types": { "phrase de récupération": "texte" },
                          "aide": { "phrase de récupération": "Vos 24 mots, séparés par des espaces" } },
                    ],
                },
                "nœuds trouvés sur le réseau local": {
                    "_contenu": if s.scanning { json!("recherche en cours…") } else if found.is_empty() { json!("aucun (le Nœud est-il allumé, sur le même réseau, annonce locale active ?)") } else { json!(found) },
                    "_formulaires": [
                        { "nom": "scan", "libellé": "Rechercher à nouveau", "style": "secondary", "champs": [] },
                        { "nom": "manual", "titre": "Nœud absent de la liste : saisir son adresse",
                          "libellé": "Se rattacher", "champs": ["adresse"],
                          "aide": { "adresse": "Pour un Nœud joignable mais non trouvé ci-dessus (autre réseau, annonce locale désactivée) : son adresse /ip4/…/tcp/…/p2p/… figure dans son tableau de bord. S3m lui demande le rattachement automatiquement ; s'il le refuse, transmettez d'abord à son opérateur votre identifiant et votre sel (section ci-dessous)." } },
                    ],
                },
                "si le Nœud n'accepte pas le rattachement automatique, transmettez à son opérateur": {
                    "user_id": p.user_id,
                    "salt": p.salt,
                },
                "accès aux fichiers": {
                    "_contenu": access_summary(&s.access, &dir),
                    "_formulaires": [access_form(&s.access, &dir)],
                },
                "actions": []
            })
        })
    };
    let act_fn: ActionFn = {
        let (state, p, dir) = (state.clone(), prepared, dir.clone());
        Arc::new(move |name, v| {
            let addr = match name {
                "restore" => {
                    let input = v
                        .get("phrase de récupération")
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
                "fs_browse" => return s3m_protocol::local_fs::browse(&v),
                "fs_mkdir" => return s3m_protocol::local_fs::mkdir(&v),
                "set_access" => {
                    state.lock().unwrap().access = parse_access(&v)?;
                    return Ok(json!({ "ok": true, "message": "Accès aux fichiers choisi" }));
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
            let access = state.lock().unwrap().access.clone();
            match write_config(&dir, &p, &addr, &access) {
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
    let url = local_http::serve(0, st_fn, act_fn, ASSETS, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok((url, rx))
}

/// Formulaire « Accès aux fichiers » : Dossier (chemin et espace) ou
/// Périphérique (lettre libre sous Windows, point de montage ailleurs).
pub fn access_form(c: &AccessChoice, dir: &Path) -> Value {
    let mount_field = if cfg!(windows) {
        "lettre"
    } else {
        "point de montage"
    };
    let mut choices = vec![json!([
        "dossier",
        "Dossier synchronisé (comme OneDrive, rien à installer)"
    ])];
    if drive_possible() {
        choices.push(json!([
            "lecteur",
            if cfg!(windows) {
                "Périphérique (lettre de lecteur, WinFsp)"
            } else {
                "Périphérique (point de montage)"
            }
        ]));
    }
    let access = c.access.clone().unwrap_or_else(|| {
        if drive_possible() {
            "lecteur".into()
        } else {
            "dossier".into()
        }
    });
    json!({ "nom": "set_access", "titre": "Accès aux fichiers", "libellé": "Appliquer",
        "champs": ["accès", "dossier", mount_field],
        "types": { "accès": "choix", "dossier": "chemin", mount_field: if cfg!(windows) { "lettre" } else { "chemin" } },
        "options": { "accès": choices, "lettre": s3m_protocol::local_fs::free_letters() },
        "visible_si": { "dossier": ["accès", "dossier"], mount_field: ["accès", "lecteur"] },
        "valeurs": { "accès": access,
                     // Jamais un chemin inexistant : vide tant qu'aucun dossier
                     // existant n'est choisi.
                     "dossier": c.folder.clone().or_else(|| Some(default_folder(dir)))
                         .filter(|f| f.is_dir()).map(|f| f.display().to_string()).unwrap_or_default(),
                     mount_field: c.mount.clone().unwrap_or_else(|| if cfg!(windows) { free_drive_letter() } else { String::new() }) },
        "aide": { "accès": if drive_possible() {
                      "Dossier : vos fichiers dans un dossier synchronisé ; Périphérique : un lecteur à part dans l'Explorateur. Modifiable ensuite dans le tableau de bord."
                  } else {
                      "WinFsp n'est pas installé : seul le dossier synchronisé est possible sur cet ordinateur."
                  },
                  "dossier": "Choisissez avec « Parcourir… » un dossier vide, ou créez-en un (par exemple « S3m » dans votre dossier personnel), sur un disque local (NTFS sous Windows)",
                  "lettre": "Lettre libre, par exemple P:",
                  "point de montage": "Dossier vide où le lecteur sera monté" } })
}

/// Accès retenu, avec seulement l'emplacement qui correspond au type
/// d'accès et à la plateforme (pas de lettre hors de Windows).
pub fn access_summary(c: &AccessChoice, dir: &Path) -> Value {
    let drive = if cfg!(windows) {
        "périphérique (lettre de lecteur)"
    } else {
        "périphérique (point de montage)"
    };
    match (c.access.as_deref(), &c.folder, &c.mount) {
        (Some("dossier"), Some(f), _) => {
            json!({ "accès choisi": "dossier synchronisé (comme OneDrive)", "dossier": f.display().to_string() })
        }
        (Some(_), _, Some(m)) if cfg!(windows) => json!({ "accès choisi": drive, "lettre": m }),
        (Some(_), _, Some(m)) => json!({ "accès choisi": drive, "point de montage": m }),
        _ if cfg!(windows) && drive_possible() => {
            json!({ "accès choisi": format!("automatique : {drive}, WinFsp est installé"), "lettre": free_drive_letter() })
        }
        _ if !cfg!(windows) => json!({ "accès choisi": "à choisir ci-dessous" }),
        _ => {
            json!({ "accès choisi": "automatique : dossier synchronisé (WinFsp n'est pas installé)", "dossier": default_folder(dir).display().to_string() })
        }
    }
}
