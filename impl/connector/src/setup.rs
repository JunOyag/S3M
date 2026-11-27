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
    let mnemonic = match s3m_protocol::vault::read(&seed) {
        Ok(m) => m.trim().to_string(),
        Err(_) => {
            let m = generate_mnemonic().map_err(|e| e.to_string())?;
            s3m_protocol::vault::write(&seed, &m).map_err(|e| e.to_string())?;
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
    s3m_protocol::vault::write(&dir.join("user.seed"), &mnemonic).map_err(|e| e.to_string())?;
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
        // Sans choix : dossier synchronisé (Windows), même avec WinFsp.
        access: choice
            .access
            .clone()
            .or_else(|| cfg!(windows).then(|| "dossier".to_string())),
        folder: choice.folder.clone(),
        // DHT et échange de blocs partagent la pile du Nœud.
        dht_bootstrap: vec![m.to_string()],
        auto_attach: true,
        emergency_write: true,
        n_secours: crate::emergency::DEFAULT_N_SECOURS,
        free_after_days: 0,
        always_free: false,
        keep_offline: vec![],
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
    /// Nœud choisi dans la liste (adresse), mis en évidence.
    selected: Option<String>,
    /// Recherche du Nœud de rattachement dans l'annuaire : état affiché.
    lookup: Option<String>,
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

/// Recherche du Nœud de rattachement (`network.bootstrap`) : entrée User de
/// l'annuaire (`wanted = None`), sinon le Nœud saisi ; il est choisi s'il est
/// trouvé, et le sel de l'attachement repris de l'entrée User.
fn lookup(
    state: Arc<Mutex<SetupState>>,
    prepared: Arc<Mutex<Prepared>>,
    dir: PathBuf,
    wanted: Option<crate::find_node::NodeRef>,
) {
    use crate::find_node::*;
    state.lock().unwrap().lookup = Some("recherche dans l'annuaire…".into());
    tokio::spawn(async move {
        // La recherche locale fournit les premiers points d'entrée.
        for _ in 0..20 {
            if !state.lock().unwrap().scanning {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let (lan, lan_ids): (Vec<String>, Vec<[u8; 32]>) = {
            let s = state.lock().unwrap();
            (
                s.found.iter().map(|n| n.addr.clone()).collect(),
                s.found.iter().map(|n| n.node_id).collect(),
            )
        };
        let mnemonic = prepared.lock().unwrap().mnemonic.clone();
        let r: Result<Home, String> = async {
            let c = client(entry_points(&dir, &lan)).await?;
            match &wanted {
                None => {
                    let (priv_user, pub_user) =
                        user_keys(&mnemonic, 0).map_err(|e| e.to_string())?;
                    home_from_user_entry(&c, &priv_user, &pub_user).await
                }
                Some(r) => {
                    let id = match r {
                        NodeRef::Id(id) => *id,
                        NodeRef::Fingerprint(fp) => {
                            let mut ids = lan_ids.clone();
                            ids.extend(known_ids(&c).await);
                            match_fingerprint(fp, &ids).ok_or(
                                "aucun Nœud connu n'a cette empreinte : saisissez son identifiant complet (page Identité de son tableau de bord)",
                            )?
                        }
                    };
                    Ok(Home {
                        node_id: id,
                        addr: node_addr(&c, &id).await?,
                        salt: None,
                        label: s3m_protocol::pseudo::fingerprint(&id[..]),
                    })
                }
            }
        }
        .await;
        let mut s = state.lock().unwrap();
        match r {
            Ok(h) => {
                if let Some(salt) = h.salt.filter(|x| x.len() == 16) {
                    let salt = hex::encode(salt);
                    if std::fs::write(dir.join("attach.salt"), &salt).is_ok() {
                        prepared.lock().unwrap().salt = salt;
                    }
                }
                s.selected = Some(h.addr.to_string());
                s.lookup = Some(format!(
                    "✔ Votre Nœud {} a été trouvé ({}) et choisi : complétez puis « Démarrer sous cette identité ».",
                    h.label, h.addr
                ));
            }
            Err(e) => {
                s.lookup = Some(format!(
                    "{e}. Saisissez l'identité de votre Nœud ci-dessous, ou choisissez-le dans la liste."
                ));
            }
        }
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
                    let chosen = s.selected.as_deref() == Some(n.addr.as_str());
                    let mut row = json!({
                        "numéro": i + 1,
                        "nœud": s3m_protocol::pseudo::display(&[n.name.as_deref()], &n.node_id),
                        "adresse": n.addr,
                        "état": match (chosen, n.accepting_partners) {
                            (true, _) => "✔ choisi",
                            (false, true) => "prêt",
                            (false, false) => "prêt (n'accepte pas de partenaires)",
                        },
                        "_gras": chosen,
                    });
                    if !chosen {
                        row["_actions"] = json!([{ "nom": "choose", "libellé": "Choisir",
                                       "valeurs": { "numéro": (i + 1).to_string() } }]);
                    }
                    row
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
                "retrouver mon nœud": {
                    "_contenu": s.lookup.clone().unwrap_or_else(|| "Après « Reprendre cette identité », votre Nœud est cherché dans l'annuaire. Vous pouvez aussi saisir son identité.".into()),
                    "_formulaires": [
                        { "nom": "find_node", "libellé": "Rechercher ce Nœud", "champs": ["identité du nœud"],
                          "aide": { "identité du nœud": "Identifiant de votre Nœud (64 caractères, page Identité de son tableau de bord, ou son PeerId 12D3Koo…), ou son empreinte" } },
                    ],
                },
                "nœuds trouvés sur le réseau local": {
                    "_contenu": if s.scanning { json!("recherche en cours…") } else if found.is_empty() { json!("aucun (le Nœud est-il allumé, sur le même réseau, annonce locale active ?)") } else { json!(found) },
                    "_formulaires": [
                        { "nom": "scan", "libellé": "Rechercher à nouveau", "style": "secondary", "champs": [] },
                    ],
                },
                "si le Nœud n'accepte pas le rattachement automatique, transmettez à son opérateur": {
                    "user_id": p.user_id,
                    "salt": p.salt,
                },
                "démarrer": {
                    "_contenu": { "nœud choisi": s.selected.clone().unwrap_or_else(|| "aucun : choisissez-en un dans la liste ou saisissez son adresse ci-dessous".into()) },
                    "_formulaires": [start_form(&s.access, &dir)],
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
                    lookup(state.clone(), p.clone(), dir.clone(), None);
                    return Ok(
                        json!({ "ok": true, "message": "Identité reprise : recherche de votre Nœud dans l'annuaire…" }),
                    );
                }
                "find_node" => {
                    let input = v
                        .get("identité du nœud")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default();
                    let r = crate::find_node::parse_node_ref(input)?;
                    lookup(state.clone(), p.clone(), dir.clone(), Some(r));
                    return Ok(json!({ "ok": true, "message": "Recherche du Nœud…" }));
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
                // Tout ce qui est saisi : adresse (sinon le Nœud choisi) et accès.
                "start" => {
                    let access = parse_access(&v)?;
                    let typed = v
                        .get("adresse du nœud")
                        .and_then(|x| x.as_str())
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(str::to_string);
                    let mut s = state.lock().unwrap();
                    s.access = access;
                    typed
                        .or_else(|| s.selected.clone())
                        .ok_or("choisissez un Nœud dans la liste ou saisissez son adresse")?
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
                    let mut s = state.lock().unwrap();
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
                    // Choisir ne fait que mettre le Nœud en évidence.
                    s.selected = Some(f.addr.clone());
                    return Ok(
                        json!({ "ok": true, "message": "Nœud choisi : complétez puis « Démarrer sous cette identité »" }),
                    );
                }
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
    let mut choices = vec![json!(["dossier", "Dossier synchronisé"])];
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
    // Par défaut : dossier synchronisé, même si WinFsp est installé.
    let access = c.access.clone().unwrap_or_else(|| "dossier".into());
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
                      "Dossier synchronisé : vos fichiers dans un dossier de l'Explorateur, comme OneDrive ou Google Drive ; ils ne sont téléchargés qu'à l'ouverture, rien à installer. Périphérique : un lecteur à part dans l'Explorateur. Modifiable ensuite dans le tableau de bord."
                  } else {
                      "WinFsp n'est pas installé : seul le dossier synchronisé (fichiers dans un dossier de l'Explorateur, comme OneDrive ou Google Drive) est possible sur cet ordinateur."
                  },
                  "dossier": "Choisissez avec « Parcourir… » un dossier vide, ou créez-en un (par exemple « S3m » dans votre dossier personnel), sur un disque local (NTFS sous Windows)",
                  "lettre": "Lettre libre, par exemple P:",
                  "point de montage": "Dossier vide où le lecteur sera monté" } })
}

/// Formulaire final du premier lancement : adresse saisie (facultative si
/// un Nœud est choisi dans la liste) et accès aux fichiers, pris en compte
/// d'un seul clic.
pub fn start_form(c: &AccessChoice, dir: &Path) -> Value {
    let mut f = access_form(c, dir);
    f["nom"] = json!("start");
    f["titre"] = json!("Démarrer");
    f["libellé"] = json!("Démarrer sous cette identité");
    let mut champs = vec![json!("adresse du nœud")];
    champs.extend(f["champs"].as_array().cloned().unwrap_or_default());
    f["champs"] = json!(champs);
    f["aide"]["adresse du nœud"] = json!("Vide : le Nœud choisi dans la liste. Pour un Nœud joignable mais absent de la liste (autre réseau, annonce locale désactivée) : son adresse /ip4/…/tcp/…/p2p/…, dans son tableau de bord. S3m lui demande le rattachement automatiquement ; s'il le refuse, transmettez d'abord à son opérateur votre identifiant et votre sel (section ci-dessus).");
    f
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
            json!({ "accès choisi": "dossier synchronisé", "dossier": f.display().to_string() })
        }
        (Some(_), _, Some(m)) if cfg!(windows) => json!({ "accès choisi": drive, "lettre": m }),
        (Some(_), _, Some(m)) => json!({ "accès choisi": drive, "point de montage": m }),
        _ if !cfg!(windows) => json!({ "accès choisi": "à choisir ci-dessous" }),
        _ => {
            json!({ "accès choisi": "par défaut : dossier synchronisé", "dossier": default_folder(dir).display().to_string() })
        }
    }
}
