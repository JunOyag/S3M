//! Exécutable du Connecteur — id `deploiement.packaging` (partie
//! connector). Réf. spec : docs/07-deploiement/packaging.md.
//!
//! Assemble : identité User depuis la phrase de récupération, session
//! authentifiée auprès du Nœud rattaché, surveillance de sa joignabilité,
//! autorisation de secours (renouvelée et conservée sur disque), état de la
//! file d'écriture, et API locale du dashboard. Le lecteur monté
//! (`protocols.acces-applicatif`) se branche sur ce démon.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::Multiaddr;
use p2p_storage_core::identity_derivation::{derive_identity_seed, mnemonic_to_seed, IdentityRole};
use p2p_storage_protocol::exchange::{
    decode_response, encode_response, open_grant, Refusal, Response, SignedGrant,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::exchange::{BlockClient, ExchangeError, GrantKeeper, NodeSession};
use crate::local_http::{self, ActionFn, Asset, StatusFn};
use crate::write_queue::WriteQueue;

/// `Q_max` par défaut : 4 GiO.
pub const DEFAULT_Q_MAX_BYTES: u64 = 4 << 30;
/// Intervalle de surveillance par défaut : 5 minutes.
pub const DEFAULT_WATCH_INTERVAL_S: u64 = 300;

/// Erreurs de l'exécutable.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("configuration : {0}")]
    Config(String),
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
}

/// Nœud rattaché.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLink {
    /// `/ip4/…/tcp/…/p2p/<PeerId>` du serveur d'échange de blocs.
    pub addr: String,
    /// `pub_node` (hex).
    pub node_id: String,
    /// Sel d'attachement (hex, 16 o).
    pub salt: String,
}

/// Fichier de configuration (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub seed_file: PathBuf,
    #[serde(default)]
    pub identity_index: u32,
    pub data_dir: PathBuf,
    pub node: NodeLink,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_q_max")]
    pub q_max_bytes: u64,
    #[serde(default = "default_watch")]
    pub watch_interval_s: u64,
    /// Lettre ou répertoire du lecteur monté.
    #[serde(default)]
    pub mount_point: Option<String>,
}

fn default_api_port() -> u16 {
    8766
}
fn default_q_max() -> u64 {
    DEFAULT_Q_MAX_BYTES
}
fn default_watch() -> u64 {
    DEFAULT_WATCH_INTERVAL_S
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        let s = std::fs::read_to_string(path)?;
        let mut c: Config =
            serde_json::from_str(&s).map_err(|e| DaemonError::Config(e.to_string()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut c.seed_file, &mut c.data_dir] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        Ok(c)
    }
}

/// `(priv_user, pub_user)` depuis la phrase de récupération.
pub fn user_keys(mnemonic: &str, index: u32) -> Result<([u8; 32], [u8; 32]), DaemonError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    bip39::Mnemonic::parse_normalized(&words)
        .map_err(|e| DaemonError::Config(format!("phrase de récupération : {e}")))?;
    let seed = mnemonic_to_seed(&words, "").map_err(|e| DaemonError::Config(e.to_string()))?;
    let priv_user = derive_identity_seed(&seed, IdentityRole::User, index)
        .map_err(|e| DaemonError::Config(e.to_string()))?;
    let pub_user = ed25519_dalek::SigningKey::from_bytes(&priv_user)
        .verifying_key()
        .to_bytes();
    Ok((priv_user, pub_user))
}

/// Nouvelle phrase de récupération de 24 mots.
pub fn generate_mnemonic() -> Result<String, DaemonError> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| DaemonError::Config(e.to_string()))?;
    Ok(bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| DaemonError::Config(e.to_string()))?
        .to_string())
}

/// 32 o aléatoires.
pub fn random32() -> Result<[u8; 32], DaemonError> {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).map_err(|e| DaemonError::Config(e.to_string()))?;
    Ok(k)
}

fn unhex(s: &str, len: usize) -> Result<Vec<u8>, DaemonError> {
    let v = hex::decode(s).map_err(|e| DaemonError::Config(e.to_string()))?;
    if v.len() != len {
        return Err(DaemonError::Config(format!("{len} octets attendus : {s}")));
    }
    Ok(v)
}

/// Clé anonyme de l'appareil (`grant_priv`), créée au premier démarrage.
fn device_key(dir: &Path) -> Result<[u8; 32], DaemonError> {
    let p = dir.join("device.key");
    match std::fs::read(&p) {
        Ok(b) => b
            .try_into()
            .map_err(|_| DaemonError::Config("device.key corrompu".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k = random32()?;
            std::fs::write(&p, k)?;
            Ok(k)
        }
        Err(e) => Err(e.into()),
    }
}

/// L'autorisation est conservée sous forme de réponse `GrantIssued`.
fn load_grant(dir: &Path) -> Option<SignedGrant> {
    match decode_response(&std::fs::read(dir.join("grant.bin")).ok()?).ok()? {
        Response::GrantIssued(g) => Some(g),
        _ => None,
    }
}

fn save_grant(dir: &Path, g: &SignedGrant) -> std::io::Result<()> {
    std::fs::write(
        dir.join("grant.bin"),
        encode_response(&Response::GrantIssued(g.clone())),
    )
}

// ------------------------------------------------------------- état

/// Observations de la surveillance.
#[derive(Debug, Clone, Default)]
pub struct Health {
    pub reachable: Option<bool>,
    pub last_contact: Option<u64>,
    /// Début de l'indisponibilité courante du Nœud.
    pub inactivity_detected_at: Option<u64>,
    pub last_error: Option<String>,
    pub incidents: Vec<String>,
}

/// Contexte partagé par le dashboard et la surveillance.
pub struct Shared {
    pub config: Config,
    pub pub_user: [u8; 32],
    pub session: NodeSession,
    pub keeper: tokio::sync::Mutex<GrantKeeper>,
    pub grant_expiry: Mutex<Option<u64>>,
    pub health: Mutex<Health>,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

fn queue_status(c: &Config) -> Value {
    let p = c.data_dir.join("write-queue.bin");
    match std::fs::read(&p) {
        Err(_) => {
            json!({ "mutations en attente": 0, "taille (octets)": 0, "Q_max (octets)": c.q_max_bytes })
        }
        Ok(b) => match WriteQueue::decode(&b, c.q_max_bytes) {
            Ok(q) => json!({
                "mutations en attente": q.mutations.len(),
                "taille (octets)": q.used_bytes(),
                "Q_max (octets)": c.q_max_bytes,
            }),
            Err(e) => json!({ "erreur": e.to_string() }),
        },
    }
}

/// État présenté par le dashboard Connecteur.
pub fn status(sh: &Shared) -> Value {
    let now = (sh.clock)();
    let h = sh.health.lock().unwrap().clone();
    json!({
        "titre": "Connecteur P2P-Storage",
        "nœud rattaché": {
            "node_id": sh.config.node.node_id,
            "adresse": sh.config.node.addr,
            "joignable": h.reachable,
            "dernier contact": h.last_contact,
            "indisponible depuis (s)": h.inactivity_detected_at.map(|t| now.saturating_sub(t)),
            "dernière erreur": h.last_error,
        },
        "utilisateur": { "user_id": hex::encode(sh.pub_user) },
        "autorisation de secours": { "expire le": *sh.grant_expiry.lock().unwrap() },
        "file d'écriture": queue_status(&sh.config),
        "incidents d'intégrité": h.incidents,
        "configuration": {
            "Q_max (octets)": sh.config.q_max_bytes,
            "intervalle de surveillance (s)": sh.config.watch_interval_s,
            "lecteur monté": sh.config.mount_point,
        },
        "non suivi par cet exécutable": ["écriture d'urgence", "espace de travail de l'écriture différée"],
        "actions": [
            { "nom": "sync_now", "libellé": "Synchroniser maintenant", "champs": [] }
        ]
    })
}

/// Un tour de surveillance : joignabilité du Nœud, renouvellement de
/// l'autorisation de secours.
pub async fn watch_once(sh: &Shared) {
    let now = (sh.clock)();
    // Sonde : un hash nul n'existe jamais ; `NotFound` prouve que le Nœud
    // répond et accepte notre identifiant.
    let probe = sh.session.get_block(&[0; 32]).await;
    let ok = matches!(probe, Err(ExchangeError::Refused(Refusal::NotFound)));
    {
        let mut h = sh.health.lock().unwrap();
        h.reachable = Some(ok);
        if ok {
            h.last_contact = Some(now);
            h.inactivity_detected_at = None;
            h.last_error = None;
        } else {
            h.inactivity_detected_at.get_or_insert(now);
            h.last_error = probe.err().map(|e| e.to_string());
        }
    }
    if ok {
        let mut k = sh.keeper.lock().await;
        if k.refresh(&sh.session, now).await.is_ok() {
            if let Some(g) = &k.grant {
                let _ = save_grant(&sh.config.data_dir, g);
                *sh.grant_expiry.lock().unwrap() = open_grant(g, now).ok().map(|g| g.expires_at);
            }
        }
    }
}

fn state_dir(c: &Config) -> Result<(), DaemonError> {
    std::fs::create_dir_all(&c.data_dir)?;
    Ok(())
}

const ASSETS: &[Asset] = &[
    (
        "index.html",
        "text/html; charset=utf-8",
        include_str!("../dashboard/index.html"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_str!("../dashboard/app.js"),
    ),
];

/// Démarre le Connecteur ; rend le contexte et l'URL du dashboard.
pub async fn start(
    config: Config,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Result<(Arc<Shared>, String), DaemonError> {
    state_dir(&config)?;
    let mnemonic = std::fs::read_to_string(&config.seed_file)?;
    let (priv_user, pub_user) = user_keys(&mnemonic, config.identity_index)?;
    let addr: Multiaddr = config
        .node
        .addr
        .parse()
        .map_err(|e| DaemonError::Config(format!("adresse du Nœud : {e}")))?;
    let pub_node: [u8; 32] = unhex(&config.node.node_id, 32)?.try_into().unwrap();
    let salt = unhex(&config.node.salt, 16)?;
    let client = BlockClient::start()?;
    let session = NodeSession::new(client, addr, &priv_user, &pub_user, &pub_node, &salt)?;
    let mut keeper = GrantKeeper::new(device_key(&config.data_dir)?);
    keeper.grant = load_grant(&config.data_dir);
    let expiry = keeper
        .grant
        .as_ref()
        .and_then(|g| open_grant(g, clock()).ok())
        .map(|g| g.expires_at);
    let shared = Arc::new(Shared {
        config: config.clone(),
        pub_user,
        session,
        keeper: tokio::sync::Mutex::new(keeper),
        grant_expiry: Mutex::new(expiry),
        health: Mutex::new(Health::default()),
        clock,
    });
    let st_fn: StatusFn = {
        let sh = shared.clone();
        Arc::new(move || status(&sh))
    };
    let act_fn: ActionFn = {
        let sh = shared.clone();
        Arc::new(move |name, _| match name {
            "sync_now" => {
                let sh = sh.clone();
                tokio::spawn(async move { watch_once(&sh).await });
                Ok(json!({ "ok": true }))
            }
            _ => Err(format!("action inconnue : {name}")),
        })
    };
    let url = local_http::serve(config.api_port, st_fn, act_fn, ASSETS).await?;
    let sh = shared.clone();
    tokio::spawn(async move {
        loop {
            watch_once(&sh).await;
            tokio::time::sleep(Duration::from_secs(sh.config.watch_interval_s.max(1))).await;
        }
    });
    Ok((shared, url))
}
