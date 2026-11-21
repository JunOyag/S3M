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
use s3m_core::identity_derivation::{
    derive_identity_seed, derive_master_key, mnemonic_to_seed, IdentityRole,
};
use s3m_protocol::exchange::{
    decode_response, encode_response, open_grant, Refusal, Response, SignedGrant,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::access::Root;
use crate::dht_directory::{chiavdf_verifier, DhtClient, DhtClientConfig};
use crate::drive::{BlockIo, Drive, DriveError, KEY_VERSION};
use crate::exchange::{BlockClient, ExchangeError, GrantKeeper, NodeSession};
use crate::fs::BlockHash;
use crate::local_http::{self, ActionFn, Asset, StatusFn};
use crate::publish::{ensure_user_proof, publish_if_changed, read_user_entry, UserEntryState};
use crate::write_back::{Scheduler, WriteBackConfig};
use crate::write_queue::WriteQueue;
use s3m_protocol::entries::{Attachment, UserPlain};

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
    /// Nœuds d'amorçage DHT (`/ip4/…/tcp/…/p2p/<PeerId>`, adresse « DHT »
    /// du dashboard Nœud). Vide : pas de publication de l'entrée User.
    #[serde(default)]
    pub dht_bootstrap: Vec<String>,
    /// Demander soi-même le rattachement au Nœud s'il refuse l'identifiant
    /// (`protocols.partenariat-automatique`).
    #[serde(default = "default_true")]
    pub auto_attach: bool,
    /// Écriture d'urgence chez des partenaires de secours quand seul le
    /// Nœud est injoignable (`protocols.espace-secours`).
    #[serde(default = "default_true")]
    pub emergency_write: bool,
    /// `n_secours` : partenaires de secours distincts.
    #[serde(default = "default_n_secours")]
    pub n_secours: usize,
    /// Fichier d'où la configuration a été lue (modifications depuis le
    /// dashboard).
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

/// Lettre de lecteur saisie (`P`, `p:`, `P:\`) → `P:` ; `A:` à `Z:` sauf
/// `C:`.
pub fn parse_drive_letter(s: &str) -> Result<String, String> {
    let t = s.trim().trim_end_matches(['\\', '/']).trim_end_matches(':');
    let mut it = t.chars();
    match (it.next(), it.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() => {
            let c = c.to_ascii_uppercase();
            if c == 'C' {
                return Err("C: est le disque système".into());
            }
            Ok(format!("{c}:"))
        }
        _ => Err("lettre attendue, par exemple « S » ou « S: »".into()),
    }
}

/// Lettres libres, de D: à Z: (aide du dashboard).
fn free_letters() -> Vec<String> {
    ('D'..='Z')
        .map(|c| format!("{c}:"))
        .filter(|l| !Path::new(&format!("{l}\\")).exists())
        .collect()
}

/// Change la lettre du lecteur : démontage, montage sur la nouvelle lettre
/// (retour à l'ancienne en cas d'échec), puis enregistrement dans le
/// fichier de configuration. Les modifications en attente sont conservées.
fn set_mount_point(sh: &Shared, v: &Value) -> Result<Value, String> {
    let raw = v
        .get("lettre du lecteur")
        .and_then(|x| x.as_str())
        .ok_or("champ « lettre du lecteur » manquant")?;
    let letter = parse_drive_letter(raw)?;
    if sh.mount_point().as_deref() == Some(letter.as_str()) {
        return Ok(json!({ "ok": true, "message": format!("Le lecteur est déjà {letter}") }));
    }
    if Path::new(&format!("{letter}\\")).exists() {
        return Err(format!("{letter} est déjà utilisé sur ce PC"));
    }
    let path = sh
        .config
        .source
        .clone()
        .ok_or("fichier de configuration inconnu")?;
    let remount = sh.remount.lock().unwrap().clone();
    let live = match remount {
        Some(tx) => {
            let (rtx, rrx) = std::sync::mpsc::channel();
            tx.send((letter.clone(), rtx))
                .map_err(|_| "lecteur indisponible")?;
            rrx.recv_timeout(Duration::from_secs(30))
                .map_err(|_| "le remontage du lecteur ne répond pas")??;
            true
        }
        None => false,
    };
    *sh.mount_point.lock().unwrap() = Some(letter.clone());
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut raw: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    raw["mount_point"] = json!(letter);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(&raw).expect("sérialisable"),
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true, "message": if live {
        format!("Lecteur déplacé sur {letter}")
    } else {
        format!("Lettre {letter} enregistrée : prise en compte au prochain démarrage")
    } }))
}

fn default_n_secours() -> usize {
    crate::emergency::DEFAULT_N_SECOURS
}

/// Délai d'injoignabilité du Nœud avant un dépôt d'urgence (5 minutes).
pub const EMERGENCY_DELAY_S: u64 = 300;

/// Suivi de l'écriture d'urgence, conservé sur disque (`emergency.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmergencyStatus {
    /// Blocs déposés à libérer : `(node_id hex, adresse, hashes hex)`.
    #[serde(default)]
    pub deposits: Vec<(String, String, Vec<String>)>,
    pub last_deposit_at: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_error: Option<String>,
    pub published_seq: Option<u64>,
    #[serde(default)]
    pub released_blocks: u64,
    pub reconciled_at: Option<u64>,
    /// Dernier horodatage de libération utilisé.
    #[serde(default)]
    pub last_release_ts: u64,
}

fn emergency_path(c: &Config) -> PathBuf {
    c.data_dir.join("emergency.json")
}

fn load_emergency(c: &Config) -> EmergencyStatus {
    std::fs::read(emergency_path(c))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_emergency(sh: &Shared) {
    let st = sh.emergency.lock().unwrap().clone();
    let p = emergency_path(&sh.config);
    let tmp = p.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(&st).expect("sérialisable")).is_ok() {
        let _ = std::fs::rename(tmp, p);
    }
}

fn channel_path(c: &Config) -> PathBuf {
    c.data_dir.join("channel.json")
}

fn load_channel(c: &Config) -> crate::channel::ChannelState {
    std::fs::read(channel_path(c))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_channel(sh: &Shared) {
    let st = sh.channel.lock().unwrap().clone();
    let p = channel_path(&sh.config);
    let tmp = p.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(&st).expect("sérialisable")).is_ok() {
        let _ = std::fs::rename(tmp, p);
    }
}

fn default_true() -> bool {
    true
}

/// État du rattachement automatique.
#[derive(Debug, Clone, Default)]
pub struct AttachState {
    pub in_progress: bool,
    pub attached_quota: Option<u64>,
    pub last_error: Option<String>,
    pub last_attempt: u64,
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
        c.source = Some(path.to_path_buf());
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

/// `master_key[version]` de l'Utilisateur (`crypto.master-key-chain`).
pub fn master_key(mnemonic: &str, version: u16) -> Result<[u8; 32], DaemonError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    let seed = mnemonic_to_seed(&words, "").map_err(|e| DaemonError::Config(e.to_string()))?;
    derive_master_key(&seed, version).map_err(|e| DaemonError::Config(e.to_string()))
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

/// `BlockIo` du lecteur sur la session réseau (appels bloquants).
pub struct NodeIo {
    pub session: NodeSession,
    pub runtime: tokio::runtime::Handle,
}

impl NodeIo {
    fn wait<F: std::future::Future>(&self, f: F) -> F::Output {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| self.runtime.block_on(f))
        } else {
            self.runtime.block_on(f)
        }
    }
}

impl BlockIo for NodeIo {
    fn get(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        self.wait(self.session.get_block(hash)).ok()
    }

    fn put(&self, hash: &BlockHash, frame: Vec<u8>) -> Result<(), String> {
        match self.wait(self.session.put_block(frame)) {
            Ok(h) if h == hash.to_vec() => Ok(()),
            Ok(_) => Err("hash refusé par le Nœud".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn commit(&self, base: &BlockHash, new: &BlockHash) -> Result<Option<BlockHash>, String> {
        let (ok, current) = self
            .wait(self.session.commit_root(base, new))
            .map_err(|e| e.to_string())?;
        if ok {
            Ok(None)
        } else {
            Ok(Some(current.try_into().unwrap_or([0; 32])))
        }
    }
}

/// État du lecteur monté.
#[derive(Debug, Clone, Default)]
pub struct DriveStatus {
    pub mounted: bool,
    pub mount_error: Option<String>,
    pub last_sync: Option<u64>,
    pub last_sync_error: Option<String>,
}

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

/// Demande de remontage du lecteur : `(lettre, réponse)`.
pub type RemountTx = std::sync::mpsc::Sender<(String, std::sync::mpsc::Sender<Result<(), String>>)>;

/// Contexte partagé par le dashboard et la surveillance.
pub struct Shared {
    pub config: Config,
    /// Dernière recherche du Nœud sur le réseau local (adresse changée).
    pub last_lan_search: Mutex<Option<u64>>,
    /// « Changer de Nœud » demandé (l'application redémarre sur l'assistant).
    pub change_node: std::sync::atomic::AtomicBool,
    /// Lettre courante du lecteur.
    pub mount_point: Mutex<Option<String>>,
    /// Remontage du lecteur sur une autre lettre : `(lettre, réponse)`.
    pub remount: Mutex<Option<RemountTx>>,
    pub pub_user: [u8; 32],
    pub session: NodeSession,
    pub keeper: tokio::sync::Mutex<GrantKeeper>,
    pub grant_expiry: Mutex<Option<u64>>,
    pub health: Mutex<Health>,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub drive: Option<Arc<Mutex<Drive>>>,
    pub scheduler: Arc<Mutex<Scheduler>>,
    pub drive_status: Mutex<DriveStatus>,
    /// Synchronisation suspendue (menu de la barre des tâches) : les
    /// modifications restent journalisées localement.
    pub paused: std::sync::atomic::AtomicBool,
    /// Synchronisation en cours.
    pub syncing: std::sync::atomic::AtomicBool,
    pub user_entry: Mutex<UserEntryState>,
    pub attach: Mutex<AttachState>,
    /// Client DHT (si `dht_bootstrap`), pour relire l'entrée du Nœud.
    pub dht: std::sync::OnceLock<DhtClient>,
    /// Écriture d'urgence (`protocols.espace-secours`).
    pub emergency: Mutex<EmergencyStatus>,
    /// Canal Nœud ↔ Utilisateurs (`protocols.canal-noeud`).
    pub channel: Mutex<crate::channel::ChannelState>,
    priv_user: [u8; 32],
    pub_node: [u8; 32],
    salt: Vec<u8>,
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
    let mut v = status_base(sh);
    channel_status(sh, &mut v);
    v["résumé"] = connector_summary(&v);
    v["pages"] = json!([
        { "id": "accueil", "titre": "Vue d'ensemble", "résumé": true, "sections": [], "actions": ["sync_now"] },
        { "id": "fichiers", "titre": "Fichiers et synchronisation",
          "sections": ["lecteur", "file d'écriture"], "actions": ["sync_now", "set_mount_point"] },
        { "id": "noeud", "titre": "Mon Nœud",
          "sections": ["nœud rattaché", "espace", "rattachement automatique"], "actions": ["admin_node", "change_node"] },
        { "id": "messages", "titre": "Messages du Nœud",
          "sections": ["alerte du nœud", "messages du nœud", "messages envoyés au nœud"],
          "actions": ["send_node_message", "acknowledge_alert"] },
        { "id": "urgence", "titre": "Écriture d'urgence",
          "sections": ["écriture d'urgence"], "actions": [] },
        { "id": "securite", "titre": "Identité et sécurité",
          "sections": ["utilisateur", "annuaire (entrée User)", "autorisation de secours", "incidents d'intégrité"], "actions": [] },
        { "id": "parametres", "titre": "Paramètres", "autres": true,
          "sections": ["configuration"], "actions": [] }
    ]);
    v
}

/// Indicateurs de la vue d'ensemble (`état` : ok, attention, probleme, neutre).
fn connector_summary(v: &Value) -> Value {
    let p = |path: &str| v.pointer(path).cloned().unwrap_or(Value::Null);
    let (node, node_state) = match p("/nœud rattaché/joignable") {
        Value::Bool(true) => ("joignable", "ok"),
        Value::Bool(false) => ("injoignable", "probleme"),
        _ => ("vérification…", "neutre"),
    };
    let pending = p("/lecteur/modifications en attente").as_u64().unwrap_or(0);
    let (sync, sync_state) = if !p("/lecteur/erreur de synchronisation").is_null() {
        ("erreur".to_string(), "probleme")
    } else if p("/lecteur/conflit (racine du Nœud)").as_bool() == Some(true) {
        ("conflit".to_string(), "probleme")
    } else if pending > 0 {
        (format!("{pending} en attente"), "attention")
    } else {
        ("à jour".to_string(), "ok")
    };
    let mount = p("/lecteur/point de montage");
    let (drive, drive_state) = if p("/lecteur/monté").as_bool() == Some(true) {
        (format!("{} monté", mount.as_str().unwrap_or("")), "ok")
    } else if !p("/lecteur/erreur de montage").is_null() {
        ("erreur de montage".to_string(), "probleme")
    } else {
        ("non monté".to_string(), "neutre")
    };
    let queue = p("/file d'écriture/mutations en attente")
        .as_u64()
        .unwrap_or(0);
    let (space, space_state) = match (
        p("/espace/libre (octets)").as_u64(),
        p("/espace/% utilisé").as_f64(),
    ) {
        (Some(free), Some(pct)) => (
            format!("{} libres ({pct} % utilisé)", gib_text(free)),
            if pct >= 95.0 {
                "probleme"
            } else if pct >= 85.0 {
                "attention"
            } else {
                "ok"
            },
        ),
        _ => ("inconnu".to_string(), "neutre"),
    };
    let deposits = p("/écriture d'urgence/blocs déposés à libérer")
        .as_u64()
        .unwrap_or(0);
    let alert = p("/alerte du nœud/message");
    let unread = p("/alerte du nœud/acquittée").as_bool() == Some(false);
    let mut cards = vec![];
    if let Some(t) = alert.as_str() {
        cards.push(json!({ "libellé": "Alerte du Nœud", "valeur": t,
            "détail": "Votre Nœud signale une compromission : ouvrez « Messages du Nœud »",
            "état": if unread { "probleme" } else { "attention" }, "page": "messages" }));
    }
    let base = json!([
        { "libellé": "Espace", "valeur": space, "état": space_state, "page": "noeud" },
        { "libellé": "Écriture d'urgence",
          "valeur": if deposits > 0 { format!("{deposits} bloc(s) chez les partenaires") } else { "aucun dépôt".to_string() },
          "état": if deposits > 0 { "attention" } else { "ok" }, "page": "urgence" },
        { "libellé": "Mon Nœud", "valeur": node, "état": node_state, "page": "noeud" },
        { "libellé": "Synchronisation", "valeur": sync, "état": sync_state, "page": "fichiers" },
        { "libellé": "Lecteur", "valeur": drive, "état": drive_state, "page": "fichiers" },
        { "libellé": "File d'écriture", "valeur": queue, "détail": "modifications hors ligne",
          "état": if queue == 0 { "ok" } else { "attention" }, "page": "fichiers" }
    ]);
    cards.extend(base.as_array().cloned().unwrap_or_default());
    Value::Array(cards)
}

/// Canal Nœud ↔ Utilisateurs : sections du dashboard.
fn channel_status(sh: &Shared, v: &mut Value) {
    let c = sh.channel.lock().unwrap();
    v["alerte du nœud"] = match &c.alert {
        None => json!({ "état": "aucune alerte" }),
        Some(a) => json!({
            "message": a.text, "émise le": a.timestamp, "acquittée": c.alert_acknowledged,
            "nœud de remplacement": a.successor.map(hex::encode),
            "conduite à tenir": if a.successor.is_some() {
                "Votre Nœud est compromis. Utilisez « Changer de Nœud » (page Mon Nœud) avec l'identifiant du Nœud de remplacement."
            } else {
                "Votre Nœud est compromis. Choisissez un autre Nœud avec « Changer de Nœud » (page Mon Nœud)."
            },
            "pointeur de migration": "ignoré (l'alerte l'emporte)",
        }),
    };
    v["messages du nœud"] = json!(c.received.iter().rev().map(|m| json!({
        "sorte": if m.kind == s3m_protocol::message::Kind::Alert { "alerte" } else { "information" },
        "reçu le": m.timestamp, "message": m.text })).collect::<Vec<_>>());
    v["messages envoyés au nœud"] = json!(c
        .sent
        .iter()
        .rev()
        .map(|(t, m)| json!({
        "envoyé le": t, "message": m }))
        .collect::<Vec<_>>());
    v["clé d'annonce du nœud"] = json!(c.announce.map(hex::encode));
    if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
        a.push(json!({ "nom": "send_node_message", "titre": "Écrire à mon Nœud", "libellé": "Envoyer",
            "champs": ["message"],
            "aide": { "message": "Lu par l'opérateur de votre Nœud (4 096 octets au plus, 10 messages par jour) ; chaque message occupe 4 Kio de votre quota pendant 30 jours" } }));
        if c.alert.is_some() && !c.alert_acknowledged {
            a.push(json!({ "nom": "acknowledge_alert", "titre": "Alerte du Nœud", "libellé": "J'ai lu l'alerte", "champs": [] }));
        }
    }
}

/// Un tour du canal : épinglage de la clé d'annonce, lecture des messages
/// (Nœud joignable), alerte relue dans l'annuaire (Nœud injoignable, ou une
/// fois par jour) et republiée telle quelle.
async fn channel_tick(sh: &Shared, now: u64, reachable: bool) {
    use s3m_protocol::message::{alert_key, open_alert_entry, ALERT_POLL_S};
    let before = sh.channel.lock().unwrap().clone();
    sh.channel.lock().unwrap().pin(&sh.pub_node, None);
    let poll_due = {
        let c = sh.channel.lock().unwrap();
        !reachable || now >= c.alert_polled_at.saturating_add(ALERT_POLL_S)
    };
    let dht = sh.dht.get();
    if let (true, Some(client)) = (poll_due, dht) {
        if sh.channel.lock().unwrap().announce.is_none() {
            if let Ok(Some(env)) = client.get(sh.pub_node.to_vec()).await {
                let ann = s3m_protocol::entries::node_entry_announce(&env);
                sh.channel.lock().unwrap().pin(&sh.pub_node, ann);
            }
        }
        let announce = sh.channel.lock().unwrap().announce;
        if let Some(announce) = announce {
            if let Ok(Some(env)) = client.get(alert_key(&announce).to_vec()).await {
                if let Ok((k, alert)) = open_alert_entry(&env, now) {
                    sh.channel.lock().unwrap().accept_entry(&k, &alert, env);
                }
            }
        }
        sh.channel.lock().unwrap().alert_polled_at = now;
    }
    if reachable {
        let cur = sh.channel.lock().unwrap().cursor;
        if let Ok(list) = sh.session.read_messages(cur.info, cur.alert).await {
            let mut c = sh.channel.lock().unwrap();
            for s in &list {
                c.accept(s);
            }
        }
    }
    let republish = sh.channel.lock().unwrap().republish_due(now);
    let announce = sh.channel.lock().unwrap().announce;
    if let (Some(env), Some(announce), Some(client)) = (republish, announce, dht) {
        if client.put(alert_key(&announce).to_vec(), env).await.is_ok() {
            sh.channel.lock().unwrap().alert_republished_at = now;
        }
    }
    if *sh.channel.lock().unwrap() != before {
        save_channel(sh);
    }
}

/// Actions du canal (fil bloquant du serveur du dashboard).
fn channel_action(sh: &Shared, name: &str, v: &Value) -> Result<Value, String> {
    match name {
        "send_node_message" => {
            let text = v
                .get("message")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .ok_or("message vide")?;
            tokio::runtime::Handle::current()
                .block_on(sh.session.post_message(text))
                .map_err(|e| match e {
                    ExchangeError::Refused(Refusal::RateLimited) => {
                        "10 messages par jour au plus : réessayez demain".to_string()
                    }
                    ExchangeError::Refused(Refusal::QuotaExceeded) => {
                        "quota plein : libérez de l'espace pour écrire à votre Nœud (chaque message occupe 4 Kio pendant 30 jours)".to_string()
                    }
                    e => format!("envoi impossible : {e}"),
                })?;
            sh.channel
                .lock()
                .unwrap()
                .sent
                .push(((sh.clock)(), text.to_string()));
            save_channel(sh);
            Ok(json!({ "ok": true, "message": "Message envoyé à votre Nœud" }))
        }
        _ => {
            sh.channel.lock().unwrap().alert_acknowledged = true;
            save_channel(sh);
            Ok(json!({ "ok": true, "message": "Alerte acquittée" }))
        }
    }
}

fn status_base(sh: &Shared) -> Value {
    let now = (sh.clock)();
    let h = sh.health.lock().unwrap().clone();
    json!({
        "titre": "Connecteur S3m",
        "nœud rattaché": {
            "node_id": sh.config.node.node_id,
            "adresse configurée": sh.config.node.addr,
            "adresse utilisée": sh.session.node_addr().to_string(),
            "joignable": h.reachable,
            "dernier contact": h.last_contact,
            "indisponible depuis (s)": h.inactivity_detected_at.map(|t| now.saturating_sub(t)),
            "dernière erreur": h.last_error,
        },
        "utilisateur": { "user_id": hex::encode(sh.pub_user) },
        "autorisation de secours": { "expire le": *sh.grant_expiry.lock().unwrap() },
        "file d'écriture": queue_status(&sh.config),
        "incidents d'intégrité": h.incidents,
        "lecteur": drive_status(sh),
        "espace": space_status(sh),
        "annuaire (entrée User)": user_entry_status(sh),
        "rattachement automatique": attach_status(sh),
        "configuration": {
            "Q_max (octets)": sh.config.q_max_bytes,
            "intervalle de surveillance (s)": sh.config.watch_interval_s,
            "lecteur monté": sh.mount_point(),
        },
        "écriture d'urgence": emergency_status(sh, now),
        "actions": [
            { "nom": "sync_now", "libellé": "Synchroniser maintenant", "champs": [] },
            { "nom": "set_mount_point", "titre": "Lettre du lecteur", "libellé": "Changer",
              "champs": ["lettre du lecteur"],
              "valeurs": { "lettre du lecteur": sh.mount_point() },
              "aide": { "lettre du lecteur": format!("Lettres libres : {}. S3m redémarre ; les modifications en attente sont conservées.", free_letters().join(", ")) } },
            { "nom": "admin_node", "titre": "Administrer mon Nœud à distance",
              "libellé": "Ouvrir son tableau de bord", "champs": ["code 2FA", "adresse d'administration"],
              "aide": { "code 2FA": "Code à 6 chiffres de votre application d'authentification",
                        "adresse d'administration": "Facultatif : par défaut, IP du Nœud et port 4003" } },
            { "nom": "change_node", "titre": "Changer de Nœud",
              "libellé": "Changer de Nœud", "champs": ["je confirme"], "types": { "je confirme": "bool" },
              "aide": { "je confirme": "S3m redémarre sur l'assistant (votre identité est conservée). L'ancienne configuration et les données locales sont mises de côté, pas effacées." } }
        ]
    })
}

fn gib_text(b: u64) -> String {
    let g = b as f64 / (1u64 << 30) as f64;
    if g >= 10.0 {
        format!("{g:.0} Gio")
    } else {
        format!("{g:.1} Gio")
    }
}

/// Espace de l'Utilisateur chez son Nœud (`RootState`).
fn space_status(sh: &Shared) -> Value {
    match sh.session.space() {
        None => json!("non communiqué par le Nœud"),
        Some((quota, used)) => {
            let pct = (used as f64 * 1000.0 / quota.max(1) as f64).round() / 10.0;
            json!({
                "libre (octets)": quota.saturating_sub(used),
                "total (octets)": quota,
                "utilisé (octets)": used,
                "% utilisé": pct,
            })
        }
    }
}

/// Écriture d'urgence vue du dashboard.
fn emergency_status(sh: &Shared, now: u64) -> Value {
    if !sh.config.emergency_write {
        return json!("désactivée");
    }
    let e = sh.emergency.lock().unwrap().clone();
    let h = sh.health.lock().unwrap().clone();
    let (pending, deposited) = match &sh.drive {
        Some(d) => {
            let d = d.lock().unwrap();
            (d.pending(), d.emergency_current())
        }
        None => (0, false),
    };
    let blocks: usize = e.deposits.iter().map(|(_, _, h)| h.len()).sum();
    let etat = if deposited {
        "modifications déposées chez les partenaires de secours".to_string()
    } else if h.reachable == Some(false) && pending > 0 {
        let since = now.saturating_sub(h.inactivity_detected_at.unwrap_or(now));
        if since < EMERGENCY_DELAY_S {
            format!(
                "Nœud injoignable : dépôt dans {} s",
                EMERGENCY_DELAY_S - since
            )
        } else {
            "Nœud injoignable : dépôt en cours ou en échec".to_string()
        }
    } else if blocks > 0 {
        "Nœud revenu : libération des partenaires en cours".to_string()
    } else {
        "inactive (Nœud joignable)".to_string()
    };
    let partners: Vec<Value> = e
        .deposits
        .iter()
        .map(|(n, a, h)| json!({ "partenaire": n, "adresse": a, "blocs": h.len() }))
        .collect();
    json!({
        "état": etat,
        "partenaires de secours (n_secours)": sh.config.n_secours,
        "Q_max (octets)": sh.config.q_max_bytes,
        "dernier dépôt": e.last_deposit_at,
        "dernière tentative": e.last_attempt,
        "séquence publiée": e.published_seq,
        "blocs déposés à libérer": blocks,
        "partenaires": partners,
        "blocs libérés": e.released_blocks,
        "dernière réconciliation": e.reconciled_at,
        "erreur": e.last_error,
    })
}

fn drive_status(sh: &Shared) -> Value {
    let st = sh.drive_status.lock().unwrap().clone();
    let (pending, conflict) = match &sh.drive {
        Some(d) => {
            let d = d.lock().unwrap();
            (Some(d.pending()), d.conflict.map(hex::encode))
        }
        None => (None, None),
    };
    json!({
        "point de montage": sh.mount_point(),
        "monté": st.mounted,
        "erreur de montage": st.mount_error,
        "modifications en attente": pending,
        "synchronisations planifiées": sh.scheduler.lock().unwrap().pending_count(),
        "dernière synchronisation": st.last_sync,
        "erreur de synchronisation": st.last_sync_error,
        "conflit (racine du Nœud)": conflict,
    })
}

fn user_entry_status(sh: &Shared) -> Value {
    if sh.config.dht_bootstrap.is_empty() {
        return json!("désactivé (dht_bootstrap vide)");
    }
    let s = sh.user_entry.lock().unwrap().clone();
    json!({
        "connecté à la DHT": s.dht_connected,
        "preuve VDF": if s.proof_ready { json!("prête") } else {
            json!(s.proof_error.clone().unwrap_or_else(|| "calcul en cours (≈ 1 min)".into())) },
        "racine publiée": s.published_root.map(hex::encode),
        "publiée le": s.published_at,
        "racine restaurée depuis la DHT": s.restored_from_dht,
        "erreur": s.last_error,
    })
}

/// Date du premier rattachement, conservée sur disque.
fn attached_at(dir: &Path, now: u64) -> u64 {
    let p = dir.join("attached_at");
    if let Some(t) = std::fs::read_to_string(&p)
        .ok()
        .and_then(|s| s.trim().parse().ok())
    {
        return t;
    }
    let _ = std::fs::write(&p, now.to_string());
    now
}

/// Entrée DHT User : restauration de la racine, preuve VDF, publication à
/// chaque nouvelle racine.
fn spawn_user_entry(sh: Arc<Shared>, priv_user: [u8; 32], pub_node: [u8; 32], salt: Vec<u8>) {
    tokio::spawn(async move {
        let bootstrap: Vec<Multiaddr> = sh
            .config
            .dht_bootstrap
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect();
        let client = match DhtClient::start(DhtClientConfig {
            bootstrap,
            vdf: chiavdf_verifier(),
            clock: sh.clock.clone(),
        })
        .await
        {
            Ok(c) => c,
            Err(e) => {
                sh.user_entry.lock().unwrap().last_error = Some(e.to_string());
                return;
            }
        };
        sh.user_entry.lock().unwrap().dht_connected = true;
        let _ = sh.dht.set(client.clone());
        // Nouvel appareil : racine relue dans l'entrée User publiée.
        if let Some(plain) = read_user_entry(&client, &priv_user, &sh.pub_user).await {
            if let Some(d) = &sh.drive {
                let adopted = d.lock().unwrap().adopt_root(Root {
                    fs_root_hash: plain.fs_root_hash,
                    encryption_salt: plain.encryption_salt,
                    key_version: plain.key_version,
                });
                if adopted.unwrap_or(false) {
                    sh.user_entry.lock().unwrap().restored_from_dht = true;
                }
            }
        }
        let cache = sh.config.data_dir.join("vdf_proof.bin");
        let proof = match ensure_user_proof(&cache, &priv_user, &sh.pub_user).await {
            Ok(p) => p,
            Err(e) => {
                sh.user_entry.lock().unwrap().proof_error = Some(e);
                return;
            }
        };
        sh.user_entry.lock().unwrap().proof_ready = true;
        let since = attached_at(&sh.config.data_dir, (sh.clock)());
        loop {
            let root = sh.drive.as_ref().map(|d| d.lock().unwrap().root());
            let (fs_root_hash, encryption_salt, key_version) = match root {
                Some(r) => (r.fs_root_hash, r.encryption_salt, r.key_version),
                None => ([0; 32], [0; 16], KEY_VERSION),
            };
            let inactivity = sh
                .health
                .lock()
                .unwrap()
                .inactivity_detected_at
                .unwrap_or(0);
            let plain = UserPlain {
                fs_root_hash,
                encryption_salt,
                key_version,
                attachments: vec![Attachment {
                    node_id: pub_node,
                    salt: salt.clone(),
                    timestamp: since,
                    inactivity_detected_at: inactivity,
                }],
            };
            publish_if_changed(
                &client,
                &priv_user,
                &sh.pub_user,
                &proof,
                &plain,
                &sh.user_entry,
                (sh.clock)(),
            )
            .await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

/// Surveillance puis synchronisation immédiates (menu, dashboard), même si
/// la synchronisation automatique est suspendue.
pub fn sync_now(sh: &Arc<Shared>) {
    let sh = sh.clone();
    sh.scheduler.lock().unwrap().sync_now();
    tokio::spawn(async move {
        watch_once(&sh).await;
        let s2 = sh.clone();
        let _ = tokio::task::spawn_blocking(move || sync_drive(&s2)).await;
    });
}

/// État résumé pour l'icône de la barre des tâches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Starting,
    Ok,
    Syncing,
    Paused,
    Offline,
    Error,
}

/// Vue de l'état pour l'icône, l'infobulle et les notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayView {
    pub state: TrayState,
    pub text: String,
    pub pending: usize,
    pub conflict: bool,
    pub sync_error: Option<String>,
    pub reachable: Option<bool>,
    pub offline_since: Option<u64>,
    pub attached_quota: Option<u64>,
    pub attach_error: Option<String>,
    pub mounted: bool,
    pub mount_point: Option<String>,
}

/// Calcule la vue de l'état courant.
pub fn tray_view(sh: &Shared) -> TrayView {
    use std::sync::atomic::Ordering::Relaxed;
    let h = sh.health.lock().unwrap().clone();
    let ds = sh.drive_status.lock().unwrap().clone();
    let (pending, conflict) = match &sh.drive {
        Some(d) => {
            let d = d.lock().unwrap();
            (d.pending(), d.conflict.is_some())
        }
        None => (0, false),
    };
    let a = sh.attach.lock().unwrap().clone();
    let (state, text) = if a.in_progress {
        (
            TrayState::Starting,
            "Rattachement au Nœud (preuve d'identité, 1 à 2 min au premier lancement)…".to_string(),
        )
    } else if h.reachable.is_none() {
        (TrayState::Starting, "Démarrage…".to_string())
    } else if let Some(e) = &ds.mount_error {
        (TrayState::Error, format!("Lecteur non monté : {e}"))
    } else if conflict {
        (
            TrayState::Error,
            "Conflit : la version du Nœud a changé (voir le tableau de bord)".into(),
        )
    } else if h.reachable == Some(false) {
        (
            TrayState::Offline,
            "Nœud injoignable — modifications conservées localement".into(),
        )
    } else if let Some(e) = &ds.last_sync_error {
        (TrayState::Error, format!("Erreur de synchronisation : {e}"))
    } else if sh.syncing.load(Relaxed) {
        (TrayState::Syncing, "Synchronisation en cours…".into())
    } else if sh.paused.load(Relaxed) {
        (
            TrayState::Paused,
            format!("Synchronisation suspendue ({pending} modification(s) en attente)"),
        )
    } else if pending > 0 {
        (
            TrayState::Syncing,
            format!("{pending} modification(s) en attente"),
        )
    } else {
        (TrayState::Ok, "À jour".into())
    };
    TrayView {
        state,
        text,
        pending,
        conflict,
        sync_error: ds.last_sync_error,
        reachable: h.reachable,
        offline_since: h.inactivity_detected_at,
        attached_quota: a.attached_quota,
        attach_error: a.last_error,
        mounted: ds.mounted,
        mount_point: sh.mount_point(),
    }
}

/// Synchronise le lecteur (appel bloquant).
pub fn sync_drive(sh: &Shared) -> Option<Result<usize, DriveError>> {
    let d = sh.drive.as_ref()?;
    let mut drive = d.lock().unwrap();
    sh.syncing.store(true, std::sync::atomic::Ordering::Relaxed);
    let r = drive.sync();
    sh.syncing
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let mut st = sh.drive_status.lock().unwrap();
    match &r {
        Ok(_) => {
            sh.scheduler.lock().unwrap().take_due(u64::MAX);
            st.last_sync = Some((sh.clock)());
            st.last_sync_error = None;
        }
        Err(e) => st.last_sync_error = Some(e.to_string()),
    }
    drop(drive);
    Some(r)
}

fn attach_status(sh: &Shared) -> Value {
    if !sh.config.auto_attach {
        return json!("désactivé");
    }
    let a = sh.attach.lock().unwrap().clone();
    json!({
        "en cours": a.in_progress,
        "quota attribué (octets)": a.attached_quota,
        "dernière tentative": if a.last_attempt == 0 { Value::Null } else { json!(a.last_attempt) },
        "erreur": a.last_error,
    })
}

/// Rattachement automatique : preuve VDF (calculée une fois), signature
/// liant l'identité VDF à `pub_user` et au Nœud, requête `Attach`.
async fn auto_attach(sh: &Shared) -> Result<u64, String> {
    let cache = sh.config.data_dir.join("vdf_proof.bin");
    let proof = ensure_user_proof(&cache, &sh.priv_user, &sh.pub_user).await?;
    let sig_priv = s3m_core::keys::derive_sig_priv_user(&sh.priv_user, &sh.pub_user)
        .map_err(|e| e.to_string())?;
    let sig_pub = s3m_core::keys::derive_sig_pub_user(&sig_priv);
    let signature = s3m_protocol::exchange::attach_signature(&sig_priv, &sh.pub_user, &sh.pub_node);
    sh.session
        .attach(&sh.salt, &sig_pub, &proof, signature)
        .await
        .map_err(|e| e.to_string())
}

/// Multiaddrs du Nœud publiées dans son entrée DHT, directe d'abord.
pub fn node_candidates(pub_node: &[u8; 32], envelope: &[u8]) -> Vec<Multiaddr> {
    let Some((addrs, direct)) = s3m_protocol::entries::node_entry_addrs(envelope) else {
        return Vec::new();
    };
    let peer = libp2p::identity::ed25519::PublicKey::try_from_bytes(pub_node)
        .ok()
        .map(|k| libp2p::PeerId::from(libp2p::identity::PublicKey::from(k)));
    let mut out = Vec::new();
    if let (Some((ip, port)), Some(peer)) = (direct, peer) {
        let proto = if ip.contains(':') { "ip6" } else { "ip4" };
        if let Ok(a) = format!("/{proto}/{ip}/tcp/{port}/p2p/{peer}").parse() {
            out.push(a);
        }
    }
    out.extend(addrs.iter().filter_map(|a| a.parse().ok()));
    out
}

/// Période minimale entre deux recherches du Nœud sur le réseau local.
pub const LAN_SEARCH_PERIOD_S: u64 = 120;
const LEARNED_ADDR_FILE: &str = "node.addr";

/// Adresse du Nœud apprise sur le réseau local, si elle désigne le même
/// Nœud (`PeerId` identique) que `configured`.
pub fn learned_node_addr(data_dir: &Path, configured: &Multiaddr) -> Option<Multiaddr> {
    let a: Multiaddr = std::fs::read_to_string(data_dir.join(LEARNED_ADDR_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let peer = |m: &Multiaddr| match m.iter().last() {
        Some(libp2p::multiaddr::Protocol::P2p(p)) => Some(p),
        _ => None,
    };
    (peer(&a).is_some() && peer(&a) == peer(configured)).then_some(a)
}

/// Retient l'adresse qui a répondu (préférée au prochain démarrage).
pub fn save_learned_node_addr(data_dir: &Path, addr: &Multiaddr) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(data_dir.join(LEARNED_ADDR_FILE), addr.to_string())
}

/// Un tour de surveillance : joignabilité du Nœud, renouvellement de
/// l'autorisation de secours.
pub async fn watch_once(sh: &Shared) {
    let now = (sh.clock)();
    // Sonde : un hash nul n'existe jamais ; `NotFound` prouve que le Nœud
    // répond et accepte notre identifiant.
    let mut probe = sh.session.get_block(&[0; 32]).await;
    // Identifiant refusé : pas encore rattaché — demande automatique (au
    // plus une tentative toutes les 10 minutes).
    let refused = matches!(probe, Err(ExchangeError::Refused(Refusal::Unauthorized)));
    let retry = {
        let a = sh.attach.lock().unwrap();
        !a.in_progress && now >= a.last_attempt + 600
    };
    if refused && sh.config.auto_attach && retry {
        {
            let mut a = sh.attach.lock().unwrap();
            a.in_progress = true;
            a.last_attempt = now;
        }
        let r = auto_attach(sh).await;
        {
            let mut a = sh.attach.lock().unwrap();
            a.in_progress = false;
            match r {
                Ok(q) => {
                    a.attached_quota = Some(q);
                    a.last_error = None;
                }
                Err(e) => a.last_error = Some(e),
            }
        }
        probe = sh.session.get_block(&[0; 32]).await;
    }
    // Nœud injoignable à l'adresse courante : adresses publiées dans son
    // entrée DHT (directe, QUIC, relais — `network.traversee-nat`).
    if matches!(probe, Err(ExchangeError::Network(_))) {
        if let Some(client) = sh.dht.get() {
            if let Some(env) = client.get(sh.pub_node.to_vec()).await.ok().flatten() {
                let current = sh.session.node_addr();
                for a in node_candidates(&sh.pub_node, &env) {
                    if a == current {
                        continue;
                    }
                    sh.session.set_node_addr(a);
                    probe = sh.session.get_block(&[0; 32]).await;
                    if !matches!(probe, Err(ExchangeError::Network(_))) {
                        break;
                    }
                }
                if matches!(probe, Err(ExchangeError::Network(_))) {
                    sh.session.set_node_addr(current);
                }
            }
        }
    }
    // Toujours injoignable : le Nœud a peut-être changé d'adresse sur le
    // réseau local (box, DHCP) — recherche mDNS par son identité, au plus
    // toutes les 2 minutes (`network.bootstrap` § Découverte sur le réseau local).
    if matches!(probe, Err(ExchangeError::Network(_))) {
        let due = {
            let mut last = sh.last_lan_search.lock().unwrap();
            let due = last.is_none_or(|t| now.saturating_sub(t) >= LAN_SEARCH_PERIOD_S);
            if due {
                *last = Some(now);
            }
            due
        };
        if due {
            let current = sh.session.node_addr();
            let found = crate::lan::scan(Duration::from_secs(4))
                .await
                .unwrap_or_default();
            for n in found
                .iter()
                .filter(|n| n.node_id == sh.pub_node && !n.to_configure)
            {
                let Ok(a) = n.addr.parse::<Multiaddr>() else {
                    continue;
                };
                if a == current {
                    continue;
                }
                sh.session.set_node_addr(a.clone());
                probe = sh.session.get_block(&[0; 32]).await;
                if !matches!(probe, Err(ExchangeError::Network(_))) {
                    if let Err(e) = save_learned_node_addr(&sh.config.data_dir, &a) {
                        eprintln!("adresse du Nœud : {e}");
                    }
                    break;
                }
                sh.session.set_node_addr(current.clone());
            }
        }
    }
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
    channel_tick(sh, now, ok).await;
    if ok {
        // Lecture du quota et de l'occupation : validation sans changement
        // de racine (`base = new`).
        let root = sh
            .drive
            .as_ref()
            .map_or([0; 32], |d| d.lock().unwrap().root_hash());
        let _ = sh.session.commit_root(&root, &root).await;
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

/// Démarre le Connecteur ; rend le contexte et l'URL du dashboard.
pub async fn start(
    config: Config,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Result<(Arc<Shared>, String), DaemonError> {
    state_dir(&config)?;
    let mnemonic = std::fs::read_to_string(&config.seed_file)?;
    let (priv_user, pub_user) = user_keys(&mnemonic, config.identity_index)?;
    let master = master_key(&mnemonic, KEY_VERSION)?;
    let addr: Multiaddr = config
        .node
        .addr
        .parse()
        .map_err(|e| DaemonError::Config(format!("adresse du Nœud : {e}")))?;
    let addr = learned_node_addr(&config.data_dir, &addr).unwrap_or(addr);
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
    let drive = match &config.mount_point {
        None => None,
        Some(_) => Some(Arc::new(Mutex::new(
            Drive::open(
                Arc::new(NodeIo {
                    session: session.clone(),
                    runtime: tokio::runtime::Handle::current(),
                }),
                master,
                config.data_dir.join("workspace"),
                clock.clone(),
            )
            .map_err(|e| DaemonError::Config(format!("lecteur : {e}")))?,
        ))),
    };
    let shared = Arc::new(Shared {
        config: config.clone(),
        pub_user,
        drive,
        scheduler: Arc::new(Mutex::new(Scheduler::new(WriteBackConfig::default()))),
        drive_status: Mutex::new(DriveStatus::default()),
        paused: Default::default(),
        syncing: Default::default(),
        user_entry: Mutex::new(UserEntryState::default()),
        attach: Mutex::new(AttachState::default()),
        dht: std::sync::OnceLock::new(),
        emergency: Mutex::new(load_emergency(&config)),
        channel: Mutex::new(load_channel(&config)),
        last_lan_search: Mutex::new(None),
        change_node: Default::default(),
        mount_point: Mutex::new(config.mount_point.clone()),
        remount: Mutex::new(None),
        priv_user,
        pub_node,
        salt: salt.clone(),
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
        Arc::new(move |name, v| match name {
            "set_mount_point" => set_mount_point(&sh, &v),
            "sync_now" => {
                sync_now(&sh);
                Ok(json!({ "ok": true, "message": "Synchronisation lancée" }))
            }
            "admin_node" => admin_node(&sh.config.node.addr, &v),
            "send_node_message" | "acknowledge_alert" => channel_action(&sh, name, &v),
            "change_node" => {
                if v.get("je confirme").and_then(|x| x.as_bool()) != Some(true) {
                    return Err("cochez « je confirme » pour changer de Nœud".into());
                }
                sh.change_node
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(
                    json!({ "ok": true, "message": "S3m redémarre et ouvre l'assistant de choix du Nœud…" }),
                )
            }
            _ => Err(format!("action inconnue : {name}")),
        })
    };
    let url = local_http::serve(
        config.api_port,
        st_fn,
        act_fn,
        ASSETS,
        Some(&config.data_dir),
    )
    .await?;
    if !config.dht_bootstrap.is_empty() {
        spawn_user_entry(shared.clone(), priv_user, pub_node, salt.clone());
    }
    if shared.drive.is_some() {
        mount_drive(&shared);
        // Écriture différée : synchronisation quand un fichier modifié
        // atteint son échéance (`protocols.ecriture-differee`).
        let sh = shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if sh.paused.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }
                let due = !sh
                    .scheduler
                    .lock()
                    .unwrap()
                    .take_due((sh.clock)())
                    .is_empty();
                let pending = sh
                    .drive
                    .as_ref()
                    .is_some_and(|d| d.lock().unwrap().pending() > 0);
                let retry = pending && sh.drive_status.lock().unwrap().last_sync_error.is_some();
                if due || retry {
                    let s2 = sh.clone();
                    let _ = tokio::task::spawn_blocking(move || sync_drive(&s2)).await;
                }
            }
        });
    }
    let sh = shared.clone();
    tokio::spawn(async move {
        loop {
            watch_once(&sh).await;
            emergency_tick(&sh).await;
            tokio::time::sleep(Duration::from_secs(sh.config.watch_interval_s.max(1))).await;
        }
    });
    Ok((shared, url))
}

/// Monte le lecteur (Windows, feature `mount`) dans un fil dédié qui garde
/// l'hôte WinFsp vivant.
#[cfg(all(windows, feature = "mount"))]
fn mount_drive(sh: &Arc<Shared>) {
    let (Some(drive), Some(point)) = (sh.drive.clone(), sh.mount_point()) else {
        return;
    };
    let sched = sh.scheduler.clone();
    let clock = sh.clock.clone();
    let sh2 = sh.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    *sh.remount.lock().unwrap() = Some(tx);
    std::thread::spawn(move || {
        let session = sh2.session.clone();
        let on_write: crate::winfsp_backend::WriteHook = Arc::new(move |path, size| {
            sched.lock().unwrap().on_write(path, size, clock());
        });
        let mount = |letter: &str| {
            let session = session.clone();
            let fs = crate::winfsp_backend::DriveFs {
                drive: drive.clone(),
                on_write: on_write.clone(),
                space: Arc::new(move || session.space()),
            };
            let r = crate::winfsp_backend::mount(fs, letter);
            let mut st = sh2.drive_status.lock().unwrap();
            st.mounted = r.is_ok();
            st.mount_error = r.as_ref().err().cloned();
            r.ok()
        };
        let mut point = point;
        let mut host = mount(&point);
        // Le fil garde l'hôte WinFsp vivant et traite les changements de lettre.
        while let Ok((letter, reply)) = rx.recv() {
            if let Some(mut h) = host.take() {
                h.stop();
                h.unmount();
            }
            match mount(&letter) {
                Some(h) => {
                    host = Some(h);
                    point = letter;
                    let _ = reply.send(Ok(()));
                }
                None => {
                    let e = sh2.drive_status.lock().unwrap().mount_error.clone();
                    host = mount(&point);
                    let _ = reply.send(Err(format!(
                        "montage sur {letter} impossible : {}",
                        e.unwrap_or_default()
                    )));
                }
            }
        }
    });
}

#[cfg(not(all(windows, feature = "mount")))]
fn mount_drive(sh: &Arc<Shared>) {
    sh.drive_status.lock().unwrap().mount_error =
        Some("exécutable compilé sans la feature `mount` (WinFsp)".into());
}

/// Ouvre le dashboard du Nœud à distance (code 2FA) —
/// `deploiement.appairage-admin` § Administration à distance. Appelée
/// depuis un fil bloquant (API locale).
pub fn admin_node(node_addr: &str, v: &Value) -> Result<Value, String> {
    let totp = v
        .get("code 2FA")
        .and_then(|x| x.as_str())
        .unwrap_or_default();
    let addr = match v.get("adresse d'administration").and_then(|x| x.as_str()) {
        Some(a) if !a.trim().is_empty() => {
            a.trim().parse().map_err(|e| format!("adresse : {e}"))?
        }
        _ => crate::admin_client::default_admin_addr(node_addr)?,
    };
    tokio::runtime::Handle::current().block_on(async move {
        let client = crate::admin_client::AdminClient::start()?;
        let session = client.login(&addr, totp).await?;
        let url = crate::remote::serve_remote(session).await?;
        Ok(json!({ "ok": true, "message": "Connecté au Nœud : son tableau de bord s'ouvre", "ouvrir": url }))
    })
}

// ------------------------------------------------- écriture d'urgence

impl Shared {
    /// Lettre courante du lecteur monté.
    pub fn mount_point(&self) -> Option<String> {
        self.mount_point.lock().unwrap().clone()
    }
}

/// Un tour d'écriture d'urgence (`protocols.espace-secours`) : dépôt chez
/// les partenaires de secours quand le Nœud est injoignable depuis
/// `EMERGENCY_DELAY_S`, réconciliation et libération à son retour.
pub async fn emergency_tick(sh: &Arc<Shared>) {
    if !sh.config.emergency_write {
        return;
    }
    let Some(drive) = sh.drive.clone() else {
        return;
    };
    let now = (sh.clock)();
    let h = sh.health.lock().unwrap().clone();
    if h.reachable == Some(true) {
        reconcile_emergency(sh, &drive, now).await;
        return;
    }
    let Some(since) = h.inactivity_detected_at else {
        return;
    };
    if now.saturating_sub(since) < EMERGENCY_DELAY_S {
        return;
    }
    let d2 = drive.clone();
    let build =
        match tokio::task::spawn_blocking(move || d2.lock().unwrap().emergency_build()).await {
            Ok(Ok(Some(b))) => b,
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(e)) => {
                let mut e2 = sh.emergency.lock().unwrap();
                e2.last_attempt = Some(now);
                e2.last_error = Some(format!("arborescence : {e}"));
                drop(e2);
                save_emergency(sh);
                return;
            }
        };
    sh.emergency.lock().unwrap().last_attempt = Some(now);
    match deposit(sh, &build, now).await {
        Ok(seq) => {
            if let Err(e) = drive.lock().unwrap().emergency_confirm(&build) {
                sh.emergency.lock().unwrap().last_error = Some(e.to_string());
            } else {
                let mut e = sh.emergency.lock().unwrap();
                e.published_seq = Some(seq);
                e.last_deposit_at = Some(now);
                e.last_error = None;
            }
        }
        Err(e) => sh.emergency.lock().unwrap().last_error = Some(e),
    }
    save_emergency(sh);
}

fn deposit_identity(
    sh: &Shared,
    proof: s3m_core::vdf::VdfProof,
) -> Result<crate::emergency::DepositIdentity, String> {
    let sig_priv_user = s3m_core::keys::derive_sig_priv_user(&sh.priv_user, &sh.pub_user)
        .map_err(|e| e.to_string())?;
    Ok(crate::emergency::DepositIdentity {
        sig_pub_user: s3m_core::keys::derive_sig_pub_user(&sig_priv_user),
        sig_priv_user,
        proof,
        keys: s3m_protocol::emergency::emergency_keys(&sh.session.k_attach())
            .map_err(|e| e.to_string())?,
    })
}

/// Dépose les blocs de `build` et publie l'`EmergencyManifest` fusionné ;
/// rend la séquence publiée.
async fn deposit(
    sh: &Arc<Shared>,
    build: &crate::drive::EmergencyBuild,
    now: u64,
) -> Result<u64, String> {
    use crate::emergency::{assign_blocks, deposit_block, discover};
    use s3m_protocol::emergency::{Manifest, RootChange};
    let dht = sh.dht.get().cloned().ok_or("annuaire DHT indisponible")?;
    let cache = sh.config.data_dir.join("vdf_proof.bin");
    let proof = ensure_user_proof(&cache, &sh.priv_user, &sh.pub_user).await?;
    let id = deposit_identity(sh, proof)?;
    let n = sh.config.n_secours.max(1);
    let mut cands = discover(&dht, &sh.pub_user, &sh.pub_node, n + 4).await;
    if cands.len() < n {
        return Err(format!(
            "partenaires de secours : {} trouvé(s), {n} nécessaire(s)",
            cands.len()
        ));
    }
    let spares = cands.split_off(n);
    let mut spares = spares.into_iter();
    let assign =
        assign_blocks(build.blocks.len(), n, sh.config.q_max_bytes).map_err(|e| e.to_string())?;
    let client = sh.session.client().clone();
    let mut placed: Vec<([u8; 32], [u8; 32])> = Vec::new();
    for ((hash, frame), slot) in build.blocks.iter().zip(assign) {
        loop {
            let c = cands[slot].clone();
            match deposit_block(&client, &c, &id, frame.clone()).await {
                Ok(()) => {
                    placed.push((*hash, c.partner.node_id));
                    record_deposit(sh, &c, hash);
                    break;
                }
                Err(e) => match spares.next() {
                    Some(s) => cands[slot] = s,
                    None => return Err(format!("dépôt refusé : {e}")),
                },
            }
        }
    }
    let used: Vec<_> = cands
        .iter()
        .filter(|c| placed.iter().any(|(_, n)| *n == c.partner.node_id))
        .map(|c| c.partner.clone())
        .collect();
    let mine = Manifest {
        user_id: sh.pub_user,
        partners: used,
        blocks: placed,
        roots: vec![RootChange {
            timestamp: now,
            new_root: build.root.fs_root_hash,
            encryption_salt: build.root.encryption_salt,
            key_version: build.root.key_version,
        }],
        base_fs_root_hash: build.base,
        timestamp: now,
    };
    publish_manifest(sh, &dht, &mine, now).await
}

/// Lecture, fusion, publication avec `seq + 1` (un nouvel essai si un
/// autre Connecteur a publié entre-temps).
async fn publish_manifest(
    sh: &Shared,
    dht: &DhtClient,
    mine: &s3m_protocol::emergency::Manifest,
    now: u64,
) -> Result<u64, String> {
    use s3m_protocol::emergency::{emergency_entry_envelope, merge_manifest, open_emergency_entry};
    let k = sh.session.k_attach();
    let key = s3m_protocol::dht::emergency_dht_key(&k).to_vec();
    let mut last = String::new();
    for _ in 0..2 {
        let current = dht
            .get(key.clone())
            .await
            .ok()
            .flatten()
            .and_then(|env| open_emergency_entry(&k, &env).ok());
        let seq = current.as_ref().map_or(0, |(s, _)| *s) + 1;
        let merged = merge_manifest(current.as_ref().map(|(_, m)| m), mine);
        let nonce: [u8; 12] = random32().map_err(|e| e.to_string())?[..12]
            .try_into()
            .expect("12 octets");
        let env =
            emergency_entry_envelope(&k, seq, now, &nonce, &merged).map_err(|e| e.to_string())?;
        match dht.put(key.clone(), env).await {
            Ok(()) => return Ok(seq),
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("publication du manifeste de secours : {last}"))
}

fn record_deposit(sh: &Shared, c: &crate::emergency::Candidate, hash: &[u8; 32]) {
    let mut e = sh.emergency.lock().unwrap();
    let n = hex::encode(c.partner.node_id);
    let h = hex::encode(hash);
    match e.deposits.iter_mut().find(|(p, _, _)| *p == n) {
        Some((_, _, v)) => {
            if !v.contains(&h) {
                v.push(h);
            }
        }
        None => e.deposits.push((n, c.addr.to_string(), vec![h])),
    }
}

/// Nœud revenu : réconcilie un dépôt fait par un autre Connecteur, puis
/// libère les partenaires une fois les modifications validées.
async fn reconcile_emergency(sh: &Arc<Shared>, drive: &Arc<Mutex<Drive>>, now: u64) {
    let (pending, current) = {
        let d = drive.lock().unwrap();
        (d.pending(), d.emergency_current())
    };
    // Dépôt d'un autre Connecteur, construit sur notre racine.
    if pending == 0 {
        adopt_from_manifest(sh, drive, now).await;
    }
    // Nos propres dépôts : libérés dès que plus rien ne les attend (validés
    // par la synchronisation, ou remplacés par des modifications plus
    // récentes que les copies locales enverront).
    if current {
        return;
    }
    let deposits = sh.emergency.lock().unwrap().deposits.clone();
    if deposits.is_empty() {
        return;
    }
    let Ok(keys) = s3m_protocol::emergency::emergency_keys(&sh.session.k_attach()) else {
        return;
    };
    let client = sh.session.client().clone();
    let mut next = sh.emergency.lock().unwrap().last_release_ts.max(now) + 1;
    let mut remaining = Vec::new();
    for (node, addr, hashes) in deposits {
        let hs: Vec<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
            .collect();
        let Ok(a) = addr.parse::<Multiaddr>() else {
            continue;
        };
        match crate::emergency::release_blocks(&client, a, &keys, &mut next, &hs).await {
            Ok(n) => sh.emergency.lock().unwrap().released_blocks += n,
            Err(_) => remaining.push((node, addr, hashes)),
        }
    }
    {
        let mut e = sh.emergency.lock().unwrap();
        e.deposits = remaining;
        e.last_release_ts = next;
        e.reconciled_at = Some(now);
    }
    save_emergency(sh);
}

/// Changement de racine déposé par un autre Connecteur sur la racine de
/// ce lecteur : blocs complétés chez le Nœud, validation, adoption,
/// libération des partenaires.
async fn adopt_from_manifest(sh: &Arc<Shared>, drive: &Arc<Mutex<Drive>>, now: u64) {
    use s3m_protocol::emergency::open_emergency_entry;
    let Some(dht) = sh.dht.get().cloned() else {
        return;
    };
    let k = sh.session.k_attach();
    let key = s3m_protocol::dht::emergency_dht_key(&k).to_vec();
    let Some(env) = dht.get(key).await.ok().flatten() else {
        return;
    };
    let Ok((_, m)) = open_emergency_entry(&k, &env) else {
        return;
    };
    let root = drive.lock().unwrap().root_hash();
    let Some(change) = m.pending_root(&root).copied() else {
        return;
    };
    let Ok(keys) = s3m_protocol::emergency::emergency_keys(&sh.session.k_attach()) else {
        return;
    };
    let client = sh.session.client().clone();
    let mut addrs = std::collections::HashMap::new();
    for p in &m.partners {
        if let Some(a) = crate::emergency::partner_addr(Some(&dht), p).await {
            addrs.insert(p.node_id, a);
        }
    }
    for (h, p) in &m.blocks {
        match sh.session.get_block(h).await {
            Ok(_) => continue,
            Err(ExchangeError::Refused(Refusal::NotFound)) => {}
            Err(_) => return,
        }
        let Some(a) = addrs.get(p).cloned() else {
            return;
        };
        let Some(d) = crate::emergency::fetch_block(&client, a, &keys.sig_pub, h).await else {
            return;
        };
        if sh.session.put_block(d).await.is_err() {
            return;
        }
    }
    let Ok((committed, current)) = sh.session.commit_root(&root, &change.new_root).await else {
        return;
    };
    if !committed && current != change.new_root.to_vec() {
        return;
    }
    let adopted = drive.lock().unwrap().advance_root(
        &root,
        Root {
            fs_root_hash: change.new_root,
            encryption_salt: change.encryption_salt,
            key_version: change.key_version,
        },
    );
    if !matches!(adopted, Ok(true)) {
        return;
    }
    let mut next = sh.emergency.lock().unwrap().last_release_ts.max(now) + 1;
    let mut freed = 0;
    for p in &m.partners {
        let Some(a) = addrs.get(&p.node_id).cloned() else {
            continue;
        };
        let hs = m.blocks_at(&p.node_id);
        freed += crate::emergency::release_blocks(&client, a, &keys, &mut next, &hs)
            .await
            .unwrap_or(0);
    }
    {
        let mut e = sh.emergency.lock().unwrap();
        e.released_blocks += freed;
        e.last_release_ts = next;
        e.reconciled_at = Some(now);
    }
    save_emergency(sh);
}
