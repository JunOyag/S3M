//! Exécutable du Nœud — id `deploiement.packaging` (partie node).
//! Réf. spec : docs/07-deploiement/packaging.md.
//!
//! Assemble : identité depuis la phrase de récupération, stockage physique,
//! adaptateur DHT, serveur d'échange de blocs, état persistant (JSON),
//! tâches périodiques (pointeurs de migration, purge des Nœuds silencieux,
//! sauvegarde) et API locale du dashboard.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::Multiaddr;
use s3m_core::identity_derivation::{derive_identity_seed, mnemonic_to_seed, IdentityRole};
use s3m_protocol::exchange::{
    decode_request, encode_request, Body, Delegation, Request, SILENT_NODE_RETENTION_SECONDS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dht_directory::{chiavdf_verifier, system_clock};
use crate::dispersal_engine::{
    reconcile, run_cycle, CycleReport, DispersalState, EngineConfig, NetFabric,
};
use crate::exchange::{refresh_successors, NodeService, PartnerState, UserAccount};
use crate::exchange::{AttachPolicy, PartnerPolicy, VdfCheck};
use crate::geo::{Geo, ATTRIBUTION, DB_FILE};
use crate::local_http::{ActionFn, Asset, StatusFn};
use crate::net::{NatState, NetConfig, RelayLimits};
use crate::partnering::{excluded, run_partnering, score, Net, PartneringConfig, PartneringReport};
use crate::publish::{ensure_node_proof, publish_entry, NodeEntryState};
use crate::recovery::recover;
use crate::snapshot_engine::run_snapshot;
use crate::tombstones::PartnerLedger;
use crate::upkeep::{run_upkeep, UpkeepConfig, UpkeepReport};
use crate::{PhysicalStore, VolumeConfig};

/// Erreurs de l'exécutable.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("configuration : {0}")]
    Config(String),
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("démarrage : {0}")]
    Start(String),
}

/// Volume de stockage déclaré.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub volume_id: u32,
    pub mount_path: PathBuf,
    pub max_capacity_bytes: u64,
}

/// Fichier de configuration (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Fichier contenant la phrase de récupération (BIP-39) du Nœud.
    pub seed_file: PathBuf,
    #[serde(default)]
    pub identity_index: u32,
    /// Répertoire de la base SQLite et de l'état.
    pub data_dir: PathBuf,
    pub volumes: Vec<VolumeSpec>,
    /// Adresse d'écoute de la pile réseau unique (DHT, échange de blocs,
    /// traversée de NAT ; QUIC sur le même port).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Anciens réglages (deux ports) : s'ils sont présents, ils remplacent
    /// `listen` — les configurations existantes restent valides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dht_listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks_listen: Option<String>,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// Paramètres de dispersion (k, coef, délai de padding, délai de grâce).
    #[serde(default)]
    pub dispersal: EngineConfig,
    /// Contrôles PoS, analyse de volatilité, scrubbing.
    #[serde(default)]
    pub upkeep: UpkeepConfig,
    /// Adresse publique annoncée dans l'entrée DHT Node (IP joignable par
    /// les Connecteurs et partenaires). Absente : IP d'écoute de l'échange
    /// de blocs si elle est explicite.
    #[serde(default)]
    pub public_ip: Option<String>,
    /// Port public de l'échange de blocs (défaut : port d'écoute).
    #[serde(default)]
    pub public_port: Option<u16>,
    /// Partenariats automatiques (découverte, score, recrutement, retrait).
    #[serde(default)]
    pub partnering: PartneringConfig,
    /// Acceptation des propositions de partenariat.
    #[serde(default)]
    pub partner_policy: PartnerPolicy,
    /// Rattachement automatique des Utilisateurs (valeur initiale ; modifiable
    /// depuis le dashboard).
    #[serde(default)]
    pub attach: AttachPolicy,
    /// Enregistrer l'adresse IP des Utilisateurs (carte du dashboard).
    #[serde(default = "default_true")]
    pub record_user_ips: bool,
    /// Ouverture automatique du port sur la box (UPnP).
    #[serde(default = "default_true")]
    pub upnp: bool,
    /// Service de relais rendu aux Nœuds derrière un NAT.
    #[serde(default = "default_true")]
    pub relay_server: bool,
    #[serde(default)]
    pub relay_limits: RelayLimits,
    /// Relais imposés (`/ip4/…/tcp/…/p2p/<PeerId>`) ; sinon choix automatique.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Réserver des relais même sans NAT détecté.
    #[serde(default)]
    pub force_relay: bool,
    /// Annonce sur le réseau local (mDNS) : l'assistant du Connecteur trouve
    /// ce Nœud.
    #[serde(default = "default_true")]
    pub mdns: bool,
    /// Administration à distance par le canal `/s3m/admin/1`
    /// (deploiement.appairage-admin).
    #[serde(default = "default_true")]
    pub remote_admin: bool,
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Numéro de série du secret 2FA (régénération).
    #[serde(default)]
    pub admin_totp_serial: u32,
    /// Fichier d'origine (modification depuis le dashboard) ; non sérialisé.
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

pub fn default_listen() -> String {
    "/ip4/0.0.0.0/tcp/4001".into()
}

pub fn default_admin_listen() -> String {
    format!("/ip4/0.0.0.0/tcp/{}", s3m_protocol::admin::DEFAULT_PORT)
}

fn default_api_port() -> u16 {
    8765
}

impl Config {
    /// Adresses d'écoute effectives : anciens réglages s'ils sont présents
    /// (échange de blocs en premier), sinon `listen`.
    pub fn listen_addrs(&self) -> Vec<String> {
        let mut out: Vec<String> = [&self.blocks_listen, &self.dht_listen]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        out.dedup();
        if out.is_empty() {
            out.push(self.listen.clone());
        }
        out
    }

    fn dht_bootstrap_is_empty(&self) -> bool {
        self.bootstrap.is_empty()
    }

    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        let s = std::fs::read_to_string(path)?;
        let mut c: Config =
            serde_json::from_str(&s).map_err(|e| DaemonError::Config(e.to_string()))?;
        // Chemins relatifs : relatifs au fichier de configuration.
        let base = path.parent().unwrap_or(Path::new("."));
        let abs = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        abs(&mut c.seed_file);
        abs(&mut c.data_dir);
        for v in &mut c.volumes {
            abs(&mut v.mount_path);
        }
        c.source = Some(path.to_path_buf());
        Ok(c)
    }
}

/// Graine `priv_node` depuis la phrase de récupération.
pub fn node_seed_from_mnemonic(mnemonic: &str, index: u32) -> Result<[u8; 32], DaemonError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    bip39::Mnemonic::parse_normalized(&words)
        .map_err(|e| DaemonError::Config(format!("phrase de récupération : {e}")))?;
    let seed = mnemonic_to_seed(&words, "").map_err(|e| DaemonError::Config(e.to_string()))?;
    derive_identity_seed(&seed, IdentityRole::Node, index)
        .map_err(|e| DaemonError::Config(e.to_string()))
}

/// `pub_node_recovery` (`m/0x703270'/2'/<index>'`) depuis la phrase.
pub fn node_recovery_pub(mnemonic: &str, index: u32) -> Result<[u8; 32], DaemonError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    let seed = mnemonic_to_seed(&words, "").map_err(|e| DaemonError::Config(e.to_string()))?;
    let k = derive_identity_seed(&seed, IdentityRole::NodeRecovery, index)
        .map_err(|e| DaemonError::Config(e.to_string()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&k)
        .verifying_key()
        .to_bytes())
}

/// Adresse TCP directe annoncée : configuration, sinon adresse externe
/// confirmée par la traversée de NAT, sinon IP et port d'écoute explicites.
pub fn announced_direct(c: &Config, nat: &NatState) -> Option<(String, u16)> {
    if c.public_ip.is_none() {
        if let Some((ip, port)) = nat.direct_tcp() {
            return Some((ip, c.public_port.unwrap_or(port)));
        }
    }
    announced_addr(c)
}

/// Adresses externes déclarées par `public_ip` (TCP et QUIC, même port).
pub fn declared_external(c: &Config) -> Vec<Multiaddr> {
    let Some((ip, port)) = c.public_ip.as_ref().and_then(|_| announced_addr(c)) else {
        return Vec::new();
    };
    let proto = if ip.contains(':') { "ip6" } else { "ip4" };
    [
        format!("/{proto}/{ip}/tcp/{port}"),
        format!("/{proto}/{ip}/udp/{port}/quic-v1"),
    ]
    .iter()
    .filter_map(|a| a.parse().ok())
    .collect()
}

/// Adresse annoncée : configuration, sinon IP et port d'écoute explicites.
pub fn announced_addr(c: &Config) -> Option<(String, u16)> {
    let listen: Multiaddr = c.listen_addrs().first()?.parse().ok()?;
    let (mut ip, mut port) = (None, 0);
    for p in listen.iter() {
        match p {
            libp2p::multiaddr::Protocol::Ip4(v) if !v.is_unspecified() => ip = Some(v.to_string()),
            libp2p::multiaddr::Protocol::Tcp(v) => port = v,
            _ => {}
        }
    }
    let ip = c.public_ip.clone().or(ip)?;
    let port = c.public_port.unwrap_or(port);
    (port != 0).then_some((ip, port))
}

/// Nouvelle phrase de récupération de 24 mots.
pub fn generate_mnemonic() -> Result<String, DaemonError> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| DaemonError::Start(e.to_string()))?;
    bip39::Mnemonic::from_entropy(&entropy)
        .map(|m| m.to_string())
        .map_err(|e| DaemonError::Start(e.to_string()))
}

// --------------------------------------------------------- état persistant

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "32 octets attendus".to_string())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedUser {
    pub user_id: String,
    pub salt: String,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub root: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedPartner {
    pub node_id: String,
    #[serde(default)]
    pub addr: Option<String>,
    pub allowance: u64,
    pub hosted_for_partner: u64,
    pub hosted_by_partner: u64,
    pub last_tombstone_at: u64,
    pub last_seen: u64,
}

/// État du service hors blocs (les blocs sont dans le stockage physique).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedState {
    pub users: Vec<SavedUser>,
    pub partners: Vec<SavedPartner>,
    pub previous_node_ids: Vec<String>,
    pub incidents: Vec<String>,
    /// Délégations reçues, encodées comme requêtes `Delegate`.
    pub delegations: Vec<String>,
    /// Politique de rattachement automatique modifiée depuis le dashboard.
    #[serde(default)]
    pub attach_policy: Option<AttachPolicy>,
    #[serde(default)]
    pub auto_attached: Vec<String>,
    #[serde(default)]
    pub used_attach_identities: Vec<String>,
    /// `(user_id, ip)` de la dernière connexion.
    #[serde(default)]
    pub user_ips: Vec<(String, String)>,
}

impl SavedState {
    pub fn capture(s: &NodeService, addrs: &HashMap<[u8; 32], String>) -> Self {
        let mut users: Vec<SavedUser> = s
            .users
            .iter()
            .map(|(id, u)| SavedUser {
                user_id: hx(id),
                salt: hx(&u.salt),
                quota_bytes: u.quota_bytes,
                used_bytes: u.used_bytes,
                root: hx(&u.root),
            })
            .collect();
        users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        let mut partners: Vec<SavedPartner> = s
            .partners
            .iter()
            .map(|(id, p)| SavedPartner {
                node_id: hx(id),
                addr: addrs.get(id).cloned(),
                allowance: p.allowance,
                hosted_for_partner: p.ledger.hosted_for_partner,
                hosted_by_partner: p.ledger.hosted_by_partner,
                last_tombstone_at: p.ledger.last_tombstone_at,
                last_seen: p.last_seen,
            })
            .collect();
        partners.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Self {
            users,
            partners,
            previous_node_ids: s.previous_node_ids.iter().map(|i| hx(i)).collect(),
            incidents: s.incidents.iter().map(|i| hx(i)).collect(),
            delegations: s
                .delegations
                .iter()
                .map(|d| {
                    hx(&encode_request(&Request {
                        credential: None,
                        body: Body::Delegate(d.clone()),
                    }))
                })
                .collect(),
            attach_policy: Some(s.attach_policy),
            auto_attached: sorted(s.auto_attached.iter().map(|i| hx(i))),
            used_attach_identities: sorted(s.used_attach_identities.iter().map(|i| hx(i))),
            user_ips: {
                let mut v: Vec<(String, String)> = s
                    .last_user_ip
                    .iter()
                    .map(|(u, ip)| (hx(u), ip.clone()))
                    .collect();
                v.sort();
                v
            },
        }
    }

    /// Restaure dans `s` ; rend les adresses des partenaires.
    pub fn restore(&self, s: &mut NodeService) -> Result<HashMap<[u8; 32], String>, String> {
        let mut addrs = HashMap::new();
        for u in &self.users {
            s.users.insert(
                unhex32(&u.user_id)?,
                UserAccount {
                    salt: hex::decode(&u.salt).map_err(|e| e.to_string())?,
                    quota_bytes: u.quota_bytes,
                    used_bytes: u.used_bytes,
                    root: unhex32(&u.root)?,
                },
            );
        }
        for p in &self.partners {
            let id = unhex32(&p.node_id)?;
            if let Some(a) = &p.addr {
                addrs.insert(id, a.clone());
            }
            s.partners.insert(
                id,
                PartnerState {
                    allowance: p.allowance,
                    ledger: PartnerLedger {
                        hosted_for_partner: p.hosted_for_partner,
                        hosted_by_partner: p.hosted_by_partner,
                        last_tombstone_at: p.last_tombstone_at,
                    },
                    last_seen: p.last_seen,
                },
            );
        }
        s.previous_node_ids = self
            .previous_node_ids
            .iter()
            .map(|i| unhex32(i))
            .collect::<Result<_, _>>()?;
        s.incidents = self
            .incidents
            .iter()
            .map(|i| unhex32(i))
            .collect::<Result<_, _>>()?;
        if let Some(p) = self.attach_policy {
            s.attach_policy = p;
        }
        for u in &self.auto_attached {
            s.auto_attached.insert(unhex32(u)?);
        }
        for u in &self.used_attach_identities {
            s.used_attach_identities.insert(unhex32(u)?);
        }
        for (u, ip) in &self.user_ips {
            s.last_user_ip.insert(unhex32(u)?, ip.clone());
        }
        s.delegations = self
            .delegations
            .iter()
            .map(|d| {
                let bytes = hex::decode(d).map_err(|e| e.to_string())?;
                match decode_request(&bytes).map_err(|e| e.to_string())?.body {
                    Body::Delegate(d) => Ok::<Delegation, String>(d),
                    _ => Err("délégation attendue".into()),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(addrs)
    }
}

fn sorted(it: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = it.collect();
    v.sort();
    v
}

/// Lecture de l'état (absent : état vide).
pub fn load_state(path: &Path) -> Result<SavedState, DaemonError> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| DaemonError::Config(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SavedState::default()),
        Err(e) => Err(e.into()),
    }
}

/// Écriture atomique (fichier temporaire puis renommage).
pub fn save_state(path: &Path, st: &SavedState) -> Result<(), DaemonError> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(st).expect("sérialisable"))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ------------------------------------------------------------- dashboard

pub const ASSETS: &[Asset] = &[
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
    (
        "map.html",
        "text/html; charset=utf-8",
        include_bytes!("../dashboard/map.html"),
    ),
    (
        "map.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../dashboard/map.js"),
    ),
    (
        "world.json",
        "application/json",
        include_bytes!("../dashboard/world.json"),
    ),
];

/// État de la mise à jour de la base de géolocalisation.
#[derive(Default)]
pub struct GeoipState {
    pub running: bool,
    /// Dernier résultat : `None` = réussie, `Some(erreur)` sinon.
    pub last: Option<Option<String>>,
}

/// Contexte partagé par le dashboard et les tâches.
pub struct Shared {
    pub service: Arc<Mutex<NodeService>>,
    pub addrs: Arc<Mutex<HashMap<[u8; 32], String>>>,
    pub dispersal: tokio::sync::Mutex<DispersalState>,
    /// Dernier cycle de dispersion : `(instant, bilan)`.
    pub last_cycle: Mutex<Option<(u64, CycleReport)>>,
    /// Dernier cycle de contrôle : `(instant, bilan)`.
    pub last_upkeep: Mutex<Option<(u64, UpkeepReport)>>,
    /// Entrée DHT Node.
    pub node_entry: Arc<Mutex<NodeEntryState>>,
    /// `NodeSnapshotPointer` courant (sérialisé).
    pub snapshot_pointer: Mutex<Option<Vec<u8>>>,
    /// Résultat de la restauration au démarrage, s'il y en a eu une.
    pub recovery: Mutex<Option<Value>>,
    pub excluded: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
    /// Traversée de NAT.
    pub nat: Arc<Mutex<NatState>>,
    pub geo: std::sync::RwLock<Geo>,
    /// Mise à jour de la base de géolocalisation lancée depuis le dashboard.
    pub geoip: Mutex<GeoipState>,
    pub last_partnering: Mutex<Option<(u64, PartneringReport)>>,
    pub config: Config,
    /// Administration à distance : graine `priv_node` (secret TOTP), série
    /// courante, affichage du QR code jusqu'à, serveur.
    pub priv_node: [u8; 32],
    pub admin_serial: std::sync::atomic::AtomicU32,
    pub admin_reveal_until: Mutex<Option<u64>>,
    pub admin: Mutex<Option<crate::admin::AdminServer>>,
    pub peer_id: String,
    pub blocks_addr: Option<String>,
    pub dht_addr: Option<String>,
}

/// État présenté par le dashboard Nœud.
pub fn status(sh: &Shared, now: u64) -> Value {
    let mut v = status_base(sh, now);
    let (forms, pending) = config_forms(sh);
    if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
        a.push(json!({ "nom": "geoip_update", "titre": "Géolocalisation",
            "libellé": "Mettre à jour la base de géolocalisation", "champs": [] }));
        a.extend(forms);
    }
    v["géolocalisation"] = geoip_status(sh);
    v["administration à distance"] = admin_status(sh);
    if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
        a.push(
            json!({ "nom": "show_totp", "titre": "Double authentification (2FA)",
            "libellé": "Afficher le QR code 2FA (2 min)", "champs": [] }),
        );
        a.push(json!({ "nom": "regenerate_totp", "libellé": "Régénérer le 2FA (téléphone perdu)", "champs": [] }));
    }
    v["configuration"] = json!({
        "fichier": sh.config.source.as_ref().map(|p| p.display().to_string()),
        "en attente de redémarrage": if pending.is_empty() { json!("rien") } else { json!(pending) },
    });
    v["résumé"] = node_summary(&v);
    v["pages"] = json!([
        { "id": "accueil", "titre": "Vue d'ensemble", "résumé": true, "carte": true,
          "sections": ["alertes d'intégrité signalées", "identité"], "actions": [] },
        { "id": "utilisateurs", "titre": "Utilisateurs",
          "sections": ["utilisateurs rattachés", "rattachement automatique"],
          "actions": ["attach_user", "set_quota", "set_attach_policy"] },
        { "id": "partenaires", "titre": "Partenaires", "carte": true,
          "sections": ["partenaires", "recherche de partenaires"], "actions": ["add_partner"] },
        { "id": "carte", "titre": "Carte du monde", "cadre": "map.html", "sections": [], "actions": [] },
        { "id": "stockage", "titre": "Stockage et protection",
          "sections": ["volumes", "dispersion", "contrôles et réparation", "snapshot du nœud"], "actions": [] },
        { "id": "reseau", "titre": "Réseau",
          "sections": ["traversée de NAT", "annuaire (entrée Node)", "géolocalisation"], "actions": ["geoip_update"] },
        { "id": "distance", "titre": "Administration à distance",
          "sections": ["administration à distance"], "actions": ["show_totp", "regenerate_totp"] },
        { "id": "configuration", "titre": "Configuration", "sections": ["configuration"], "actions": ["set_config"] },
        { "id": "diagnostic", "titre": "Diagnostic", "autres": true,
          "sections": ["migration", "non suivi par cet exécutable"], "actions": [] }
    ]);
    v
}

/// Indicateurs de la vue d'ensemble (`état` : ok, attention, probleme, neutre).
fn node_summary(v: &Value) -> Value {
    let len = |k: &str| v.get(k).and_then(|x| x.as_array()).map_or(0, |a| a.len());
    let nat = v
        .pointer("/traversée de NAT/joignabilité")
        .and_then(|x| x.as_str())
        .unwrap_or("inconnu")
        .to_string();
    let nat_state = if nat.contains("public") || nat.contains("direct") {
        "ok"
    } else if nat == "inconnu" {
        "neutre"
    } else {
        "attention"
    };
    let entry = v.get("annuaire (entrée Node)");
    let (dir, dir_state) = match entry {
        Some(e) if e.get("erreur").is_some_and(|x| !x.is_null()) => {
            ("erreur".to_string(), "probleme")
        }
        Some(e) if e.get("publiée le").is_some_and(|x| !x.is_null()) => {
            ("publiée".to_string(), "ok")
        }
        Some(e) => (
            e.get("preuve VDF")
                .and_then(|x| x.as_str())
                .unwrap_or("en attente")
                .to_string(),
            "neutre",
        ),
        None => ("—".into(), "neutre"),
    };
    let target = v
        .pointer("/recherche de partenaires/partenaires visés")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let partners = len("partenaires");
    let capacity: u64 = v.get("volumes").and_then(|x| x.as_array()).map_or(0, |a| {
        a.iter()
            .filter_map(|x| x.get("capacité (octets)")?.as_u64())
            .sum()
    });
    let alerts = len("alertes d'intégrité signalées");
    json!([
        { "libellé": "Joignabilité", "valeur": nat, "état": nat_state, "page": "reseau" },
        { "libellé": "Annuaire", "valeur": dir, "état": dir_state, "page": "reseau" },
        { "libellé": "Utilisateurs", "valeur": len("utilisateurs rattachés"), "état": "neutre", "page": "utilisateurs" },
        { "libellé": "Partenaires", "valeur": partners, "détail": format!("{target} visés"),
          "état": if partners == 0 { "attention" } else { "ok" }, "page": "partenaires" },
        { "libellé": "Capacité", "valeur": capacity, "unité": "octets", "état": "neutre", "page": "stockage" },
        { "libellé": "Alertes d'intégrité", "valeur": alerts,
          "état": if alerts == 0 { "ok" } else { "probleme" }, "page": "accueil" }
    ])
}

fn admin_status(sh: &Shared) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let listen: Vec<String> = sh
        .admin
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| {
            s.listen
                .lock()
                .unwrap()
                .iter()
                .map(|a| a.to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut v = json!({
        "active": sh.config.remote_admin && !listen.is_empty(),
        "écoute": listen,
        "série du 2FA": sh.admin_serial.load(std::sync::atomic::Ordering::SeqCst),
    });
    let reveal = sh
        .admin_reveal_until
        .lock()
        .unwrap()
        .is_some_and(|t| now < t);
    if let (true, Some(secret)) = (reveal, admin_secret(sh)) {
        let node_id = ed25519_dalek::SigningKey::from_bytes(&sh.priv_node)
            .verifying_key()
            .to_bytes();
        v["QR code 2FA"] = json!(crate::admin::qr_svg(&crate::admin::otpauth_uri(
            &secret, &node_id
        )));
        v["clé 2FA"] = json!(s3m_core::identity_derivation::base32_encode(&secret));
    }
    v
}

/// Régénère le secret 2FA : série + 1, enregistrée dans `node.json`.
fn regenerate_totp(sh: &Shared) -> Result<Value, String> {
    let next = sh.admin_serial.load(std::sync::atomic::Ordering::SeqCst) + 1;
    if let Some(path) = sh.config.source.as_deref() {
        crate::settings::set_raw(path, "admin_totp_serial", json!(next))?;
    }
    sh.admin_serial
        .store(next, std::sync::atomic::Ordering::SeqCst);
    Ok(
        json!({ "ok": true, "message": "Nouveau 2FA : scannez le nouveau QR code ; l'ancien code et les sessions à distance ne valent plus" }),
    )
}

fn geoip_status(sh: &Shared) -> Value {
    let g = sh.geoip.lock().unwrap();
    let state = match (&g.running, &g.last) {
        (true, _) => "téléchargement en cours…".to_string(),
        (false, None) => "—".into(),
        (false, Some(None)) => "réussie".into(),
        (false, Some(Some(e))) => format!("échec : {e}"),
    };
    json!({
        "base": if sh.geo.read().unwrap().available() { "présente" } else { "absente (carte sans positions)" },
        "dernière mise à jour": state,
        "source": ATTRIBUTION,
    })
}

fn config_forms(sh: &Shared) -> (Vec<Value>, Vec<String>) {
    let Some(path) = sh.config.source.as_deref() else {
        return (vec![], vec![]);
    };
    let running = serde_json::to_value(&sh.config).unwrap_or_default();
    let file = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Config>(&s).ok())
        .and_then(|c| serde_json::to_value(c).ok());
    crate::settings::forms(file.as_ref().unwrap_or(&running), &running)
}

/// Télécharge la base de géolocalisation en arrière-plan puis la recharge.
pub fn geoip_update(sh: Arc<Shared>) -> Result<Value, String> {
    {
        let mut g = sh.geoip.lock().unwrap();
        if g.running {
            return Err("mise à jour déjà en cours".into());
        }
        g.running = true;
    }
    std::thread::spawn(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let r = crate::geo::update(&sh.config.data_dir, now);
        if let Ok(p) = &r {
            *sh.geo.write().unwrap() = Geo::open(p);
        }
        let mut g = sh.geoip.lock().unwrap();
        g.running = false;
        g.last = Some(r.err());
    });
    Ok(json!({ "ok": true,
        "message": "Téléchargement de la base de géolocalisation lancé (quelques dizaines de secondes)" }))
}

/// Enregistre la configuration modifiée ; applique à chaud ce qui peut l'être.
fn set_config(sh: &Shared, v: &Value) -> Result<Value, String> {
    let path = sh
        .config
        .source
        .as_deref()
        .ok_or("configuration sans fichier source")?;
    let a = crate::settings::apply(path, v)?;
    if a.live.is_empty() && a.restart.is_empty() {
        return Ok(json!({ "ok": true, "message": "Aucun changement" }));
    }
    {
        let mut s = sh.service.lock().unwrap();
        s.partner_policy = a.config.partner_policy;
        s.record_user_ips = a.config.record_user_ips;
    }
    let message = if a.restart.is_empty() {
        "Configuration enregistrée et appliquée".to_string()
    } else {
        format!(
            "Configuration enregistrée ; redémarrez le Nœud pour appliquer : {}",
            a.restart.join(", ")
        )
    };
    Ok(json!({ "ok": true, "message": message }))
}

fn status_base(sh: &Shared, now: u64) -> Value {
    let s = sh.service.lock().unwrap();
    let addrs = sh.addrs.lock().unwrap();
    let d = sh.dispersal.try_lock().ok();
    let peers = d
        .as_ref()
        .map(|d| d.partnering.peers.clone())
        .unwrap_or_default();
    let pos = d
        .as_ref()
        .map(|d| {
            (
                d.upkeep.pos_ok.clone(),
                d.upkeep.pos_fail.clone(),
                d.upkeep.last_seen.clone(),
            )
        })
        .unwrap_or_default();
    drop(d);
    let country = |ip: Option<&String>| {
        ip.and_then(|i| sh.geo.read().unwrap().locate(i))
            .map(|p| p.country)
    };
    let mut users: Vec<Value> = s
        .users
        .iter()
        .map(|(id, u)| {
            json!({ "utilisateur": hx(id), "quota (octets)": u.quota_bytes,
                    "utilisé (octets)": u.used_bytes,
                    "rattachement": if s.auto_attached.contains(id) { "automatique" } else { "manuel" },
                    "pays": country(s.last_user_ip.get(id)),
                    "racine": hx(&u.root) })
        })
        .collect();
    users.sort_by_key(|v| v["utilisateur"].to_string());
    let mut partners: Vec<Value> = s
        .partners
        .iter()
        .map(|(id, p)| {
            let purge = p.last_seen + SILENT_NODE_RETENTION_SECONDS;
            let n = hx(id);
            let peer = peers.get(&n).cloned().unwrap_or_default();
            let sc = score(
                &sh.config.partnering,
                &peer,
                pos.0.get(&n).copied().unwrap_or(0),
                pos.1.get(&n).copied().unwrap_or(0),
            );
            let r2 = |x: f64| (x * 100.0).round() / 100.0;
            json!({ "nœud": n, "score": r2(sc.total),
                    "fiabilité": r2(sc.reliability), "disponibilité": r2(sc.availability), "vitesse": r2(sc.speed),
                    "état": if peer.status.is_empty() { "partenaire".to_string() } else { peer.status.clone() },
                    "pays": country(Some(&peer.ip)),
                    "latence (ms)": if peer.answered == 0 { Value::Null } else { json!(peer.latency_ms.round()) },
                    "dernier challenge réussi": pos.2.get(&n),
                    "solde accordé": p.allowance,
                    "fragments confiés": p.ledger.hosted_for_partner,
                    "fragments reçus": p.ledger.hosted_by_partner,
                    "adresse": addrs.get(id),
                    "dernier échange": p.last_seen,
                    "purge à venir": if p.last_seen == 0 { Value::Null } else { json!(purge) },
                    "purge échue": p.last_seen != 0 && purge <= now })
        })
        .collect();
    partners.sort_by(|a, b| {
        b["score"]
            .as_f64()
            .unwrap_or(0.0)
            .total_cmp(&a["score"].as_f64().unwrap_or(0.0))
    });
    let candidates = peers.values().filter(|p| p.status == "candidat").count();
    let pol = s.attach_policy;
    let auto_used: u64 = s
        .auto_attached
        .iter()
        .filter_map(|u| s.users.get(u))
        .map(|u| u.quota_bytes)
        .sum();
    let last_partnering = sh.last_partnering.lock().unwrap().clone();
    let volumes: Vec<Value> = sh
        .config
        .volumes
        .iter()
        .map(|v| json!({ "volume": v.volume_id, "chemin": v.mount_path, "capacité (octets)": v.max_capacity_bytes }))
        .collect();
    json!({
        "titre": "Nœud S3m",
        "carte": true,
        "identité": {
            "node_id": hx(&s.node_id()),
            "peer_id": sh.peer_id,
            "échange de blocs": sh.blocks_addr,
            "DHT": sh.dht_addr,
            "heure (s)": now,
        },
        "volumes": volumes,
        "utilisateurs rattachés": users,
        "rattachement automatique": {
            "activé": pol.enabled, "quota par utilisateur (octets)": pol.quota_bytes,
            "utilisateurs maximum": pol.max_users, "budget total (octets)": pol.budget_bytes,
            "utilisateurs rattachés automatiquement": s.auto_attached.len(),
            "budget utilisé (octets)": auto_used,
        },
        "partenaires": partners,
        "recherche de partenaires": {
            "activée": sh.config.partnering.enabled,
            "candidats connus": candidates,
            "partenaires visés": if sh.config.partnering.target_partners == 0 {
                sh.config.dispersal.k * sh.config.dispersal.coef + 4 } else { sh.config.partnering.target_partners },
            "dernier cycle": last_partnering.map(|(t, r)| json!({ "instant": t, "découverts": r.discovered,
                "testés": r.probed, "proposés": r.proposed, "acceptés": r.accepted,
                "mis en retrait": r.retiring, "terminés": r.ended })),
        },
        "alertes d'intégrité signalées": s.incidents.iter().map(|i| hx(i)).collect::<Vec<_>>(),
        "dispersion": dispersal_status(sh),
        "contrôles et réparation": upkeep_status(sh),
        "annuaire (entrée Node)": node_entry_status(sh),
        "traversée de NAT": nat_status(sh),
        "snapshot du nœud": snapshot_status(sh),
        "migration": {
            "anciens node_id couverts": s.previous_node_ids.iter().map(|i| hx(i)).collect::<Vec<_>>(),
            "délégations reçues": s.delegations.len(),
            "pointeurs de migration connus": s.successors.len(),
        },
        "non suivi par cet exécutable": [
            "taux de republication DHT", "espace de secours"
        ],
        "actions": [
            { "nom": "attach_user", "titre": "Rattacher un utilisateur manuellement", "libellé": "Rattacher",
              "champs": ["user_id", "salt", "quota_bytes"],
              "libellés": { "user_id": "identifiant de l'utilisateur", "salt": "sel d'attachement", "quota_bytes": "quota (octets)" },
              "types": { "quota_bytes": "number" },
              "aide": { "user_id": "Affiché par l'assistant de S3m de l'utilisateur", "salt": "Affiché à côté de l'identifiant (32 caractères)" } },
            { "nom": "add_partner", "titre": "Ajouter un partenaire manuellement", "libellé": "Ajouter",
              "champs": ["node_id", "addr", "allowance"],
              "libellés": { "node_id": "identifiant du Nœud", "addr": "adresse", "allowance": "solde accordé (fragments)" },
              "types": { "allowance": "number" },
              "aide": { "addr": "/ip4/…/tcp/…/p2p/…" } },
            { "nom": "set_quota", "titre": "Changer le quota d'un utilisateur", "libellé": "Changer",
              "champs": ["user_id", "quota_bytes"],
              "libellés": { "user_id": "identifiant de l'utilisateur", "quota_bytes": "nouveau quota (octets)" },
              "types": { "quota_bytes": "number" } },
            { "nom": "set_attach_policy", "titre": "Rattachement automatique des utilisateurs",
              "libellé": "Enregistrer",
              "champs": ["enabled", "quota_bytes", "max_users", "budget_bytes"],
              "libellés": { "enabled": "accepter automatiquement les nouveaux utilisateurs", "quota_bytes": "quota par utilisateur (octets)",
                            "max_users": "utilisateurs au plus", "budget_bytes": "budget total (octets)" },
              "valeurs": { "enabled": s.attach_policy.enabled, "quota_bytes": s.attach_policy.quota_bytes,
                           "max_users": s.attach_policy.max_users, "budget_bytes": s.attach_policy.budget_bytes },
              "types": { "enabled": "bool", "quota_bytes": "number", "max_users": "number", "budget_bytes": "number" } }
        ]
    })
}

fn dispersal_status(sh: &Shared) -> Value {
    let cycle = sh.last_cycle.lock().unwrap().clone();
    let users: Vec<Value> = match sh.dispersal.try_lock() {
        Err(_) => vec![json!({ "état": "cycle en cours" })],
        Ok(d) => d
            .users
            .iter()
            .map(|(u, x)| {
                json!({ "utilisateur": u, "stripes": x.stripes.len(),
                        "blocs en attente": x.pending.len(),
                        "stripes d'index": x.index.len(),
                        "publié le": if x.published_at == 0 { Value::Null } else { json!(x.published_at) },
                        "à republier": x.dirty,
                        "fragments à purger": x.retired.len(),
                        "erreur": x.last_error })
            })
            .collect(),
    };
    json!({
        "paramètres": { "k": sh.config.dispersal.k, "coef": sh.config.dispersal.coef,
                        "partenaires requis par stripe": sh.config.dispersal.k * sh.config.dispersal.coef },
        "dernier cycle": cycle.map(|(t, r)| json!({ "instant": t, "stripes dispersés": r.stripes_dispersed,
                        "publications": r.published, "fragments libérés": r.purged, "erreurs": r.errors })),
        "utilisateurs": users,
    })
}

fn upkeep_status(sh: &Shared) -> Value {
    let last = sh.last_upkeep.lock().unwrap().clone();
    let up = match sh.dispersal.try_lock() {
        Err(_) => return json!({ "état": "cycle en cours" }),
        Ok(d) => d.upkeep.clone(),
    };
    let blacklist: Vec<Value> = up
        .blacklist
        .iter()
        .map(|(n, (at, why))| json!({ "nœud": n, "depuis": at, "motif": why }))
        .collect();
    json!({
        "challenges réussis": up.challenges_passed,
        "challenges sans réponse": up.challenges_timeout,
        "dernière analyse de volatilité": up.last_analysis,
        "dernier scrubbing": up.last_scrub,
        "dernier cycle": last.map(|(t, r)| json!({ "instant": t, "challengés": r.challenged,
            "réussis": r.passed, "sans réponse": r.timeouts, "fraudes": r.frauds.len(),
            "fragments replacés": r.repaired, "blocs locaux réparés": r.local_repaired })),
        "liste noire": blacklist,
        "événements récents": up.events.iter().rev().take(15).cloned().collect::<Vec<_>>(),
    })
}

fn nat_status(sh: &Shared) -> Value {
    let n = sh.nat.lock().unwrap().clone();
    json!({
        "joignabilité": n.status,
        "box (UPnP)": n.upnp,
        "adresses externes confirmées": n.external,
        "adresses via relais": n.relayed,
        "perçages réussis": n.hole_punch_ok,
        "perçages échoués": n.hole_punch_failed,
        "circuits relayés pour d'autres": n.relay_circuits_served,
    })
}

fn node_entry_status(sh: &Shared) -> Value {
    let s = sh.node_entry.lock().unwrap().clone();
    json!({
        "preuve VDF": if s.proof_ready { json!("prête") } else {
            json!(s.proof_error.clone().unwrap_or_else(|| "calcul en cours (≈ 1 min)".into())) },
        "adresse annoncée": announced_direct(&sh.config, &sh.nat.lock().unwrap()).map(|(i, p)| format!("{i}:{p}")),
        "adresses publiées": s.published_addrs,
        "publiée le": s.published_at,
        "prochaine republication": if s.published_at.is_some() { json!(s.next_republish) } else { Value::Null },
        "erreur": s.last_error,
    })
}

fn snapshot_status(sh: &Shared) -> Value {
    let recovery = sh.recovery.lock().unwrap().clone();
    let snap = match sh.dispersal.try_lock() {
        Err(_) => return json!({ "état": "cycle en cours", "restauration": recovery }),
        Ok(d) => d.snapshot.clone(),
    };
    json!({
        "dernier snapshot": if snap.last_at == 0 { Value::Null } else { json!(snap.last_at) },
        "fragments placés": snap.stripe.as_ref().map(|s| s.parity.len()),
        "publié dans l'entrée Node": sh.node_entry.lock().unwrap().published_snapshot.is_some(),
        "erreur": snap.last_error,
        "restauration au démarrage": recovery,
    })
}

/// Points de la carte du dashboard.
pub fn map_points(sh: &Shared) -> Value {
    let s = sh.service.lock().unwrap();
    let d = sh.dispersal.try_lock().ok();
    let peers = d
        .as_ref()
        .map(|d| d.partnering.peers.clone())
        .unwrap_or_default();
    let black: std::collections::BTreeMap<String, (u64, String)> = d
        .as_ref()
        .map(|d| d.upkeep.blacklist.clone())
        .unwrap_or_default();
    drop(d);
    let addrs = sh.addrs.lock().unwrap();
    let mut points = Vec::new();
    let mut unlocated: std::collections::BTreeMap<&str, u64> = Default::default();
    let ip_of_addr = |a: &String| -> Option<String> {
        a.parse::<Multiaddr>().ok()?.iter().find_map(|p| match p {
            libp2p::multiaddr::Protocol::Ip4(v) => Some(v.to_string()),
            libp2p::multiaddr::Protocol::Ip6(v) => Some(v.to_string()),
            _ => None,
        })
    };
    let mut push = |kind: &'static str, ip: Option<String>, label: String, detail: String| {
        match ip.as_deref().and_then(|i| sh.geo.read().unwrap().locate(i)) {
            Some(p) => points.push(json!({ "kind": kind, "lat": p.lat, "lon": p.lon, "label": label,
                "detail": format!("{}{}{}", [p.city.as_str(), p.country.as_str()].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(", "), if detail.is_empty() { "" } else { " — " }, detail) })),
            None => *unlocated.entry(kind).or_default() += 1,
        }
    };
    let mut seen = std::collections::HashSet::new();
    for (n, (at, why)) in &black {
        seen.insert(n.clone());
        let ip = peers.get(n).map(|p| p.ip.clone()).filter(|i| !i.is_empty());
        push(
            "liste noire",
            ip,
            format!("{}…", &n[..16.min(n.len())]),
            format!("{why} depuis {at}"),
        );
    }
    for (id, p) in &s.partners {
        let n = hx(id);
        if !seen.insert(n.clone()) {
            continue;
        }
        let ip = addrs
            .get(id)
            .and_then(ip_of_addr)
            .or_else(|| peers.get(&n).map(|p| p.ip.clone()));
        push(
            "partenaire",
            ip,
            format!("{}…", &n[..16]),
            format!(
                "solde {} · confiés {}",
                p.allowance, p.ledger.hosted_for_partner
            ),
        );
    }
    for (n, p) in &peers {
        if seen.contains(n) || !(p.status == "candidat" || p.status == "terminé") {
            continue;
        }
        push(
            "candidat",
            Some(p.ip.clone()),
            format!("{}…", &n[..16.min(n.len())]),
            p.status.clone(),
        );
    }
    for id in s.users.keys() {
        push(
            "utilisateur",
            s.last_user_ip.get(id).cloned(),
            format!("{}…", &hx(id)[..16]),
            if s.auto_attached.contains(id) {
                "rattachement automatique".into()
            } else {
                String::new()
            },
        );
    }
    json!({ "points": points, "non_localises": unlocated, "geoip": sh.geo.read().unwrap().available(), "attribution": ATTRIBUTION })
}

fn dispersal_path(c: &Config) -> PathBuf {
    c.data_dir.join("dispersal.json")
}

/// Sauvegarde l'état de dispersion.
pub fn save_dispersal(c: &Config, st: &DispersalState) -> Result<(), DaemonError> {
    let tmp = dispersal_path(c).with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(st).expect("sérialisable"))?;
    std::fs::rename(&tmp, dispersal_path(c))?;
    Ok(())
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(format!("champ « {k} » manquant"))
}

fn number(v: &Value, k: &str) -> Result<u64, String> {
    match v.get(k) {
        Some(Value::Number(n)) => n.as_u64().ok_or(format!("« {k} » invalide")),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| format!("« {k} » invalide")),
        _ => Err(format!("champ « {k} » manquant")),
    }
}

/// Actions du dashboard Nœud.
pub fn act(sh: &Shared, name: &str, v: Value) -> Result<Value, String> {
    if name == "set_config" {
        return set_config(sh, &v);
    }
    if name == "regenerate_totp" {
        regenerate_totp(sh)?;
    }
    if name == "show_totp" || name == "regenerate_totp" {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        *sh.admin_reveal_until.lock().unwrap() = Some(now + 120);
        return Ok(json!({ "ok": true, "message": if name == "show_totp" {
            "QR code 2FA affiché pendant 2 minutes (section « administration à distance »)"
        } else {
            "Nouveau 2FA : scannez le nouveau QR code ; l'ancien et les sessions à distance ne valent plus"
        } }));
    }
    let mut s = sh.service.lock().unwrap();
    match name {
        "attach_user" => {
            let id = unhex32(field(&v, "user_id")?)?;
            let salt = hex::decode(field(&v, "salt")?).map_err(|e| e.to_string())?;
            if salt.len() != 16 {
                return Err("sel de 16 octets attendu".into());
            }
            let quota_bytes = number(&v, "quota_bytes")?;
            let e = s.users.entry(id).or_insert(UserAccount {
                salt: salt.clone(),
                quota_bytes,
                used_bytes: 0,
                root: [0; 32],
            });
            e.salt = salt;
            e.quota_bytes = quota_bytes;
        }
        "add_partner" => {
            let id = unhex32(field(&v, "node_id")?)?;
            let blacklisted = sh
                .dispersal
                .try_lock()
                .map(|d| d.upkeep.is_blacklisted(&id))
                .map_err(|_| "cycle de contrôle en cours, réessayez dans un instant".to_string())?;
            if blacklisted {
                return Err("partenaire en liste noire (fraude PoS) : refusé".into());
            }
            let addr = field(&v, "addr")?;
            addr.parse::<Multiaddr>().map_err(|e| e.to_string())?;
            let allowance = number(&v, "allowance")?;
            s.partners.entry(id).or_default().allowance = allowance;
            sh.addrs.lock().unwrap().insert(id, addr.to_string());
        }
        "set_quota" => {
            let id = unhex32(field(&v, "user_id")?)?;
            let q = number(&v, "quota_bytes")?;
            s.users
                .get_mut(&id)
                .ok_or("utilisateur inconnu")?
                .quota_bytes = q;
        }
        "set_attach_policy" => {
            let yes = |x: &str| {
                matches!(
                    x.trim().to_lowercase().as_str(),
                    "oui" | "true" | "1" | "yes"
                )
            };
            let mut p = s.attach_policy;
            if let Some(b) = v.get("enabled").and_then(|x| x.as_bool()) {
                p.enabled = b;
            } else if let Ok(e) = field(&v, "enabled") {
                if !e.trim().is_empty() {
                    p.enabled = yes(e);
                }
            }
            if let Ok(q) = number(&v, "quota_bytes") {
                p.quota_bytes = q;
            }
            if let Ok(m) = number(&v, "max_users") {
                p.max_users = m as usize;
            }
            if let Ok(b) = number(&v, "budget_bytes") {
                p.budget_bytes = b;
            }
            s.attach_policy = p;
        }
        _ => return Err(format!("action inconnue : {name}")),
    }
    drop(s);
    save(sh).map_err(|e| e.to_string())?;
    let message = match name {
        "attach_user" => "Utilisateur rattaché",
        "add_partner" => "Partenaire ajouté",
        "set_quota" => "Quota modifié",
        _ => "Rattachement automatique enregistré",
    };
    Ok(json!({ "ok": true, "message": message }))
}

fn state_path(c: &Config) -> PathBuf {
    c.data_dir.join("state.json")
}

/// Sauvegarde l'état courant.
pub fn save(sh: &Shared) -> Result<(), DaemonError> {
    let st = SavedState::capture(&sh.service.lock().unwrap(), &sh.addrs.lock().unwrap());
    save_state(&state_path(&sh.config), &st)
}

/// Démarre le Nœud ; rend le contexte et l'URL du dashboard.
pub async fn start(config: Config) -> Result<(Arc<Shared>, String), DaemonError> {
    let switch = crate::local_http::Switch::new();
    let url = switch.serve(config.api_port, ASSETS).await?;
    let sh = start_with(config, &switch).await?;
    Ok((sh, url))
}

/// Secret TOTP courant du Nœud.
pub fn admin_secret(sh: &Shared) -> Option<[u8; 20]> {
    let serial = sh.admin_serial.load(std::sync::atomic::Ordering::SeqCst);
    s3m_core::symmetric_suite::derive_admin_totp_secret(&sh.priv_node, serial).ok()
}

/// Démarre le Nœud derrière le dashboard `switch` (déjà servi).
pub async fn start_with(
    config: Config,
    switch: &Arc<crate::local_http::Switch>,
) -> Result<Arc<Shared>, DaemonError> {
    let start = |e: &dyn std::fmt::Display| DaemonError::Start(e.to_string());
    let mnemonic = std::fs::read_to_string(&config.seed_file)?;
    let seed = node_seed_from_mnemonic(&mnemonic, config.identity_index)?;
    let recovery_pub = node_recovery_pub(&mnemonic, config.identity_index)?;
    std::fs::create_dir_all(&config.data_dir)?;
    let volumes = config
        .volumes
        .iter()
        .map(|v| VolumeConfig {
            volume_id: v.volume_id,
            mount_path: v.mount_path.clone(),
            max_capacity_bytes: v.max_capacity_bytes,
        })
        .collect();
    let store = PhysicalStore::open(config.data_dir.join("store.sqlite"), volumes)
        .map_err(|e| start(&e))?;
    let mut service = NodeService::with_store(seed, Box::new(store));
    service.attach_policy = config.attach;
    service.partner_policy = config.partner_policy;
    service.record_user_ips = config.record_user_ips;
    let vdf = chiavdf_verifier();
    let check: VdfCheck = Arc::new(move |id, proof| vdf(id, proof).unwrap_or(false));
    service.vdf = Some(check);
    let addrs = load_state(&state_path(&config))?
        .restore(&mut service)
        .map_err(DaemonError::Config)?;
    let service = Arc::new(Mutex::new(service));
    let fresh = !state_path(&config).exists() && !dispersal_path(&config).exists();
    let mut dispersal: DispersalState = match std::fs::read(dispersal_path(&config)) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| DaemonError::Config(e.to_string()))?,
        Err(_) => DispersalState::default(),
    };
    reconcile(&service, &mut dispersal, system_clock()());

    let parse = |s: &str| {
        s.parse::<Multiaddr>()
            .map_err(|e| DaemonError::Config(format!("{s} : {e}")))
    };
    // Pile réseau unique (DHT, échange de blocs, traversée de NAT).
    let listen = config
        .listen_addrs()
        .iter()
        .map(|s| parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    let node_net = crate::net::start(NetConfig {
        node_seed: seed,
        listen,
        bootstrap: config
            .bootstrap
            .iter()
            .map(|b| parse(b))
            .collect::<Result<_, _>>()?,
        vdf: chiavdf_verifier(),
        clock: system_clock(),
        service: service.clone(),
        upnp: config.upnp,
        relay_server: config.relay_server,
        relay_limits: config.relay_limits,
        relays: config
            .relays
            .iter()
            .map(|r| parse(r))
            .collect::<Result<_, _>>()?,
        force_relay: config.force_relay,
        external: declared_external(&config),
        assume_listen_public: false,
        mdns: config.mdns,
    })
    .await
    .map_err(|e| start(&e))?;
    let (dht, blocks, nat) = (node_net.dht, node_net.blocks, node_net.nat);

    // Installation vide : restauration depuis le réseau (seed seule).
    let restored = Arc::new(Mutex::new(HashMap::new()));
    let mut recovery_report = None;
    if fresh && !config.dht_bootstrap_is_empty() {
        let attempt = tokio::time::timeout(
            Duration::from_secs(300),
            recover(
                &service,
                &mut dispersal,
                &blocks,
                &dht,
                &config.dispersal,
                &restored,
                system_clock()(),
            ),
        )
        .await;
        recovery_report = Some(match attempt {
            Err(_) => json!({ "erreur": "délai dépassé" }),
            Ok(Err(e)) => json!({ "erreur": e }),
            Ok(Ok(r)) => json!({ "utilisateurs": r.users, "partenaires": r.partners,
                "stripes": r.stripes, "blocs reconstruits": r.blocks, "erreurs": r.errors }),
        });
    }
    let mut addrs = addrs;
    addrs.extend(restored.lock().unwrap().drain());
    let initial_pointer = dispersal
        .snapshot
        .pointer
        .as_deref()
        .and_then(|p| hex::decode(p).ok());
    let shared = Arc::new(Shared {
        service,
        addrs: Arc::new(Mutex::new(addrs)),
        excluded: Arc::new(Mutex::new(Default::default())),
        nat: nat.clone(),
        geo: std::sync::RwLock::new(Geo::open(&config.data_dir.join(DB_FILE))),
        geoip: Mutex::new(GeoipState::default()),
        last_partnering: Mutex::new(None),
        dispersal: tokio::sync::Mutex::new(dispersal),
        last_cycle: Mutex::new(None),
        last_upkeep: Mutex::new(None),
        node_entry: Arc::new(Mutex::new(NodeEntryState::default())),
        snapshot_pointer: Mutex::new(initial_pointer),
        recovery: Mutex::new(recovery_report),
        peer_id: blocks.peer_id().to_string(),
        blocks_addr: blocks.listen_addr().await.map(|a| a.to_string()),
        dht_addr: dht.listen_addr().await.map(|a| a.to_string()),
        config: config.clone(),
        priv_node: seed,
        admin_serial: std::sync::atomic::AtomicU32::new(config.admin_totp_serial),
        admin_reveal_until: Mutex::new(None),
        admin: Mutex::new(None),
    });

    let clock = system_clock();
    let st_fn: StatusFn = {
        let (sh, clock) = (shared.clone(), clock.clone());
        Arc::new(move || status(&sh, clock()))
    };
    let act_fn: ActionFn = {
        let sh = shared.clone();
        Arc::new(move |n, v| {
            if n == "geoip_update" {
                return geoip_update(sh.clone());
            }
            act(&sh, n, v)
        })
    };
    let map_fn: StatusFn = {
        let sh = shared.clone();
        Arc::new(move || map_points(&sh))
    };
    switch.set(st_fn, act_fn, Some(map_fn));
    if config.remote_admin {
        let sh = shared.clone();
        let secret: crate::admin::SecretFn = Arc::new(move || admin_secret(&sh));
        let key = libp2p::identity::Keypair::ed25519_from_bytes(seed).map_err(|e| start(&e))?;
        match crate::admin::serve(
            key,
            &config.admin_listen,
            false,
            crate::admin::Mode::Node { secret },
            switch.status_fn(),
            switch.action_fn(),
            Some(switch.map_fn()),
        )
        .await
        {
            Ok(s) => *shared.admin.lock().unwrap() = Some(s),
            Err(e) => eprintln!("administration à distance indisponible : {e}"),
        }
    }

    // Tâches périodiques : dispersion et sauvegarde (30 s), pointeurs de
    // migration (1 h), purge des Nœuds silencieux (1 j).
    let fabric = NetFabric {
        server: Arc::new(blocks),
        dht: Arc::new(dht),
        service: shared.service.clone(),
        addrs: shared.addrs.clone(),
        excluded: shared.excluded.clone(),
    };
    // Entrée DHT Node : preuve VDF (une fois), publication, republication.
    {
        let (sh, dht, clock) = (shared.clone(), fabric.dht.clone(), clock.clone());
        let pub_node = shared.service.lock().unwrap().node_id();
        tokio::spawn(async move {
            let cache = sh.config.data_dir.join("vdf_proof.bin");
            let proof = match ensure_node_proof(&cache, &pub_node).await {
                Ok(p) => p,
                Err(e) => {
                    sh.node_entry.lock().unwrap().proof_error = Some(e);
                    return;
                }
            };
            sh.node_entry.lock().unwrap().proof_ready = true;
            loop {
                let (direct, addrs) = {
                    let n = sh.nat.lock().unwrap();
                    (announced_direct(&sh.config, &n), n.announced())
                };
                if direct.is_none() && addrs.is_empty() {
                    sh.node_entry.lock().unwrap().last_error = Some(
                        "aucune adresse joignable encore (public_ip, UPnP ou relais en attente)"
                            .into(),
                    );
                } else {
                    let snapshot = sh.snapshot_pointer.lock().unwrap().clone();
                    publish_entry(
                        &dht,
                        &seed,
                        &pub_node,
                        &recovery_pub,
                        direct,
                        addrs,
                        &proof,
                        snapshot,
                        &sh.node_entry,
                        clock(),
                    )
                    .await;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }
    let sh = shared.clone();
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            tick += 1;
            {
                let now = clock();
                let mut d = sh.dispersal.lock().await;
                // Partenariats automatiques, puis exclusions de placement.
                sh.service.lock().unwrap().blacklisted = d
                    .upkeep
                    .blacklist
                    .keys()
                    .filter_map(|n| hex::decode(n).ok()?.try_into().ok())
                    .collect();
                let own_entry = sh.node_entry.lock().unwrap().last_envelope.clone();
                let target = sh.config.dispersal.k * sh.config.dispersal.coef + 4;
                let net = Net {
                    server: &fabric.server,
                    dht: &fabric.dht,
                    addrs: &sh.addrs,
                    own_entry,
                };
                let pr = run_partnering(
                    &sh.service,
                    &mut d,
                    &net,
                    &sh.config.partnering,
                    target,
                    now,
                )
                .await;
                *sh.last_partnering.lock().unwrap() = Some((now, pr));
                *sh.excluded.lock().unwrap() = excluded(&sh.config.partnering, &d);
                let up = run_upkeep(
                    &sh.service,
                    &mut d,
                    &fabric,
                    &sh.config.dispersal,
                    &sh.config.upkeep,
                    now,
                )
                .await;
                *sh.last_upkeep.lock().unwrap() = Some((now, up));
                let report =
                    run_cycle(&sh.service, &mut d, &fabric, &sh.config.dispersal, now).await;
                if run_snapshot(&sh.service, &mut d, &fabric, &sh.config.dispersal, now).await {
                    *sh.snapshot_pointer.lock().unwrap() = d
                        .snapshot
                        .pointer
                        .as_deref()
                        .and_then(|p| hex::decode(p).ok());
                }
                if let Err(e) = save_dispersal(&sh.config, &d) {
                    eprintln!("sauvegarde de la dispersion : {e}");
                }
                *sh.last_cycle.lock().unwrap() = Some((now, report));
            }
            if tick.is_multiple_of(120) {
                let _ = refresh_successors(&sh.service, &fabric.dht).await;
            }
            if tick.is_multiple_of(2880) {
                let now = clock();
                sh.service.lock().unwrap().purge_silent_partners(now);
            }
            if let Err(e) = save(&sh) {
                eprintln!("sauvegarde de l'état : {e}");
            }
        }
    });
    Ok(shared)
}
