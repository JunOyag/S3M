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
use crate::geo::Geo;
use crate::local_http::{ActionFn, Asset, StatusFn};
use crate::net::{NatState, NetConfig, RelayLimits};
use crate::partnering::{excluded, run_partnering, score, Net, PartneringConfig, PartneringReport};
use crate::publish::{ensure_node_proof, publish_entry, NodeEntryState};
use crate::recovery::{RestoreState, SnapshotOutcome, UserOrigin};
use crate::snapshot_engine::run_snapshot;
use crate::tombstones::PartnerLedger;
use crate::upkeep::{run_upkeep, UpkeepConfig, UpkeepReport};
use crate::VolumeConfig;

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
    /// En vidage avant retrait (`protocols.gestion-volumes`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub draining: bool,
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
    /// Conservation des versions passées des fichiers (jours ; 0 : aucune,
    /// `protocols.historique-versions`).
    #[serde(default = "default_history_days")]
    pub history_days: u64,
    /// Alertes critiques hors tableau de bord (`deploiement.packaging#alertes`).
    #[serde(default)]
    pub alerts: crate::alerts::AlertConfig,
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

fn default_history_days() -> u64 {
    crate::exchange::HISTORY_DAYS
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
    /// Descripteur scellé de la racine (`crypto.k-self#k-root`).
    #[serde(default)]
    pub root_seal: String,
    /// Dernière activité (`protocols.partenariat-automatique#inactivite`).
    #[serde(default)]
    pub last_active: u64,
    /// Durée d'inactivité propre (jours, 0 : éternel).
    #[serde(default)]
    pub inactivity_days: Option<u64>,
    /// Versions passées `(racine, descripteur, validée le, remplacée le)`.
    #[serde(default)]
    pub history: Vec<(String, String, u64, u64)>,
    #[serde(default)]
    pub root_since: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedPartner {
    pub node_id: String,
    #[serde(default)]
    pub addr: Option<String>,
    pub hosted_for_partner: u64,
    pub hosted_by_partner: u64,
    pub last_tombstone_at: u64,
    pub last_seen: u64,
    /// Échange sur l'offre (`node.PartnerAccount#equilibre`).
    #[serde(default)]
    pub quota: u64,
    #[serde(default)]
    pub trust: u64,
    #[serde(default)]
    pub trust_since: u64,
    #[serde(default)]
    pub proved_at: u64,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub suspended_until: u64,
    /// Début de la dernière maintenance qu'il a déclarée.
    #[serde(default)]
    pub maint_since: u64,
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
    /// Réserve de secours (limites et déposants accueillis).
    #[serde(default)]
    pub emergency: Option<crate::emergency::EmergencyReserve>,
    /// Canal Nœud ↔ Utilisateurs (clé d'annonce, messages).
    #[serde(default)]
    pub channel: Option<crate::channel::Channel>,
    /// Nom publié du Nœud (`deploiement.pseudos`).
    #[serde(default)]
    pub name: Option<String>,
    /// `(user_id, étiquette)` locales.
    #[serde(default)]
    pub user_labels: Vec<(String, String)>,
    /// Partages retirés (`protocols.partage`).
    #[serde(default)]
    pub revoked_shares: Vec<String>,
    /// Blocs libérés par leur Utilisateur : `(utilisateur, hash, instant)`.
    #[serde(default)]
    pub released: Vec<(String, String, u64)>,
    /// Instant de l'enregistrement (temps d'arrêt rendu aux Utilisateurs).
    #[serde(default)]
    pub saved_at: u64,
    /// Identités révoquées après rotation.
    #[serde(default)]
    pub revoked_users: Vec<String>,
    /// Gel des suppressions après un saut d'horloge.
    #[serde(default)]
    pub clock_freeze: Option<crate::clock_guard::Freeze>,
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
                root_seal: s.root_seals.get(id).map(|v| hx(v)).unwrap_or_default(),
                last_active: s.last_active.get(id).copied().unwrap_or(0),
                inactivity_days: s.inactivity_days.get(id).copied(),
                history: s
                    .root_history
                    .get(id)
                    .map(|h| {
                        h.iter()
                            .map(|v| (hx(&v.root), hx(&v.root_seal), v.valid_from, v.replaced_at))
                            .collect()
                    })
                    .unwrap_or_default(),
                root_since: s.root_since.get(id).copied().unwrap_or(0),
            })
            .collect();
        users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        let mut partners: Vec<SavedPartner> = s
            .partners
            .iter()
            .map(|(id, p)| SavedPartner {
                node_id: hx(id),
                addr: addrs.get(id).cloned(),
                hosted_for_partner: p.ledger.hosted_for_partner,
                hosted_by_partner: p.ledger.hosted_by_partner,
                last_tombstone_at: p.ledger.last_tombstone_at,
                last_seen: p.last_seen,
                quota: p.quota,
                trust: p.trust,
                trust_since: p.trust_since,
                proved_at: p.proved_at,
                failures: p.failures,
                suspended_until: p.suspended_until,
                maint_since: p.maint_since,
            })
            .collect();
        partners.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Self {
            saved_at: system_clock()(),
            revoked_users: sorted(s.revoked_users.iter().map(|i| hx(i))),
            clock_freeze: s.clock_freeze.clone(),
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
            emergency: Some(s.emergency.clone()),
            channel: Some(s.channel.clone()),
            name: s.name.clone(),
            user_labels: sorted_pairs(&s.user_labels),
            revoked_shares: sorted(s.revoked_shares.iter().map(|x| hx(x))),
            released: {
                let mut v: Vec<(String, String, u64)> = s
                    .released
                    .iter()
                    .flat_map(|(u, m)| m.iter().map(move |(h, t)| (hx(u), hx(h), *t)))
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
            if let Ok(v) = hex::decode(&u.root_seal) {
                if !v.is_empty() {
                    s.root_seals.insert(unhex32(&u.user_id)?, v);
                }
            }
            if u.last_active > 0 {
                s.last_active.insert(unhex32(&u.user_id)?, u.last_active);
            }
            if let Some(d) = u.inactivity_days {
                s.inactivity_days.insert(unhex32(&u.user_id)?, d);
            }
            if !u.history.is_empty() {
                let h = u
                    .history
                    .iter()
                    .map(|(r, seal, from, at)| s3m_protocol::exchange::RootVersion {
                        root: hex::decode(r).unwrap_or_default(),
                        root_seal: hex::decode(seal).unwrap_or_default(),
                        valid_from: *from,
                        replaced_at: *at,
                    })
                    .collect();
                s.root_history.insert(unhex32(&u.user_id)?, h);
            }
            if u.root_since > 0 {
                s.root_since.insert(unhex32(&u.user_id)?, u.root_since);
            }
        }
        for p in &self.partners {
            let id = unhex32(&p.node_id)?;
            if let Some(a) = &p.addr {
                addrs.insert(id, a.clone());
            }
            s.partners.insert(
                id,
                PartnerState {
                    ledger: PartnerLedger {
                        hosted_for_partner: p.hosted_for_partner,
                        hosted_by_partner: p.hosted_by_partner,
                        last_tombstone_at: p.last_tombstone_at,
                    },
                    last_seen: p.last_seen,
                    quota: p.quota,
                    trust: p.trust,
                    trust_since: p.trust_since,
                    proved_at: p.proved_at,
                    failures: p.failures,
                    suspended_until: p.suspended_until,
                    negotiated_at: 0,
                    maint_since: p.maint_since,
                    maint_last: p.maint_since,
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
        if let Some(e) = &self.emergency {
            s.emergency = e.clone();
        }
        if let Some(c) = &self.channel {
            s.channel = c.clone();
        }
        s.name = self.name.clone();
        for (u, l) in &self.user_labels {
            s.user_labels.insert(unhex32(u)?, l.clone());
        }
        for (u, h, t) in &self.released {
            s.released
                .entry(unhex32(u)?)
                .or_default()
                .insert(unhex32(h)?, *t);
        }
        for x in &self.revoked_shares {
            s.revoked_shares.insert(unhex32(x)?);
        }
        for u in &self.auto_attached {
            s.auto_attached.insert(unhex32(u)?);
        }
        for u in &self.revoked_users {
            s.revoked_users.insert(unhex32(u)?);
        }
        s.clock_freeze = self.clock_freeze.clone();
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

fn sorted_pairs(m: &HashMap<[u8; 32], String>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = m.iter().map(|(k, l)| (hx(k), l.clone())).collect();
    v.sort();
    v
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
    /// Précision obtenue lors de la dernière réussite (repli éventuel).
    pub note: Option<String>,
}

/// Espace de secours vu du dashboard (`protocols.espace-secours`).
#[derive(Default)]
pub struct EmergencyUi {
    /// Dernière séquence d'entrée de secours entièrement intégrée, par Utilisateur.
    pub seen: HashMap<[u8; 32], u64>,
    /// Dernier tour d'intégration au retour : `(instant, bilan)`.
    pub last: Option<(u64, crate::emergency::ReturnReport)>,
    /// Dépôts oubliés purgés depuis le démarrage.
    pub purged: usize,
}

/// Gestion des volumes vue du dashboard (`protocols.gestion-volumes`).
#[derive(Default)]
pub struct VolumesUi {
    /// Liste des actions saisies, appliquées d'un coup.
    pub draft: Vec<crate::volumes::Change>,
    pub imports: std::collections::BTreeMap<u32, crate::volumes::ImportCounts>,
    /// Journal : `(instant Unix, action)`.
    pub events: Vec<(u64, String)>,
}

impl VolumesUi {
    pub fn log(&mut self, e: String) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.events.push((now, e));
        if self.events.len() > 1000 {
            self.events.remove(0);
        }
    }
}

/// Contexte partagé par le dashboard et les tâches.
pub struct Shared {
    pub service: Arc<Mutex<NodeService>>,
    pub addrs: Arc<Mutex<HashMap<[u8; 32], String>>>,
    pub dispersal: tokio::sync::Mutex<DispersalState>,
    /// Dernier cycle de dispersion : `(instant, bilan)`.
    pub last_cycle: Mutex<Option<(u64, CycleReport)>>,
    /// Dernier taux de redondance calculé `(global, plus faible stripe)`,
    /// gardé pendant un cycle de dispersion.
    pub last_redundancy: Mutex<Option<(f64, f64)>>,
    /// Dernier cycle de contrôle : `(instant, bilan)`.
    pub last_upkeep: Mutex<Option<(u64, UpkeepReport)>>,
    /// Canaux d'alerte (modifiables à chaud) et alertes déjà envoyées.
    pub alert_cfg: Mutex<crate::alerts::AlertConfig>,
    pub alerts_sent: Mutex<std::collections::BTreeMap<String, u64>>,
    /// Entrée DHT Node.
    pub node_entry: Arc<Mutex<NodeEntryState>>,
    /// `NodeSnapshotPointer` courant (sérialisé).
    pub snapshot_pointer: Mutex<Option<Vec<u8>>>,
    /// Résultat de la restauration au démarrage, s'il y en a eu une.
    /// Restauration automatique (`deploiement.disaster-recovery`), si une
    /// a eu lieu ou est en cours.
    pub restore: Mutex<Option<RestoreState>>,
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
    /// Brouillon et suivi de la gestion des volumes.
    pub volumes_ui: Mutex<VolumesUi>,
    /// Nœuds à retirer de la liste noire (dashboard), appliqués au prochain
    /// tour si l'état de dispersion est occupé.
    pub unblacklist: Mutex<Vec<String>>,
    /// Redémarrage demandé depuis le dashboard (traité par l'exécutable).
    pub restart: tokio::sync::Notify,
    /// Journal du processus : `(instant Unix, événement)`, borné.
    pub journal: Mutex<Vec<(u64, String)>>,
    pub emergency_ui: Mutex<EmergencyUi>,
    pub peer_id: String,
    pub blocks_addr: Option<String>,
    pub dht_addr: Option<String>,
}

/// État présenté par le dashboard Nœud.
pub fn status(sh: &Shared, now: u64) -> Value {
    let mut v = status_base(sh, now);
    let (forms, pending) = config_forms(sh);
    if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
        a.push(json!({ "nom": "restart_node", "titre": "Redémarrage",
            "libellé": "Redémarrer le Nœud", "champs": [],
            "confirmer": "Redémarrer le Nœud ? Il est indisponible quelques secondes ; l'état est enregistré avant l'arrêt. Le tableau de bord se recharge ensuite." }));
        a.push(json!({ "nom": "test_alerts", "titre": "Alertes", "style": "secondary",
            "libellé": "Envoyer une alerte d'essai", "champs": [],
            "texte": "Envoie une alerte d'essai sur les canaux configurés (onglet Alertes de la configuration) : fenêtre, webhook, courriel." }));
        a.push(json!({ "nom": "geoip_update", "titre": "Géolocalisation",
            "libellé": "Mettre à jour la base de géolocalisation", "champs": [] }));
        a.extend(forms);
    }
    v["géolocalisation"] = geoip_status(sh);
    v["journal"] = journal_rows(sh);
    v["republication DHT"] = republication_status(sh);
    volumes_status(sh, &mut v);
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
    // Défaillances matérielles des volumes : alerte à l'opérateur.
    let faults = disk_alerts(sh);
    let n_faults = faults.len();
    if n_faults > 0 {
        let first = faults[0]["alerte"].as_str().unwrap_or("").to_string();
        v["alertes matérielles"] = json!(faults);
        if let Some(cards) = v["résumé"].as_array_mut() {
            cards.insert(0, json!({ "libellé": "Disques", "valeur": format!("{n_faults} alerte(s)"),
                "détail": first, "état": "probleme", "page": "accueil" }));
        }
    }
    let freeze = sh.service.lock().unwrap().clock_freeze.clone();
    if let Some(f) = &freeze {
        let text = crate::clock_guard::describe(f);
        v["horloge"] = json!({
            "_contenu": { "alerte": text, "détectée le": format!("le {}", f.at), "heure actuelle de la machine": format!("le {}", system_clock()()) },
            "_formulaires": [{ "nom": "clock_confirm", "libellé": "L'heure est juste : reprendre", "champs": [],
                "confirmer": "L'heure affichée par cette machine est-elle juste ? Les suppressions liées au temps reprendront aussitôt (utilisateurs inactifs, versions expirées, partenaires silencieux, dépôts de secours)." }],
        });
        if let Some(cards) = v["résumé"].as_array_mut() {
            cards.insert(0, json!({ "libellé": "Horloge", "valeur": "à vérifier", "détail": text, "état": "probleme", "page": "accueil" }));
        }
        v["à signaler"] = json!(format!("Horloge à vérifier : {text}"));
    }
    let in_maintenance = sh.service.lock().unwrap().maintenance;
    if in_maintenance {
        let m = v.pointer("/contrôles et réparation/maintenance").cloned().unwrap_or(Value::Null);
        v["maintenance"] = m.clone();
        if let Some(cards) = v["résumé"].as_array_mut() {
            cards.insert(0, json!({ "libellé": "Maintenance", "valeur": format!("{} / {} blocs reconstruits",
                m["blocs reconstruits"].as_u64().unwrap_or(0), m["blocs d'Utilisateurs perdus"].as_u64().unwrap_or(0)),
                "détail": "Stockage perdu : reconstruction depuis le réseau", "état": "probleme", "page": "accueil" }));
        }
    }
    // Signalé une fois à l'ouverture du tableau de bord, et en bandeau sur
    // la page Messages.
    let unread = sh.service.lock().unwrap().channel.inbox.unread(None);
    if unread > 0 {
        if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
            a.push(json!({ "nom": "mark_all_user_messages_read", "mise_en_avant": true,
                "titre": format!("{unread} message{} d'utilisateur non lu{}", if unread > 1 { "s" } else { "" }, if unread > 1 { "s" } else { "" }),
                "texte": "Cliquez sur une conversation pour la lire, ou marquez tout comme lu.",
                "libellé": "Tout marquer comme lu", "style": "secondary", "champs": [] }));
        }
        v["à signaler"] = json!(format!(
            "{unread} message{} d'utilisateur non lu{} : page Messages",
            if unread > 1 { "s" } else { "" },
            if unread > 1 { "s" } else { "" }
        ));
    }
    if n_faults > 0 {
        v["à signaler"] = json!(format!(
            "Alerte disque : {n_faults} défaillance(s) de volume — voir la vue d'ensemble, section « Alertes matérielles »"
        ));
    }
    v["pages"] = json!([
        { "id": "accueil", "titre": "Vue d'ensemble", "résumé": true, "carte": true,
          "sections": ["horloge", "alertes matérielles", "maintenance", "restauration", "alertes d'intégrité signalées", "identité"], "actions": ["set_node_name", "restart_node"] },
        { "id": "utilisateurs", "titre": "Utilisateurs",
          "sections": ["utilisateurs rattachés", "rattachement automatique"],
          "actions": ["attach_user", "set_attach_policy"] },
        { "id": "partenaires", "titre": "Partenaires", "carte": true,
          "sections": ["partenaires", "recherche de partenaires"], "actions": ["add_partner"] },
        { "id": "carte", "titre": "Carte du monde", "cadre": "map.html", "sections": [], "actions": [] },
        { "id": "volumes", "titre": "Volumes",
          "sections": ["volumes", "liste des actions", "imports de volumes", "journal des volumes"],
          "actions": ["volume_apply", "volume_draft_clear"] },
        { "id": "stockage", "titre": "Stockage et protection",
          "sections": ["dispersion", "contrôles et réparation", "snapshot du nœud"], "actions": [] },
        { "id": "messages", "titre": "Messages",
          "sections": ["messages des utilisateurs", "messages envoyés", "clé d'annonce"],
          "actions": ["mark_all_user_messages_read", "send_message", "create_announce_key", "replace_announce_key", "send_alert"] },
        { "id": "secours", "titre": "Espace de secours",
          "sections": ["espace de secours"], "actions": ["set_emergency_policy"] },
        { "id": "reseau", "titre": "Réseau",
          "sections": ["traversée de NAT", "annuaire (entrée Node)", "republication DHT", "géolocalisation"], "actions": ["geoip_update"] },
        { "id": "distance", "titre": "Administration à distance",
          "sections": ["administration à distance"], "actions": ["show_totp", "regenerate_totp"] },
        { "id": "configuration", "titre": "Configuration", "sections": ["configuration"], "actions": ["set_config", "test_alerts"], "onglets": true },
        { "id": "diagnostic", "titre": "Diagnostic", "autres": true, "sections": [], "actions": [],
          "onglets de sections": [{ "titre": "Général", "sections": ["migration"] },
                                  { "titre": "Avancé", "sections": ["journal"] }] }
    ]);
    simple_pages(&mut v);
    v
}

/// Mode simple (`deploiement.packaging#modes`) : cinq écrans, voyants de
/// santé, tableau des utilisateurs réduit, guide de remplacement d'un
/// disque, réglages essentiels. Le mode expert garde tous les écrans.
fn simple_pages(v: &mut Value) {
    let voyant = |ok: Option<bool>, quoi: &str, etat: String, faire: &str| {
        json!({ "": match ok { Some(true) => "🟢", Some(false) => "🔴", None => "🟠" },
                "domaine": quoi, "état": etat, "que faire": faire })
    };
    let alerts = v["alertes matérielles"].as_array().map_or(0, |a| a.len());
    let disks = if alerts > 0 {
        voyant(Some(false), "Disques", format!("{alerts} alerte(s) : {}", v["alertes matérielles"][0]["alerte"].as_str().unwrap_or("")),
            "Voir les alertes ci-dessus, puis l'écran Disques.")
    } else if v.get("maintenance").is_some_and(|m| !m.is_null()) {
        voyant(None, "Disques", "maintenance en cours : reconstruction depuis le réseau".into(), "Rien à faire : le Nœud répare seul.")
    } else {
        voyant(Some(true), "Disques", "en bon état".into(), "")
    };
    let reach = v.pointer("/traversée de NAT/joignabilité").and_then(|x| x.as_str()).unwrap_or("inconnue").to_string();
    let net_ok = reach.contains("public") || reach.contains("direct");
    let net = voyant(
        if net_ok { Some(true) } else if reach == "inconnue" { None } else { Some(false) },
        "Réseau",
        format!("joignabilité : {reach}"),
        if net_ok { "" } else { "Vérifiez la connexion Internet ; derrière une box, l'ouverture automatique du port (UPnP) aide les autres Nœuds à vous joindre." },
    );
    let partners = v["partenaires"].as_array().map_or(0, |a| a.len());
    let wanted = v.pointer("/recherche de partenaires/partenaires visés").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let part = voyant(
        Some(partners >= wanted.clamp(1, 4)),
        "Partenaires",
        format!("{partners} partenaire(s) gardent vos copies de secours (objectif : {wanted})"),
        if partners == 0 { "Le Nœud cherche des partenaires tout seul ; laissez-le connecté." } else { "" },
    );
    let users: Vec<Value> = v["utilisateurs rattachés"].as_array().cloned().unwrap_or_default();
    let soon = users.iter().filter(|u| u["jours avant suppression"].as_u64().is_some_and(|d| d <= 30)).count();
    let usr = voyant(
        Some(soon == 0),
        "Utilisateurs",
        format!("{} utilisateur(s){}", users.len(), if soon > 0 { format!(", dont {soon} supprimé(s) dans moins de 30 jours faute de connexion") } else { String::new() }),
        if soon > 0 { "Écran Utilisateurs : prévenez-les, ou rendez-les éternels (Éditer)." } else { "" },
    );
    v["santé du nœud"] = json!([disks, net, part, usr]);
    v["mes utilisateurs"] = json!(users
        .iter()
        .map(|u| json!({
            "nom": u["nom"], "espace utilisé (octets)": u["utilisé (octets)"], "quota (octets)": u["quota (octets)"],
            "dernière activité": u["dernière activité"], "jours avant suppression": u["jours avant suppression"],
            "_gras": u["_gras"], "_actions": u["_actions"],
        }))
        .collect::<Vec<_>>());
    v["remplacer un disque"] = json!({
        "_contenu": {
            "1": "Branchez le nouveau disque et créez-y un dossier vide (par exemple E:\\S3m).",
            "2": "Ci-dessus, « Ajouter un volume » avec ce dossier, puis « Appliquer » : le Nœud y range désormais les nouveaux blocs.",
            "3": "Sur l'ancien disque : « Retirer » s'il est encore lisible (ses blocs sont déplacés), ou « Déclarer perdu » s'il est hors d'usage (ses blocs sont reconstruits depuis le réseau), puis « Appliquer ».",
            "4": "Attendez la fin (journal des volumes, mode expert) avant de débrancher l'ancien disque.",
        },
    });
    v["réglages essentiels"] = json!({
        "_contenu": {
            "nom du nœud": v.pointer("/identité/nom"),
            "accueil automatique des utilisateurs": v.pointer("/rattachement automatique/activé"),
            "_note": "Tous les réglages (espace offert aux partenaires, réseau, alertes par courriel ou webhook…) : passez en mode expert, écran Configuration.",
        },
    });
    v["pages simples"] = json!([
        { "id": "accueil", "titre": "Accueil",
          "sections": ["horloge", "alertes matérielles", "maintenance", "santé du nœud", "identité"], "actions": ["restart_node"] },
        { "id": "utilisateurs", "titre": "Utilisateurs", "sections": ["mes utilisateurs"], "actions": ["attach_user"] },
        { "id": "volumes", "titre": "Disques", "sections": ["alertes matérielles", "volumes", "liste des actions", "remplacer un disque"],
          "actions": ["volume_apply", "volume_draft_clear"] },
        { "id": "messages", "titre": "Messages", "sections": ["messages des utilisateurs", "messages envoyés"],
          "actions": ["mark_all_user_messages_read", "send_message"] },
        { "id": "reglages", "titre": "Réglages essentiels", "sections": ["réglages essentiels"],
          "actions": ["set_node_name", "set_attach_policy", "test_alerts"] }
    ]);
}

/// Indicateurs de la vue d'ensemble (`état` : ok, attention, probleme, neutre).
/// Messages reçus regroupés par utilisateur : une ligne par conversation,
/// ouverte en panneau (messages reçus et réponses adressées, réponse,
/// suppression) ; l'ouverture marque la conversation lue.
fn user_conversations(s: &NodeService) -> Vec<Value> {
    use std::collections::BTreeMap;
    let mut by_user: BTreeMap<[u8; 32], Vec<&s3m_protocol::message::UserMessage>> = BTreeMap::new();
    for m in &s.channel.inbox.received {
        by_user.entry(m.user_id).or_default().push(m);
    }
    let mut rows: Vec<(u64, Value)> = by_user
        .into_iter()
        .map(|(u, msgs)| {
            let who = s3m_protocol::pseudo::display(&[s.user_labels.get(&u).map(String::as_str)], &u);
            let unread = msgs.iter().filter(|m| !m.read).count();
            let last = msgs.iter().map(|m| m.timestamp).max().unwrap_or(0);
            let delete = |t: u64| json!({ "nom": "delete_user_message", "libellé": "Supprimer", "style": "danger",
                "valeurs": { "utilisateur": hx(&u), "n°": t },
                "confirmer": "Supprimer ce message ? Les 4 Kio qu'il occupe sont rendus au quota de l'utilisateur." });
            // Fil : messages reçus et réponses adressées à cet utilisateur.
            let mut thread: Vec<(u64, Value)> = msgs
                .iter()
                .map(|m| (m.timestamp, json!({ "date": m.timestamp, "de": who, "message": m.text,
                    "_gras": !m.read, "_actions": [delete(m.timestamp)] })))
                .collect();
            thread.extend(s.channel.outbox.sent.iter().filter(|(m, _)| m.recipient == Some(u)).map(|(m, _)| {
                (m.timestamp, json!({ "date": m.timestamp, "de": "vous (Nœud)", "message": m.text }))
            }));
            thread.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
            let panel = json!({
                // `clé` : le panneau ouvert suit les mises à jour (suppression).
                "clé": format!("conversation:{}", hx(&u)),
                "titre": format!("Conversation avec {who}"),
                "contenu": thread.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
                "ouverture": { "nom": "mark_user_messages_read", "valeurs": { "utilisateur": hx(&u) } },
                "formulaires": [
                    { "nom": "send_user_message", "titre": "Répondre", "libellé": "Envoyer la réponse",
                      "champs": ["message"], "libellés": { "message": "réponse" }, "types": { "message": "texte" },
                      "fixes": { "utilisateur": hx(&u) }, "différer": 5,
                      "aide": { "message": "Lue par cet utilisateur seul à son prochain contact" } },
                ] });
            (last, json!({
                "de": who, "messages": msgs.len(), "non lus": unread, "dernier reçu le": last,
                "_gras": unread > 0,
                "_ouvrir": panel.clone(),
                "_actions": [{ "nom": "open_conversation", "libellé": "Ouvrir", "panneau": panel }],
            }))
        })
        .collect();
    rows.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    rows.into_iter().map(|(_, v)| v).collect()
}

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
        Some(e)
            if e.get("identité peut-être dupliquée")
                .is_some_and(|x| !x.is_null()) =>
        {
            ("identité peut-être dupliquée".to_string(), "attention")
        }
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
    let capacity: u64 = v
        .pointer("/volumes/_contenu")
        .and_then(|x| x.as_array())
        .map_or(0, |a| {
            a.iter()
                .filter_map(|x| x.get("capacité (octets)")?.as_u64())
                .sum()
        });
    let alerts = len("alertes d'intégrité signalées");
    let red = v.pointer("/dispersion/redondance");
    let rate = red.and_then(|r| r["taux (%)"].as_f64());
    let weakest = red.and_then(|r| r["stripe le plus faible (%)"].as_f64());
    let goal = red
        .and_then(|r| r["objectif (%)"].as_f64())
        .unwrap_or(300.0);
    let unread: u64 = v
        .get("messages des utilisateurs")
        .and_then(|x| x.as_array())
        .map_or(0, |a| a.iter().filter_map(|r| r["non lus"].as_u64()).sum());
    json!([
        { "libellé": "Joignabilité", "valeur": nat, "état": nat_state, "page": "reseau" },
        { "libellé": "Annuaire", "valeur": dir, "état": dir_state, "page": "reseau" },
        { "libellé": "Republication DHT", "valeur": v.pointer("/republication DHT/taux de republication (%)").and_then(|x| x.as_f64()).map(|x| format!("{x} %")).unwrap_or_else(|| "—".into()),
          "état": match v.pointer("/republication DHT/taux de republication (%)").and_then(|x| x.as_f64()) {
              Some(x) if x >= 100.0 => "ok", Some(x) if x > 0.0 => "attention", Some(_) => "probleme", None => "neutre" },
          "page": "reseau" },
        { "libellé": "Redondance", "valeur": rate.map(|x| format!("{x} %")).unwrap_or_else(|| "—".into()),
          "détail": weakest.map(|m| format!("stripe le plus faible : {m} %")),
          "état": match weakest { None => "neutre", Some(m) if m >= goal => "ok", Some(m) if m >= 100.0 => "attention", Some(_) => "probleme" },
          "page": "stockage" },
        { "libellé": "Utilisateurs", "valeur": len("utilisateurs rattachés"), "état": "neutre", "page": "utilisateurs" },
        { "libellé": "Partenaires", "valeur": partners, "détail": format!("{target} visés"),
          "état": if partners == 0 { "attention" } else { "ok" }, "page": "partenaires" },
        { "libellé": "Capacité", "valeur": capacity, "unité": "octets", "état": "neutre", "page": "stockage" },
        { "libellé": "Alertes d'intégrité", "valeur": alerts,
          "état": if alerts == 0 { "ok" } else { "probleme" }, "page": "accueil" },
        { "libellé": "Messages non lus", "valeur": unread,
          "état": if unread == 0 { "neutre" } else { "attention" }, "page": "messages" }
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
        "précision": sh.geo.read().unwrap().mode(),
        "dernière mise à jour": match (&g.note, state.as_str()) {
            (Some(n), "réussie") => n.clone(),
            _ => state.clone(),
        },
        "source": sh.geo.read().unwrap().source(),
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
        let r = crate::geo::update_with_fallback(&sh.config.data_dir, now);
        if r.is_ok() {
            *sh.geo.write().unwrap() = Geo::open_dir(&sh.config.data_dir);
        }
        let mut g = sh.geoip.lock().unwrap();
        g.running = false;
        g.note = r.as_ref().ok().cloned();
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
        s.history_retention_s = a.config.history_days * 86_400;
    }
    *sh.alert_cfg.lock().unwrap() = a.config.alerts.clone();
    let message = if a.restart.is_empty() {
        "Configuration enregistrée et appliquée".to_string()
    } else {
        format!(
            "Configuration enregistrée ; redémarrez le Nœud pour appliquer (bouton « Redémarrer le Nœud », Vue d'ensemble) : {}",
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
    let fillers = d
        .as_ref()
        .map(|d| d.upkeep.fillers.clone())
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
            let name = s3m_protocol::pseudo::display(&[s.user_labels.get(id).map(String::as_str)], id);
            let gib = (u.quota_bytes as f64 / (1u64 << 30) as f64 * 100.0).round() / 100.0;
            json!({ "utilisateur": hx(id),
                    "nom": name,
                    "quota (octets)": u.quota_bytes,
                    "utilisé (octets)": u.used_bytes,
                    "rattachement": if s.auto_attached.contains(id) { "automatique" } else { "manuel" },
                    "dernière activité": s.last_active.get(id).map(|t| format!("le {t}")),
                    "jours avant suppression": match crate::inactivity::remaining_days(&s, id, now) {
                        None => json!("∞"),
                        Some(d) => json!(d),
                    },
                    "_gras": crate::inactivity::remaining_days(&s, id, now).is_some_and(|d| d <= 30),
                    "pays": country(s.last_user_ip.get(id)),
                    "racine": hx(&u.root),
                    "_actions": [{ "nom": "edit_user", "libellé": "Éditer", "panneau": {
                        "titre": format!("Utilisateur {name}"),
                        "formulaires": [
                            { "nom": "set_quota", "titre": "Quota", "libellé": "Changer le quota",
                              "champs": ["quota (Gio)"], "fixes": { "user_id": hx(id) },
                              "valeurs": { "quota (Gio)": gib }, "types": { "quota (Gio)": "number" },
                              "aide": { "quota (Gio)": format!("Utilisé : {:.2} Gio", u.used_bytes as f64 / (1u64 << 30) as f64) } },
                            { "nom": "set_user_inactivity", "titre": "Durée d'inactivité avant suppression", "libellé": "Enregistrer",
                              "champs": ["jours"], "types": { "jours": "durée" }, "unités": { "jours": "j" }, "libellés": { "jours": "durée" }, "fixes": { "utilisateur": hx(id) },
                              "valeurs": { "jours": s.inactivity_days.get(id).map_or(String::new(), |d| d.to_string()) },
                              "aide": { "jours": format!("Vide : politique du Nœud ({}) ; 0 : éternel ; sinon au moins {} jours sans connexion avant suppression définitive",
                                  if s.auto_attached.contains(id) { format!("{} j", s.attach_policy.inactivity_days) } else { "éternel, rattachement manuel".into() },
                                  crate::inactivity::MIN_DAYS) } },
                            { "nom": "set_user_label", "titre": "Étiquette", "libellé": "Enregistrer",
                              "champs": ["étiquette"], "fixes": { "utilisateur": hx(id) },
                              "valeurs": { "étiquette": s.user_labels.get(id).cloned().unwrap_or_default() },
                              "aide": { "étiquette": "Visible par vous seul ; vide pour l'effacer" } },
                            { "nom": "send_user_message", "titre": "Message à cet utilisateur", "libellé": "Envoyer",
                              "champs": ["message"], "fixes": { "utilisateur": hx(id) }, "types": { "message": "texte" }, "différer": 5,
                              "aide": { "message": "Lu par cet utilisateur seul à son prochain contact (4 096 octets au plus, conservé 30 jours)" } },
                        ] } },
                        { "nom": "write_user", "libellé": "Écrire", "style": "secondary", "panneau": {
                            "titre": format!("Message à {name}"),
                            "formulaires": [
                                { "nom": "send_user_message", "libellé": "Envoyer",
                                  "champs": ["message"], "fixes": { "utilisateur": hx(id) }, "types": { "message": "texte" }, "différer": 5,
                                  "aide": { "message": "Lu par cet utilisateur seul à son prochain contact (4 096 octets au plus, conservé 30 jours)" } },
                            ] } }] })
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
            let name = s3m_protocol::pseudo::display(&[s.partner_names.get(id).map(String::as_str)], id);
            let state = if peer.status.is_empty() { "partenaire".to_string() } else { peer.status.clone() };
            // Colonnes essentielles ; le reste dans le panneau de la ligne.
            json!({ "nom": name,
                    "état": state,
                    "score": r2(sc.total),
                    "pays": country(Some(&peer.ip)),
                    "confiés / reçus": format!("{} / {}", p.ledger.hosted_for_partner, p.ledger.hosted_by_partner),
                    "dernier échange": p.last_seen,
                    "score (tri)": sc.total,
                    "_ouvrir": {
                        "titre": format!("Partenaire {name}"),
                        "contenu": {
                            "nœud": n,
                            "état": state,
                            "score": r2(sc.total),
                            "fiabilité": r2(sc.reliability), "disponibilité": r2(sc.availability), "vitesse": r2(sc.speed),
                            "pays": country(Some(&peer.ip)),
                            "latence (ms)": if peer.answered == 0 { Value::Null } else { json!(peer.latency_ms.round()) },
                            "dernier challenge réussi": pos.2.get(&n),
                            "fragments confiés": p.ledger.hosted_for_partner,
                            "fragments reçus": p.ledger.hosted_by_partner,
                            "quota négocié (fragments)": s.partner_policy.limit(p),
                            "confiance (fragments)": s.partner_policy.trust_of(p),
                            "remplissage confié (fragments)": fillers.get(&n).map_or(0, |v| v.len()),
                            "manquements (période en cours)": p.failures,
                            "placements suspendus jusqu'au": if p.suspended_until > now { json!(p.suspended_until) } else { Value::Null },
                            "adresse": addrs.get(id),
                            "dernier échange": p.last_seen,
                            "purge à venir": if p.last_seen == 0 { Value::Null } else { json!(purge) },
                            "purge échue": p.last_seen != 0 && purge <= now,
                        } } })
        })
        .collect();
    partners.sort_by(|a, b| {
        b["score (tri)"]
            .as_f64()
            .unwrap_or(0.0)
            .total_cmp(&a["score (tri)"].as_f64().unwrap_or(0.0))
    });
    for p in &mut partners {
        if let Some(o) = p.as_object_mut() {
            o.remove("score (tri)");
        }
    }
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
        // Titre (onglet du navigateur) : nom du Nœud s'il est saisi.
        "titre": match s.name.as_deref() {
            Some(n) if !n.is_empty() => format!("Nœud S3m — {n}"),
            _ => "Nœud S3m".to_string(),
        },
        "carte": true,
        "identité": {
            "node_id": hx(&s.node_id()),
            "nom": s3m_protocol::pseudo::display(&[s.name.as_deref()], &s.node_id()),
            "empreinte": s3m_protocol::pseudo::fingerprint(&s.node_id()),
            "peer_id": sh.peer_id,
            // Échange de blocs et annuaire partagent la même adresse.
            "adresse du nœud": sh.blocks_addr.clone().or_else(|| sh.dht_addr.clone()),
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
                sh.config.dispersal.k * sh.config.dispersal.coef + 4 } else { sh.config.partnering.target_partners }
                .max(sh.config.dispersal.k * sh.config.dispersal.coef) + s.missing_partners,
            "dernier cycle": last_partnering.map(|(t, r)| json!({ "instant": t, "découverts": r.discovered,
                "testés": r.probed, "proposés": r.proposed, "acceptés": r.accepted,
                "mis en retrait": r.retiring, "terminés": r.ended })),
        },
        "alertes d'intégrité signalées": s.incidents.iter().map(|i| hx(i)).collect::<Vec<_>>(),
        "dispersion": dispersal_status(sh, &s.user_labels),
        "contrôles et réparation": upkeep_status(sh),
        "annuaire (entrée Node)": node_entry_status(sh),
        "traversée de NAT": nat_status(sh),
        "snapshot du nœud": snapshot_status(sh),
        "restauration": restore_status(sh),
        "migration": {
            "anciens node_id couverts": s.previous_node_ids.iter().map(|i| hx(i)).collect::<Vec<_>>(),
            "délégations reçues": s.delegations.len(),
            "pointeurs de migration connus": s.successors.len(),
        },
        "espace de secours": emergency_status(sh, &s),
        "messages des utilisateurs": user_conversations(&s),
        "messages envoyés": s.channel.outbox.sent.iter().rev().map(|(m, _)| json!({
            "sorte": if m.kind == s3m_protocol::message::Kind::Alert { "alerte" }
                else if m.announce_replacement.is_some() { "remplacement de la clé d'annonce" } else { "information" },
            "destinataire": m.recipient.map(|u| s3m_protocol::pseudo::display(&[s.user_labels.get(&u).map(String::as_str)], &u))
                .unwrap_or_else(|| "tous les utilisateurs".into()),
            "numéro": m.seq, "envoyé le": m.timestamp, "message": m.text,
            "nœud de remplacement": m.successor.map(|x| hx(&x)) })).collect::<Vec<_>>(),
        "clé d'annonce": {
            "clé publique": s.channel.announce.map(|k| hx(&k)),
            "alerte dans l'annuaire": match (&s.channel.alert_envelope, s.channel.alert_published_at) {
                (None, _) => json!("aucune"),
                (Some(_), 0) => json!("en attente de publication"),
                (Some(_), t) => json!(t),
            },
        },
        "actions": [
            { "nom": "set_node_name", "titre": "Nom du Nœud", "libellé": "Enregistrer",
              "champs": ["nom"], "valeurs": { "nom": s.name.clone().unwrap_or_default() },
              "aide": { "nom": "Publié dans l'annuaire et affiché par les connecteurs avec l'empreinte du Nœud (64 octets au plus) ; vide pour aucun nom" } },
            { "nom": "send_message", "titre": "Écrire à tous les utilisateurs", "libellé": "Envoyer à tous",
              "champs": ["message"], "types": { "message": "texte" }, "différer": 5,
              "aide": { "message": "Lu par tous les utilisateurs rattachés à leur prochain contact (4 096 octets au plus, conservé 30 jours). Pour un seul utilisateur : bouton « Écrire » de sa ligne (page Utilisateurs) ou « Répondre » sur son message." } },
            { "nom": "create_announce_key", "titre": "Créer la clé d'annonce", "libellé": "Créer",
              "champs": [],
              "aide": {} },
            { "nom": "replace_announce_key", "titre": "Phrase d'annonce perdue : remplacer la clé", "libellé": "Remplacer la clé d'annonce",
              "champs": [],
              "confirmer": "Remplacer la clé d'annonce ?\n\nUne nouvelle phrase de 24 mots vous sera remise. Chaque utilisateur devra accepter le remplacement dans son application : prévenez-les par un autre moyen (téléphone, courriel…) pour qu'ils sachent que la demande vient bien de vous. Tant qu'un utilisateur n'a pas accepté, une alerte signée par la nouvelle clé ne l'atteint pas." },
            { "nom": "send_alert", "titre": "Alerte : ce Nœud est compromis", "libellé": "Envoyer l'alerte",
              "champs": ["phrase d'annonce", "message", "nœud de remplacement"],
              "types": { "message": "texte" },
              "aide": { "phrase d'annonce": "Les 24 mots remis à la création de la clé d'annonce ; ils ne sont pas conservés",
                        "nœud de remplacement": "Identifiant du Nœud vers lequel les utilisateurs doivent se rattacher (facultatif)" } },
            { "nom": "attach_user", "titre": "Rattacher un utilisateur manuellement", "libellé": "Rattacher",
              "champs": ["user_id", "salt", "quota (Gio)"],
              "libellés": { "user_id": "identifiant de l'utilisateur", "salt": "sel d'attachement" },
              "types": { "quota (Gio)": "number" },
              "aide": { "user_id": "Affiché par l'assistant de S3m de l'utilisateur", "salt": "Affiché à côté de l'identifiant (32 caractères)" } },
            { "nom": "add_partner", "titre": "Ajouter un partenaire manuellement", "libellé": "Ajouter",
              "champs": ["node_id", "addr"],
              "libellés": { "node_id": "identifiant du Nœud", "addr": "adresse" },
              "aide": { "addr": "/ip4/…/tcp/…/p2p/…" } },
            { "nom": "set_attach_policy", "titre": "Rattachement automatique des utilisateurs",
              "libellé": "Enregistrer",
              "champs": ["enabled", "quota par utilisateur (Gio)", "max_users", "inactivité avant suppression (jours)"],
              "libellés": { "enabled": "accepter automatiquement les nouveaux utilisateurs", "max_users": "utilisateurs au plus", "inactivité avant suppression (jours)": "inactivité avant suppression" },
              "valeurs": { "enabled": s.attach_policy.enabled,
                           "quota par utilisateur (Gio)": s.attach_policy.quota_bytes as f64 / (1u64 << 30) as f64,
                           "max_users": s.attach_policy.max_users,
                           "inactivité avant suppression (jours)": s.attach_policy.inactivity_days },
              "types": { "enabled": "bool", "quota par utilisateur (Gio)": "number", "max_users": "number", "inactivité avant suppression (jours)": "durée" }, "unités": { "inactivité avant suppression (jours)": "j" },
              "aide": { "max_users": "Budget total réservé = quota par utilisateur × utilisateurs au plus",
                        "inactivité avant suppression (jours)": format!("Utilisateurs rattachés automatiquement : supprimés définitivement, données comprises, après ce nombre de jours sans connexion ; 0 : éternels ; au moins {} jours", crate::inactivity::MIN_DAYS) } },
            { "nom": "set_emergency_policy", "titre": "Accueil des utilisateurs en détresse",
              "libellé": "Enregistrer",
              "champs": ["utilisateurs accueillis au plus", "espace par utilisateur (Gio)"],
              "valeurs": { "utilisateurs accueillis au plus": s.emergency.max_users,
                           "espace par utilisateur (Gio)": s.emergency.per_depositor_bytes as f64 / (1u64 << 30) as f64 },
              "types": { "utilisateurs accueillis au plus": "number", "espace par utilisateur (Gio)": "number" },
              "aide": { "utilisateurs accueillis au plus": "U_backup : 0 pour ne rien accueillir",
                        "espace par utilisateur (Gio)": "Espace réservé = utilisateurs au plus × espace par utilisateur" } }
        ]
    })
}

/// Espace de secours : réserve pour tiers en détresse et intégration des
/// dépôts faits pendant une absence de ce Nœud.
fn emergency_status(sh: &Shared, s: &NodeService) -> Value {
    let e = &s.emergency;
    let rows: Vec<Value> = e
        .depositors()
        .map(|(k, d)| {
            json!({ "déposant": k, "occupé (octets)": d.bytes,
                    "dernier dépôt": if d.last_deposit == 0 { Value::Null } else { json!(d.last_deposit) } })
        })
        .collect();
    let ui = sh.emergency_ui.lock().unwrap();
    let pct = |a: u64, b: u64| {
        if b == 0 {
            0.0
        } else {
            (a as f64 * 1000.0 / b as f64).round() / 10.0
        }
    };
    json!({
        "utilisateurs accueillis": format!("{} / {}", e.users(), e.max_users),
        "espace réservé (octets)": e.reserved_bytes,
        "espace occupé (octets)": e.used_bytes(),
        "% occupé": pct(e.used_bytes(), e.reserved_bytes),
        "plafond par utilisateur (octets)": e.per_depositor_bytes,
        "déposants": rows,
        "dépôts oubliés purgés": ui.purged,
        "retour de ce Nœud : dernier contrôle": ui.last.as_ref().map(|(t, _)| *t),
        "retour de ce Nœud : bilan": ui.last.as_ref().map(|(_, r)| json!({
            "entrées à intégrer": r.entries,
            "blocs intégrés": r.integrated,
            "blocs refusés (quota)": r.over_quota,
            "blocs introuvables (nouvel essai)": r.missing,
        })),
    })
}

/// `labels` : étiquettes des Utilisateurs (verrou du service déjà tenu
/// par l'appelant).
fn dispersal_status(sh: &Shared, labels: &HashMap<[u8; 32], String>) -> Value {
    let cycle = sh.last_cycle.lock().unwrap().clone();
    let users: Value = match sh.dispersal.try_lock() {
        Err(_) => json!({ "état": "cycle en cours" }),
        Ok(d) => {
            *sh.last_redundancy.lock().unwrap() =
                crate::dispersal_engine::redundancy(&d, sh.config.dispersal.k);
            let rows: Vec<Value> = d
                .users
                .iter()
                .map(|(u, x)| {
                    let id: Option<[u8; 32]> = hex::decode(u).ok().and_then(|v| v.try_into().ok());
                    let name = id.map(|id| {
                        s3m_protocol::pseudo::display(&[labels.get(&id).map(String::as_str)], &id)
                    });
                    json!({ "nom": name, "utilisateur": u, "stripes": x.stripes.len(),
                            "blocs en attente": x.pending.len(),
                            "stripes d'index": x.index.len(),
                            "publié le": if x.published_at == 0 { Value::Null } else { json!(x.published_at) },
                            "à republier": x.dirty,
                            "fragments à purger": x.retired.len(),
                            "erreur": x.last_error })
                })
                .collect();
            let sum = |f: fn(&crate::dispersal_engine::UserDispersal) -> usize| -> usize {
                d.users.values().map(f).sum()
            };
            let last = d.users.values().map(|x| x.published_at).max().filter(|t| *t > 0);
            let errors: Vec<&String> = d.users.values().filter_map(|x| x.last_error.as_ref()).collect();
            json!({
                "utilisateurs": d.users.len(),
                "stripes": sum(|x| x.stripes.len()),
                "blocs en attente": sum(|x| x.pending.len()),
                "stripes d'index": sum(|x| x.index.len()),
                "fragments à purger": sum(|x| x.retired.len()),
                "à republier": d.users.values().filter(|x| x.dirty).count(),
                "dernière publication": last,
                "utilisateurs en erreur": errors.len(),
                "dernière erreur": errors.first(),
                "_détails": { "libellé": "Détails", "titre": "Dispersion par utilisateur",
                              "clé": "dispersion-utilisateurs", "large": true, "contenu": rows },
            })
        }
    };
    let red = *sh.last_redundancy.lock().unwrap();
    json!({
        "redondance": red.map(|(g, m)| json!({
            "taux (%)": g.round(),
            "stripe le plus faible (%)": m.round(),
            "objectif (%)": sh.config.dispersal.coef * 100,
            "_note": "100 % : au moins l'équivalent d'une copie complète dispersée ; 300 % : les 12 fragments de parité de chaque stripe placés." })),
        "paramètres": { "k": sh.config.dispersal.k, "coef": sh.config.dispersal.coef,
                        "partenaires requis par stripe": sh.config.dispersal.k * sh.config.dispersal.coef,
                        "partenaires minimum par stripe": sh.config.dispersal.min_confirmations(),
                        "mode essai": (sh.config.dispersal.min_confirmations() < sh.config.dispersal.k + 2)
                            .then_some("minimum abaissé : vos fichiers ne supportent plus la perte de partenaires") },
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
        .map(|(n, (at, why))| json!({ "nœud": n, "depuis": at, "motif": why,
            "_actions": [{ "nom": "unblacklist", "libellé": "Retirer", "valeurs": { "nœud": n },
                "confirmer": "Retirer ce Nœud de la liste noire ? Il pourra redevenir partenaire." }] }))
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
        "maintenance": maintenance_status(up.maintenance.as_ref().or(up.last_maintenance.as_ref())),
        "événements récents": up.events.iter().rev().take(15).cloned().collect::<Vec<_>>(),
    })
}

/// Défaillances matérielles des volumes, avec la conduite à tenir
/// (`securite.integrite-autoreparation#defaillance`).
/// Alertes critiques en cours : disques, maintenance, horloge.
pub fn critical_alerts(sh: &Shared) -> Vec<crate::alerts::Alert> {
    let mut out = Vec::new();
    let mut s = sh.service.lock().unwrap();
    if let Some(f) = &s.clock_freeze {
        out.push(("horloge".into(), "Horloge à vérifier".into(), crate::clock_guard::describe(f)));
    }
    if s.maintenance {
        out.push((
            "maintenance".into(),
            "Maintenance du stockage".into(),
            "Une partie du stockage a été perdue ou altérée : le Nœud reconstruit les fichiers depuis le réseau (tableau de bord, vue d'ensemble).".into(),
        ));
    }
    if let Some(p) = s.store.physical() {
        for f in p.faults() {
            out.push((format!("disque:{}:{:?}", f.volume_id, f.kind), f.title(), format!("{} — {}", f.error, f.advice())));
        }
    }
    out
}

/// Envoie les alertes apparues depuis le dernier cycle.
async fn alert_tick(sh: &Arc<Shared>, now: u64) {
    let current = critical_alerts(sh);
    let fresh = crate::alerts::new_alerts(&current, &mut sh.alerts_sent.lock().unwrap(), now);
    if fresh.is_empty() {
        return;
    }
    let cfg = sh.alert_cfg.lock().unwrap().clone();
    let node = {
        let s = sh.service.lock().unwrap();
        s3m_protocol::pseudo::display(&[s.name.as_deref()], &s.node_id())
    };
    let sh2 = sh.clone();
    let _ = tokio::task::spawn_blocking(move || {
        for (_, title, text) in fresh {
            for e in crate::alerts::dispatch(&cfg, &node, &title, &text) {
                note(&sh2, format!("alerte « {title} » non envoyée — {e}"));
            }
        }
    })
    .await;
}

fn disk_alerts(sh: &Shared) -> Vec<Value> {
    let faults = match sh.service.lock().unwrap().store.physical() {
        Some(p) => p.faults(),
        None => return Vec::new(),
    };
    faults
        .iter()
        .map(|f| json!({
            "alerte": f.title(),
            "volume": f.volume_id,
            "chemin": f.mount_path.display().to_string(),
            "erreur rencontrée": f.error,
            "occurrences": f.count,
            "depuis": f.first_at,
            "dernière": f.last_at,
            "que faire": f.advice(),
            "_actions": [{ "nom": "disk_alert_resolved", "libellé": "Résolu", "valeurs": { "volume": f.volume_id.to_string() },
                "confirmer": "Effacer les alertes de ce volume ? Elles réapparaîtront si l'erreur se reproduit." }],
        }))
        .collect()
}

/// Maintenance après la perte d'un volume
/// (`securite.integrite-autoreparation#maintenance`).
fn maintenance_status(m: Option<&crate::upkeep::Maintenance>) -> Value {
    let Some(m) = m else { return Value::Null };
    json!({
        "état": match m.ended_at {
            None => format!("en cours : reconstruction depuis le réseau (passage {} sur {} au plus)", m.passes + 1, crate::upkeep::MAINTENANCE_PASSES),
            Some(_) => "terminée".to_string(),
        },
        "cause": if m.reason.is_empty() { "fichiers de stockage disparus du disque" } else { m.reason.as_str() },
        "depuis": m.since,
        "terminée le": m.ended_at,
        "blocs d'Utilisateurs perdus": m.lost_user_blocks,
        "blocs reconstruits": m.repaired,
        "blocs irrécupérables": if m.ended_at.is_some() { json!(m.irrecoverable) } else { Value::Null },
        "fragments de partenaires perdus (replacés par eux)": m.lost_fragments,
        "dépôts d'urgence perdus": m.lost_emergency,
        "_note": "Fichiers de stockage disparus du disque : le Nœud les reconstruit depuis la parité gardée par ses partenaires. Pendant ce temps il refuse les dépôts de partenaires et leur signale ses fragments perdus, sans manquement.",
    })
}

fn nat_status(sh: &Shared) -> Value {
    let n = sh.nat.lock().unwrap().clone();
    json!({
        "joignabilité": n.status,
        "box (UPnP)": n.upnp,
        "adresse publique de la box": n.public_ip,
        "adresses externes confirmées": n.external,
        "adresses via relais": n.relayed,
        "perçages réussis": n.hole_punch_ok,
        "perçages échoués": n.hole_punch_failed,
        "circuits relayés pour d'autres": n.relay_circuits_served,
    })
}

/// Période de republication des entrées Node et DispersalManifest
/// (`network.dht-directory` § Expiration & republication).
const REPUBLISH_PERIOD_S: u64 = 2_592_000;
/// Tolérance avant de compter une entrée « en retard ».
const REPUBLISH_GRACE_S: u64 = 86_400;

/// Taux de republication DHT : part des entrées gérées par ce Nœud (entrée
/// Node, DispersalManifest de chaque Utilisateur) republiées à temps.
fn republication_status(sh: &Shared) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut entries: Vec<(String, u64, u64)> = Vec::new();
    {
        let n = sh.node_entry.lock().unwrap();
        entries.push((
            "entrée Node".into(),
            n.published_at.unwrap_or(0),
            n.next_republish,
        ));
    }
    match sh.dispersal.try_lock() {
        Ok(d) => {
            for (u, x) in &d.users {
                if x.pointer.is_some() || x.published_at > 0 {
                    entries.push((
                        format!("DispersalManifest {}…", &u[..12.min(u.len())]),
                        x.published_at,
                        x.next_republish,
                    ));
                }
            }
        }
        Err(_) => return json!({ "état": "cycle en cours" }),
    }
    let on_time = |p: u64| p > 0 && now < p + REPUBLISH_PERIOD_S + REPUBLISH_GRACE_S;
    let ok = entries.iter().filter(|e| on_time(e.1)).count();
    let late: Vec<Value> = entries
        .iter()
        .filter(|e| !on_time(e.1))
        .map(|e| json!({ "entrée": e.0, "dernière publication": if e.1 == 0 { Value::Null } else { json!(e.1) } }))
        .collect();
    json!({
        "entrées gérées": entries.len(),
        "à jour": ok,
        "taux de republication (%)": (ok as f64 * 1000.0 / entries.len().max(1) as f64).round() / 10.0,
        "prochaine republication": entries.iter().map(|e| e.2).filter(|t| *t > 0).min(),
        "en retard ou jamais publiées": late,
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
        "identité peut-être dupliquée": s.twin_warning,
    })
}

fn snapshot_status(sh: &Shared) -> Value {
    let snap = match sh.dispersal.try_lock() {
        Err(_) => return json!({ "état": "cycle en cours" }),
        Ok(d) => d.snapshot.clone(),
    };
    json!({
        "dernier snapshot": if snap.last_at == 0 { Value::Null } else { json!(snap.last_at) },
        "fragments placés": snap.stripe.as_ref().map(|s| s.parity.len()),
        "publié dans l'entrée Node": sh.node_entry.lock().unwrap().published_snapshot.is_some(),
        "erreur": snap.last_error,
    })
}

/// Points de la carte du dashboard.
pub fn map_points(sh: &Shared) -> Value {
    // Pairs du réseau local (adresse privée) : localisés par l'adresse
    // publique de la box, celle de ce Nœud.
    let public = |ip: &str| {
        ip.parse::<std::net::IpAddr>()
            .is_ok_and(|a| !crate::geo::is_private(&a))
    };
    let own_ip: Option<String> = sh
        .config
        .public_ip
        .clone()
        .filter(|i| public(i))
        .or_else(|| {
            let n = sh.nat.lock().unwrap();
            n.direct_tcp()
                .map(|(ip, _)| ip)
                .filter(|i| public(i))
                .or_else(|| n.public_ip.clone())
        });
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
        let (ip, detail) = match ip {
            Some(i) if !i.is_empty() && !public(&i) && own_ip.is_some() => (
                own_ip.clone(),
                if detail.is_empty() {
                    "réseau local".to_string()
                } else {
                    format!("{detail} · réseau local")
                },
            ),
            other => (other, detail),
        };
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
            s3m_protocol::pseudo::display(&[s.partner_names.get(id).map(String::as_str)], id),
            format!(
                "confiés {} · reçus {}",
                p.ledger.hosted_for_partner, p.ledger.hosted_by_partner
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
            s3m_protocol::pseudo::display(&[s.user_labels.get(id).map(String::as_str)], id),
            if s.auto_attached.contains(id) {
                "rattachement automatique".into()
            } else {
                String::new()
            },
        );
    }
    json!({ "points": points, "non_localises": unlocated, "geoip": sh.geo.read().unwrap().available(), "attribution": sh.geo.read().unwrap().source() })
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
    // Explorateur de dossiers (volumes) : machine du Nœud.
    if name == "fs_browse" {
        return s3m_protocol::local_fs::browse(&v);
    }
    if name == "fs_mkdir" {
        return s3m_protocol::local_fs::mkdir(&v);
    }
    if name.starts_with("volume_") {
        return volume_action(sh, name, &v);
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
    if let Some(r) = channel_action(sh, name, &v) {
        return r;
    }
    if name == "restart_node" {
        note(sh, "redémarrage demandé depuis le tableau de bord");
        sh.restart.notify_one();
        return Ok(json!({ "ok": true,
            "message": "Redémarrage en cours : le tableau de bord se reconnecte dans quelques secondes" }));
    }
    if name == "test_alerts" {
        let cfg = sh.alert_cfg.lock().unwrap().clone();
        let node = {
            let s = sh.service.lock().unwrap();
            s3m_protocol::pseudo::display(&[s.name.as_deref()], &s.node_id())
        };
        let errors = tokio::task::block_in_place(|| {
            crate::alerts::dispatch(&cfg, &node, "Alerte d'essai", "Les alertes de ce Nœud vous parviennent.")
        });
        return if errors.is_empty() {
            Ok(json!({ "ok": true, "message": "Alerte d'essai envoyée sur les canaux configurés" }))
        } else {
            Err(errors.join(" ; "))
        };
    }
    if name == "clock_confirm" {
        sh.service.lock().unwrap().clock_freeze = None;
        note(sh, "heure confirmée par l'opérateur : suppressions liées au temps reprises");
        let _ = save(sh);
        return Ok(json!({ "ok": true, "message": "Heure confirmée" }));
    }
    if name == "disk_alert_resolved" {
        let vid: u32 = field(&v, "volume")?.parse().map_err(|_| "volume invalide")?;
        if let Some(p) = sh.service.lock().unwrap().store.physical() {
            p.clear_faults(vid);
        }
        note(sh, format!("alertes du volume {vid} déclarées résolues"));
        return Ok(json!({ "ok": true, "message": format!("Alertes du volume {vid} effacées ; elles réapparaîtront si l'erreur se reproduit") }));
    }
    if name == "unblacklist" {
        let n = field(&v, "nœud")?.to_lowercase();
        let id: [u8; 32] = hex::decode(&n)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("identifiant de Nœud invalide")?;
        sh.service.lock().unwrap().blacklisted.remove(&id);
        note(
            sh,
            format!("{}… retiré de la liste noire", &n[..16.min(n.len())]),
        );
        let msg = match sh.dispersal.try_lock() {
            Ok(mut d) => {
                if !d.unblacklist(&n) {
                    return Err("ce Nœud n'est pas en liste noire".into());
                }
                let _ = save_dispersal(&sh.config, &d);
                "Nœud retiré de la liste noire"
            }
            Err(_) => {
                sh.unblacklist.lock().unwrap().push(n);
                "Retrait enregistré : appliqué à la fin du cycle de contrôle en cours"
            }
        };
        return Ok(json!({ "ok": true, "message": msg }));
    }
    let mut s = sh.service.lock().unwrap();
    match name {
        "attach_user" => {
            let id = unhex32(field(&v, "user_id")?)?;
            let salt = hex::decode(field(&v, "salt")?).map_err(|e| e.to_string())?;
            if salt.len() != 16 {
                return Err("sel de 16 octets attendu".into());
            }
            let quota_bytes = gib(&v, "quota (Gio)")?
                .or(number(&v, "quota_bytes").ok())
                .ok_or("quota manquant")?;
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
            s.partners.entry(id).or_default();
            sh.addrs.lock().unwrap().insert(id, addr.to_string());
        }
        "set_user_inactivity" => {
            let id = unhex32(field(&v, "utilisateur")?)?;
            if !s.users.contains_key(&id) {
                return Err("utilisateur inconnu".into());
            }
            match field(&v, "jours").map(str::trim).unwrap_or("") {
                "" => {
                    s.inactivity_days.remove(&id);
                }
                x => {
                    let d: u64 = x.parse().map_err(|_| "nombre de jours invalide")?;
                    s.inactivity_days.insert(id, crate::inactivity::validate_days(d)?);
                }
            }
        }
        "set_quota" => {
            let id = unhex32(field(&v, "user_id")?)?;
            let q = gib(&v, "quota (Gio)")?
                .or(number(&v, "quota_bytes").ok())
                .ok_or("quota manquant")?;
            s.users
                .get_mut(&id)
                .ok_or("utilisateur inconnu")?
                .quota_bytes = q;
        }
        "set_emergency_policy" => {
            let users = number(&v, "utilisateurs accueillis au plus")
                .unwrap_or(s.emergency.max_users as u64);
            let per =
                gib(&v, "espace par utilisateur (Gio)")?.unwrap_or(s.emergency.per_depositor_bytes);
            let users = u32::try_from(users).map_err(|_| "nombre d'utilisateurs trop grand")?;
            s.emergency.set_limits(users, per);
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
            if let Some(q) = gib(&v, "quota par utilisateur (Gio)")? {
                p.quota_bytes = q;
            } else if let Ok(q) = number(&v, "quota_bytes") {
                p.quota_bytes = q;
            }
            if let Ok(m) = number(&v, "max_users") {
                p.max_users = m as usize;
            }
            if let Ok(d) = number(&v, "inactivité avant suppression (jours)") {
                p.inactivity_days = crate::inactivity::validate_days(d)?;
            }
            // Budget total : quota par utilisateur × nombre maximal d'utilisateurs.
            p.budget_bytes = p.quota_bytes.saturating_mul(p.max_users as u64);
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
        "set_user_inactivity" => "Durée d'inactivité enregistrée",
        "set_emergency_policy" => "Accueil des utilisateurs en détresse enregistré",
        _ => "Rattachement automatique enregistré",
    };
    Ok(json!({ "ok": true, "message": message }))
}

/// Actions du canal Nœud ↔ Utilisateurs (`protocols.canal-noeud`).
fn channel_action(sh: &Shared, name: &str, v: &Value) -> Option<Result<Value, String>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let r = {
        let mut s = sh.service.lock().unwrap();
        let node_id = s.node_id();
        match name {
            "set_node_name" => {
                let n = s3m_protocol::pseudo::sanitize(v.get("nom").and_then(Value::as_str).unwrap_or(""));
                s.name = (!n.is_empty()).then_some(n);
                Ok(json!({ "ok": true, "message": "Nom du Nœud enregistré ; l'annuaire sera mis à jour dans la minute" }))
            }
            "set_user_label" => (|| {
                let u = unhex32(field(v, "utilisateur")?.trim())?;
                if !s.users.contains_key(&u) {
                    return Err("utilisateur inconnu".to_string());
                }
                let l = s3m_protocol::pseudo::sanitize(v.get("étiquette").and_then(Value::as_str).unwrap_or(""));
                if l.is_empty() {
                    s.user_labels.remove(&u);
                } else {
                    s.user_labels.insert(u, l);
                }
                Ok(json!({ "ok": true, "message": "Étiquette enregistrée" }))
            })(),
            "delete_user_message" => (|| {
                let u = unhex32(field(v, "utilisateur")?.trim())?;
                let t = number(v, "n°")?;
                if s.delete_user_message(&u, t) {
                    Ok(json!({ "ok": true, "message": "Message supprimé, 4 Kio rendus au quota de l'utilisateur" }))
                } else {
                    Err("message introuvable".to_string())
                }
            })(),
            "mark_all_user_messages_read" => {
                let users: Vec<[u8; 32]> = s.channel.inbox.received.iter().map(|m| m.user_id).collect();
                let n: usize = users.iter().map(|u| s.channel.inbox.mark_read(u)).sum();
                Ok(json!({ "ok": true, "message": format!("{n} message(s) marqué(s) lu(s)") }))
            }
            "mark_user_messages_read" => (|| {
                let u = unhex32(field(v, "utilisateur")?.trim())?;
                let n = s.channel.inbox.mark_read(&u);
                Ok(json!({ "ok": true, "message": format!("{n} message(s) marqué(s) lu(s)") }))
            })(),
            "send_user_message" => (|| {
                let u = unhex32(field(v, "utilisateur")?.trim())?;
                if !s.users.contains_key(&u) {
                    return Err("utilisateur inconnu".to_string());
                }
                let n = s.channel.post_info_to(&sh.priv_node, &u, field(v, "message")?, now)?;
                Ok(json!({ "ok": true, "message": format!("Message n° {n} envoyé à cet utilisateur") }))
            })(),
            "replace_announce_key" => s.channel.replace_announce(&sh.priv_node, now).map(|phrase| {
                json!({ "ok": true, "message": "Nouvelle clé d'annonce créée ; demande de remplacement envoyée aux utilisateurs",
                        "révéler": {
                            "titre": "Nouvelle phrase d'annonce : à noter maintenant",
                            "texte": [
                                "Ces 24 mots ne seront plus jamais affichés : le Nœud ne les conserve pas.",
                                "Notez-les sur papier (ne les photographiez pas) et rangez-les à part de la phrase de récupération du Nœud, ailleurs que sur cette machine.",
                                "Prévenez vos utilisateurs par un autre moyen (téléphone, courriel…) : leur application leur demande d'accepter le remplacement de la clé d'alerte, et ils ne doivent accepter que si vous le leur avez confirmé.",
                                "Tant qu'un utilisateur n'a pas accepté, une alerte signée par cette nouvelle clé ne l'atteint pas."
                            ],
                            "24 mots": phrase,
                            "fermer": "J'ai noté les 24 mots"
                        } })
            }),
            "send_message" => field(v, "message")
                .and_then(|t| s.channel.post_info(&sh.priv_node, t, now))
                .map(|n| json!({ "ok": true, "message": format!("Message n° {n} envoyé") })),
            "create_announce_key" => s.channel.create_announce().map(|phrase| {
                json!({ "ok": true, "message": "Clé d'annonce créée",
                        "révéler": {
                            "titre": "Phrase d'annonce : à noter maintenant",
                            "texte": [
                                "Ces 24 mots ne seront plus jamais affichés : le Nœud ne les conserve pas.",
                                "Notez-les sur papier (ne les photographiez pas) et rangez-les à part de la phrase de récupération du Nœud, ailleurs que sur cette machine.",
                                "Ils servent à une seule chose : si ce Nœud est un jour compromis, ils permettent d'envoyer à vos utilisateurs une alerte qu'un attaquant ne peut ni forger ni bloquer (page Messages, « Alerte : ce Nœud est compromis »).",
                                "Les connecteurs de vos utilisateurs retiennent cette clé à leur prochain passage : créez-la tant que le Nœud est sain."
                            ],
                            "24 mots": phrase,
                            "fermer": "J'ai noté les 24 mots"
                        },
                    })
            }),
            "send_alert" => (|| {
                let k = crate::channel::announce_from_phrase(field(v, "phrase d'annonce")?)?;
                let successor = match field(v, "nœud de remplacement").map(str::trim) {
                    Ok(x) if !x.is_empty() => Some(unhex32(x)?),
                    _ => None,
                };
                let n = s
                    .channel
                    .post_alert(&node_id, &k, field(v, "message")?, successor, now)?;
                Ok(json!({ "ok": true, "message": format!(
                    "Alerte n° {n} envoyée : les utilisateurs la verront à leur prochain contact, et dans l'annuaire") }))
            })(),
            _ => return None,
        }
    };
    if r.is_ok() {
        if let Err(e) = save(sh) {
            return Some(Err(e.to_string()));
        }
    }
    Some(r)
}

fn restore_path(c: &Config) -> PathBuf {
    c.data_dir.join("restore.json")
}

/// Marqueur posé à côté de la seed quand l'identité vient d'être créée :
/// aucune sauvegarde à chercher au premier démarrage.
pub fn new_identity_marker(seed_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.nouvelle", seed_file.display()))
}

/// Nœud gelé : sauvegarde pas encore reprise (aucune publication, aucun
/// partenariat, aucune dispersion).
fn frozen(sh: &Shared) -> bool {
    sh.restore
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|r| r.frozen())
}

/// Un tour de restauration automatique (`deploiement.disaster-recovery`
/// § Restauration automatique) : reprises à la reconnexion, Nœuds joints,
/// sauvegarde du Nœud, copie locale de chaque Utilisateur. Enregistré à
/// chaque tour ; reprend après un redémarrage.
async fn restore_tick(sh: &Shared, fabric: &NetFabric, d: &mut DispersalState, now: u64) {
    use crate::recovery::{restore_snapshot, restore_user, was_attached, Net, ABSENT_AFTER_S};
    let net = Net {
        server: &fabric.server,
        dht: &fabric.dht,
        cfg: &sh.config.dispersal,
        addrs: &sh.addrs,
    };
    let before = sh.restore.lock().unwrap().clone();
    let mut r = before.clone();
    // Reprise à la reconnexion : fiche de dispersion retrouvée.
    let cands = std::mem::take(&mut sh.service.lock().unwrap().reclaim);
    for (u, salt) in cands {
        let id = hex::encode(u);
        if r.as_ref().is_some_and(|r| r.users.contains_key(&id))
            || d.users
                .get(&id)
                .is_some_and(|x| x.pointer.is_some() || !x.stripes.is_empty())
        {
            continue;
        }
        if !matches!(
            was_attached(&sh.service, &fabric.dht, &u, &salt).await,
            Ok(true)
        ) {
            continue;
        }
        {
            let mut s = sh.service.lock().unwrap();
            let quota = s.attach_policy.quota_bytes;
            s.users.entry(u).or_insert(crate::exchange::UserAccount {
                salt: salt.clone(),
                quota_bytes: quota,
                used_bytes: 0,
                root: [0; 32],
            });
            s.adopt_next_root.insert(u);
            s.restoring.insert(u);
        }
        let st = r.get_or_insert_with(|| RestoreState {
            started_at: now,
            reconnect_only: true,
            ..Default::default()
        });
        st.add_user(&u, &salt, UserOrigin::Reconnect);
        note(
            sh,
            format!(
                "utilisateur {}… repris à sa reconnexion : restauration de ses fichiers",
                &id[..16]
            ),
        );
    }
    let Some(st) = r.as_mut() else { return };
    // Étapes 2 à 5 : Nœuds joints, sauvegarde du Nœud.
    if st.frozen() {
        let pub_node = sh.service.lock().unwrap().node_id();
        let peers = fabric
            .dht
            .closest_peers(pub_node.to_vec())
            .await
            .map(|p| !p.is_empty())
            .unwrap_or(false);
        if peers && st.peers_at.is_none() {
            st.peers_at = Some(now);
        }
        if st.peers_at.is_some() {
            match restore_snapshot(&sh.service, d, &net, now).await {
                Ok(Some((users, partners))) => {
                    st.snapshot = Some(SnapshotOutcome::Restored {
                        users: users.len(),
                        partners,
                    });
                    st.snapshot_at = Some(now);
                    st.last_error = None;
                    let mut s = sh.service.lock().unwrap();
                    for (u, salt) in &users {
                        st.add_user(u, salt, UserOrigin::Snapshot);
                        s.restoring.insert(*u);
                    }
                    drop(s);
                    note(sh, format!("sauvegarde du Nœud reprise : {} utilisateur(s), {partners} partenaire(s)", users.len()));
                }
                Ok(None) => {
                    let since = *st.absent_since.get_or_insert(now);
                    if now >= since + ABSENT_AFTER_S {
                        st.snapshot = Some(SnapshotOutcome::Absent);
                        st.snapshot_at = Some(now);
                        note(
                            sh,
                            "aucune sauvegarde publiée pour cette seed : démarrage comme Nœud neuf",
                        );
                    }
                }
                Err(e) => st.last_error = Some(e),
            }
        }
    }
    // Étape 6 : copie locale de chaque Utilisateur.
    if !st.frozen() {
        for (u, salt) in st.pending_users() {
            let res = restore_user(&sh.service, d, &net, u, &salt, now).await;
            let e = st.users.get_mut(&hex::encode(u)).expect("listé");
            e.tries += 1;
            match res {
                Ok((stripes, blocks)) => {
                    e.done_at = Some(now);
                    e.stripes = stripes;
                    e.blocks = blocks;
                    e.error = None;
                    sh.service.lock().unwrap().restoring.remove(&u);
                }
                Err(err) => e.error = Some(err),
            }
        }
        let was = st.completed_at.is_some();
        st.check_complete(now);
        if !was && st.completed_at.is_some() {
            note(sh, "restauration complète");
        }
    }
    if r != before {
        if let Some(st) = &r {
            if let Ok(b) = serde_json::to_vec_pretty(st) {
                let _ = std::fs::write(restore_path(&sh.config), b);
            }
        }
        *sh.restore.lock().unwrap() = r;
    }
}

/// Étapes de la restauration, faites et restantes.
fn restore_status(sh: &Shared) -> Value {
    let Some(r) = sh.restore.lock().unwrap().clone() else {
        return Value::Null;
    };
    let entry = sh.node_entry.lock().unwrap();
    let step = |n: u32, label: &str, state: &str, detail: Value| json!({ "étape": n, "description": label, "état": state, "détail": detail });
    let mut steps = Vec::new();
    if !r.reconnect_only {
        steps.push(step(
            1,
            "Identité et preuve de travail",
            if entry.proof_ready {
                "fait"
            } else if entry.proof_error.is_some() {
                "erreur"
            } else {
                "en cours"
            },
            json!(entry.proof_error),
        ));
        steps.push(step(
            2,
            "Nœuds du réseau joints",
            if r.peers_at.is_some() {
                "fait"
            } else {
                "en cours"
            },
            json!(r
                .peers_at
                .map(|t| format!("le {t}"))
                .unwrap_or_else(|| "recherche (réseau local, nœuds d'amorçage)…".into())),
        ));
        let (s3, d3) = match (&r.snapshot, r.absent_since) {
            (Some(SnapshotOutcome::Restored { .. }), _) => ("fait", json!("sauvegarde trouvée")),
            (Some(SnapshotOutcome::Absent), _) => ("fait", json!("aucune sauvegarde : Nœud neuf")),
            (None, Some(t)) => (
                "en cours",
                json!(format!(
                    "entrée introuvable depuis le {t} ; Nœud tenu pour neuf après {} min",
                    crate::recovery::ABSENT_AFTER_S / 60
                )),
            ),
            (None, None) if r.peers_at.is_some() => ("en cours", json!(r.last_error)),
            _ => ("à faire", Value::Null),
        };
        steps.push(step(3, "Entrée du Nœud lue dans l'annuaire", s3, d3));
        let restored = matches!(r.snapshot, Some(SnapshotOutcome::Restored { .. }));
        let s45 = if r.snapshot.is_some() {
            if restored {
                "fait"
            } else {
                "sans objet"
            }
        } else if r.last_error.is_some() {
            "erreur"
        } else {
            "à faire"
        };
        steps.push(step(
            4,
            "Sauvegarde reconstruite depuis les fragments",
            s45,
            json!(r.last_error),
        ));
        steps.push(step(
            5,
            "Utilisateurs, partenaires et liste noire restaurés",
            s45,
            match &r.snapshot {
                Some(SnapshotOutcome::Restored { users, partners }) => {
                    json!(format!("{users} utilisateur(s), {partners} partenaire(s)"))
                }
                _ => Value::Null,
            },
        ));
    }
    let users: Vec<Value> = r.users.iter().map(|(id, u)| json!({
        "utilisateur": format!("{}…", &id[..16]),
        "origine": match u.origin { UserOrigin::Snapshot => "sauvegarde", UserOrigin::Reconnect => "reconnexion" },
        "état": if u.done_at.is_some() { "fait" } else if u.error.is_some() { "erreur (nouvel essai à chaque cycle)" } else { "à faire" },
        "stripes reconstruits": u.stripes,
        "blocs reconstruits": u.blocks,
        "essais": u.tries,
        "erreur": u.error,
    })).collect();
    let done = r.users.values().filter(|u| u.done_at.is_some()).count();
    let by = |o: UserOrigin| r.users.values().filter(|u| u.origin == o).count();
    steps.push(step(
        6,
        "Copie locale de chaque utilisateur (sauvegarde)",
        if r.frozen() {
            "à faire"
        } else if r
            .users
            .values()
            .filter(|u| u.origin == UserOrigin::Snapshot)
            .all(|u| u.done_at.is_some())
        {
            "fait"
        } else {
            "en cours"
        },
        json!(format!("{} utilisateur(s)", by(UserOrigin::Snapshot))),
    ));
    steps.push(step(7, "Utilisateurs repris à leur reconnexion",
        "continu", json!(format!("{} repris ; un utilisateur inconnu dont la fiche de dispersion existe pour ce Nœud est repris automatiquement", by(UserOrigin::Reconnect)))));
    steps.push(step(
        8,
        "Restauration complète, publication rétablie",
        if r.completed_at.is_some() {
            "fait"
        } else {
            "à faire"
        },
        json!(r.completed_at.map(|t| format!("le {t}"))),
    ));
    json!({
        "état": if r.completed_at.is_some() { "terminée" } else if r.frozen() { "en cours : Nœud gelé (aucune publication)" } else { "en cours" },
        "utilisateurs restaurés": format!("{done} / {}", r.users.len()),
        "étapes": steps,
        "utilisateurs": users,
    })
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
    std::fs::create_dir_all(&config.data_dir)?;
    let url = switch
        .serve(config.api_port, ASSETS, Some(&config.data_dir))
        .await?;
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
    let (mut store, store_note) = crate::volumes::open_or_rebuild(
        &config.data_dir.join("store.sqlite"),
        volumes,
        system_clock()(),
    )
    .map_err(|e| start(&e))?;
    for v in &config.volumes {
        if v.draining {
            let _ = store.set_draining(v.volume_id, true);
        }
        // Marqueur signé (`protocols.gestion-volumes` § Marqueur) : posé s'il manque.
        if crate::volumes::read_marker(&v.mount_path).is_none() {
            let _ = crate::volumes::write_marker(&v.mount_path, &seed, v.volume_id);
        }
    }
    let mut service = NodeService::with_store(seed, Box::new(store));
    service.attach_policy = config.attach;
    service.partner_policy = config.partner_policy;
    service.record_user_ips = config.record_user_ips;
    service.history_retention_s = config.history_days * 86_400;
    let vdf = chiavdf_verifier();
    let check: VdfCheck = Arc::new(move |id, proof| vdf(id, proof).unwrap_or(false));
    service.vdf = Some(check);
    let saved = load_state(&state_path(&config))?;
    let addrs = saved.restore(&mut service).map_err(DaemonError::Config)?;
    crate::inactivity::credit_downtime(&mut service, saved.saved_at, system_clock()());
    // Long arrêt (ou heure reculée) : à confirmer avant toute suppression.
    {
        let now = system_clock()();
        if saved.saved_at > 0 && service.clock_freeze.is_none() {
            let gap = now as i64 - saved.saved_at as i64;
            if gap < -crate::clock_guard::MAX_JUMP_S || gap as u64 > crate::clock_guard::LONG_STOP_S && gap > 0 {
                service.clock_freeze = Some(crate::clock_guard::Freeze {
                    at: now,
                    jump_s: gap,
                    reason: if gap < 0 { "heure antérieure au dernier arrêt".into() } else { "Nœud arrêté longtemps".into() },
                });
            }
        }
    }
    service.rebuild_emergency(system_clock()());
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
    // Identité déjà annoncée sur le réseau local par un autre Nœud :
    // pas de pile réseau (`securite.incidents-compromissions#identite-dupliquee`).
    if config.mdns {
        let me = crate::twin::peer_id_of(seed).map_err(|e| start(&e))?;
        if let Ok(twins) = crate::twin::scan(me, crate::twin::SCAN).await {
            if !twins.is_empty() {
                let msg = crate::twin::message(&twins);
                let page = json!({
                    "titre": "Nœud S3m — identité déjà utilisée",
                    "alerte": { "problème": msg.clone(), "identifiant réseau": me.to_string() },
                    "actions": [],
                });
                let st_fn: crate::local_http::StatusFn = Arc::new(move || page.clone());
                let act_fn: crate::local_http::ActionFn =
                    Arc::new(|_, _| Err("Nœud arrêté : identité déjà utilisée".to_string()));
                switch.set(st_fn, act_fn, None);
                return Err(DaemonError::Start(msg));
            }
        }
    }
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
        records_file: Some(config.data_dir.join("dht_records.json")),
    })
    .await
    .map_err(|e| start(&e))?;
    let (dht, blocks, nat) = (node_net.dht, node_net.blocks, node_net.nat);

    // Installation vide : restauration automatique depuis le réseau (seed
    // seule), sauf identité tout juste créée.
    let mut restore: Option<RestoreState> = std::fs::read(restore_path(&config))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    if fresh {
        let marker = new_identity_marker(&config.seed_file);
        if marker.exists() {
            let _ = std::fs::remove_file(&marker);
        } else {
            restore = Some(RestoreState {
                started_at: system_clock()(),
                ..Default::default()
            });
        }
    }
    if let Some(r) = &restore {
        let mut s = service.lock().unwrap();
        for (u, _) in r.pending_users() {
            s.restoring.insert(u);
        }
    }
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
        geo: std::sync::RwLock::new(Geo::open_dir(&config.data_dir)),
        geoip: Mutex::new(GeoipState::default()),
        last_partnering: Mutex::new(None),
        dispersal: tokio::sync::Mutex::new(dispersal),
        last_cycle: Mutex::new(None),
        last_redundancy: Mutex::new(None),
        last_upkeep: Mutex::new(None),
        alert_cfg: Mutex::new(config.alerts.clone()),
        alerts_sent: Mutex::new(Default::default()),
        node_entry: Arc::new(Mutex::new(NodeEntryState::default())),
        snapshot_pointer: Mutex::new(initial_pointer),
        restore: Mutex::new(restore),
        peer_id: blocks.peer_id().to_string(),
        blocks_addr: blocks.listen_addr().await.map(|a| a.to_string()),
        dht_addr: dht.listen_addr().await.map(|a| a.to_string()),
        config: config.clone(),
        priv_node: seed,
        admin_serial: std::sync::atomic::AtomicU32::new(config.admin_totp_serial),
        admin_reveal_until: Mutex::new(None),
        admin: Mutex::new(None),
        volumes_ui: Mutex::new(VolumesUi::default()),
        unblacklist: Mutex::new(Vec::new()),
        restart: tokio::sync::Notify::new(),
        journal: Mutex::new(Vec::new()),
        emergency_ui: Mutex::new(EmergencyUi::default()),
    });
    {
        // Réponses aux OwnershipQuery des partenaires (import d'un volume).
        let weak = Arc::downgrade(&shared);
        let check: crate::exchange::PlacementCheck = Arc::new(move |p, hashes| {
            let sh = weak.upgrade()?;
            let d = sh.dispersal.try_lock().ok()?;
            Some(crate::volumes::placed_with(&d, p, hashes))
        });
        shared.service.lock().unwrap().placements = Some(check);
    }

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
                // Sauvegarde pas encore reprise : rien n'est publié (elle
                // serait écrasée).
                if frozen(&sh) {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
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
                    let (announce, name) = {
                        let s = sh.service.lock().unwrap();
                        (s.channel.announce, s.name.clone())
                    };
                    {
                        let mut e = sh.node_entry.lock().unwrap();
                        e.announce = announce;
                        e.name = name;
                    }
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
                    // Relecture : entrée étrangère sous notre clé ?
                    if sh.node_entry.lock().unwrap().published_at.is_some() {
                        if let Ok(Some(env)) = dht.get(pub_node.to_vec()).await {
                            sh.node_entry.lock().unwrap().check_readback(&env);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }
    {
        let worker = NetFabric {
            server: fabric.server.clone(),
            dht: fabric.dht.clone(),
            service: shared.service.clone(),
            addrs: shared.addrs.clone(),
            excluded: shared.excluded.clone(),
        };
        let sh = shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                volumes_tick(&sh, &worker).await;
            }
        });
    }
    let sh = shared.clone();
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        let mut last = (clock(), std::time::Instant::now());
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            tick += 1;
            {
                let now = clock();
                // Garde-fou d'horloge (`deploiement.packaging#horloge`).
                if let Some(j) = crate::clock_guard::jump(last.0, last.1.elapsed().as_secs(), now) {
                    let f = crate::clock_guard::Freeze {
                        at: now,
                        jump_s: j,
                        reason: if j > 0 { "heure avancée brusquement".into() } else { "heure reculée brusquement".into() },
                    };
                    note(&sh, crate::clock_guard::describe(&f));
                    sh.service.lock().unwrap().clock_freeze = Some(f);
                }
                last = (now, std::time::Instant::now());
                alert_tick(&sh, now).await;
                let mut d = sh.dispersal.lock().await;
                restore_tick(&sh, &fabric, &mut d, now).await;
                if frozen(&sh) {
                    if let Err(e) = save_dispersal(&sh.config, &d) {
                        eprintln!("sauvegarde de la dispersion : {e}");
                    }
                } else {
                    // Retraits de liste noire demandés pendant un cycle.
                    let pending = std::mem::take(&mut *sh.unblacklist.lock().unwrap());
                    for n in &pending {
                        d.unblacklist(n);
                    }
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
                    let mut ex = excluded(&sh.config.partnering, &d);
                    ex.extend(sh.service.lock().unwrap().suspended(now));
                    *sh.excluded.lock().unwrap() = ex;
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
                    for u in crate::inactivity::purge_expired(&sh.service, &mut d, now) {
                        crate::daemon::note(
                            &sh,
                            format!("utilisateur {}… supprimé définitivement (durée d'inactivité écoulée)", &hx(&u)[..16]),
                        );
                    }
                    let report =
                        run_cycle(&sh.service, &mut d, &fabric, &sh.config.dispersal, now).await;
                    let erased = crate::dispersal_engine::purge_released(&sh.service, &mut d, now);
                    if erased > 0 {
                        crate::daemon::note(
                            &sh,
                            format!("{erased} bloc(s) libéré(s) par leurs utilisateurs effacé(s)"),
                        );
                    }
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
            }
            if tick.is_multiple_of(120) {
                let _ = refresh_successors(&sh.service, &fabric.dht).await;
            }
            if tick.is_multiple_of(2880) {
                let now = clock();
                sh.service.lock().unwrap().purge_silent_partners(now);
            }
            // Espace de secours, toutes les 5 minutes : purge des dépôts
            // oubliés, intégration des blocs déposés pendant une absence.
            if tick.is_multiple_of(10) {
                let now = clock();
                let purged = sh.service.lock().unwrap().purge_emergency(now);
                let mut seen = std::mem::take(&mut sh.emergency_ui.lock().unwrap().seen);
                let report = crate::emergency::integrate_returns(&fabric, &mut seen).await;
                {
                    let mut ui = sh.emergency_ui.lock().unwrap();
                    ui.seen = seen;
                    ui.purged += purged;
                    ui.last = Some((now, report));
                }
                // Canal : conservation des messages, copie de l'alerte dans l'annuaire.
                let due = {
                    let mut s = sh.service.lock().unwrap();
                    s.prune_channel(now);
                    s.channel.alert_due(now)
                };
                if let Some((key, env)) = due {
                    if fabric.dht.put(key.to_vec(), env).await.is_ok() {
                        sh.service.lock().unwrap().channel.alert_published_at = now;
                    }
                }
            }
            if let Err(e) = save(&sh) {
                eprintln!("sauvegarde de l'état : {e}");
            }
        }
    });
    note(&shared, "Nœud démarré");
    if let Some(m) = store_note {
        note(&shared, m);
    }
    Ok(shared)
}

/// Lignes gardées par le journal du processus.
const JOURNAL_MAX: usize = 500;

/// Inscrit un événement au journal du processus (onglet Diagnostic › Avancé).
pub fn note(sh: &Shared, msg: impl Into<String>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut j = sh.journal.lock().unwrap();
    j.push((now, msg.into()));
    let n = j.len();
    if n > JOURNAL_MAX {
        j.drain(..n - JOURNAL_MAX);
    }
}

/// `"<instant> <texte>"` → `(instant, texte)`.
fn split_event(e: &str) -> (u64, String) {
    match e.split_once(' ') {
        Some((t, m)) if t.parse::<u64>().is_ok() => (t.parse().unwrap_or(0), m.to_string()),
        _ => (0, e.to_string()),
    }
}

/// Journal fusionné du Nœud, le plus récent d'abord : processus, contrôles,
/// partenariats, volumes, et la sortie d'erreur (`node.err.log` des Nœuds
/// lancés par script).
fn journal_rows(sh: &Shared) -> Value {
    let mut rows: Vec<(u64, &'static str, String)> = sh
        .journal
        .lock()
        .unwrap()
        .iter()
        .map(|(t, m)| (*t, "Nœud", m.clone()))
        .collect();
    if let Ok(d) = sh.dispersal.try_lock() {
        rows.extend(d.upkeep.events.iter().map(|e| {
            let (t, m) = split_event(e);
            (t, "contrôles", m)
        }));
        rows.extend(d.partnering.events.iter().map(|e| {
            let (t, m) = split_event(e);
            (t, "partenaires", m)
        }));
    }
    rows.extend(
        sh.volumes_ui
            .lock()
            .unwrap()
            .events
            .iter()
            .map(|(t, m)| (*t, "volumes", m.clone())),
    );
    if let Some(err) = sh
        .config
        .source
        .as_deref()
        .and_then(Path::parent)
        .map(|d| d.join("node.err.log"))
    {
        if let Ok(text) = std::fs::read_to_string(&err) {
            let mtime = std::fs::metadata(&err)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let start = lines.len().saturating_sub(100);
            rows.extend(
                lines[start..]
                    .iter()
                    .map(|l| (mtime, "sortie d'erreur", l.to_string())),
            );
        }
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    rows.truncate(JOURNAL_MAX);
    json!(rows
        .into_iter()
        .map(|(t, src, m)| json!({ "date": if t == 0 { Value::Null } else { json!(t) }, "source": src, "événement": m }))
        .collect::<Vec<_>>())
}

// --------------------------------------------- gestion des volumes (écran)

fn volume_usage(sh: &Shared) -> Vec<crate::VolumeUsage> {
    sh.service
        .lock()
        .unwrap()
        .store
        .physical()
        .map(|p| p.volume_usage())
        .unwrap_or_default()
}

fn volumes_status(sh: &Shared, v: &mut Value) {
    let usage = volume_usage(sh);
    let ui = sh.volumes_ui.lock().unwrap();
    let rows: Vec<Value> = usage
        .iter()
        .map(|u| {
            let id = u.volume_id.to_string();
            let act = |nom: &str, titre: &str, texte: &str, libelle: &str, style: &str| {
                json!({ "nom": "volume_draft", "titre": titre, "texte": texte, "libellé": libelle, "style": style,
                        "valeurs": { "volume": id, "modification": nom } })
            };
            let mut actions = vec![json!({ "nom": "volume_draft_edit", "titre": "Chemin et capacité",
                "libellé": "Préparer ce changement",
                "champs": ["nouveau chemin", "nouvelle capacité (Go)"], "fixes": { "volume": id },
                "valeurs": { "nouveau chemin": u.mount_path.display().to_string(),
                             "nouvelle capacité (Go)": (u.max_capacity_bytes as f64 / (1u64 << 30) as f64 * 100.0).round() / 100.0 },
                "types": { "nouveau chemin": "chemin", "nouvelle capacité (Go)": "number" },
                "aide": { "nouveau chemin": "Les données doivent déjà s'y trouver",
                          "nouvelle capacité (Go)": "Capacité réservée sur ce disque" } })];
            if u.draining {
                actions.push(act("cancel_remove", "Annuler le retrait",
                    "Le volume redevient actif et reçoit de nouveau des blocs.", "Préparer l'annulation", "secondary"));
            } else {
                actions.push(act("remove", "Retirer le volume",
                    "Ses blocs sont recopiés sur les autres volumes, puis il n'est plus utilisé.", "Préparer le retrait", "secondary"));
            }
            actions.push(act("lost", "Déclarer le volume perdu",
                "Disque mort ou débranché pour de bon : ses blocs sont reconstruits depuis les partenaires.", "Préparer : déclarer perdu", "danger"));
            if u.blocks == 0 {
                actions.push(act("wipe", "Effacer le volume",
                    "Le volume est vide : ses fichiers S3m sont supprimés du disque.", "Préparer l'effacement", "danger"));
            }
            let actions = vec![json!({ "nom": "edit_volume", "libellé": "Éditer", "panneau": {
                "titre": format!("Volume {id} — {}", u.mount_path.display()),
                "texte": [
                    "1. Préparez ici un changement : il s'ajoute aux modifications en attente, rien n'est encore fait.",
                    "2. Vérifiez-les en haut de la page Volumes, puis cliquez « Appliquer » pour tout exécuter d'un coup."
                ],
                "formulaires": actions } })];
            json!({
                "volume": u.volume_id,
                "chemin": u.mount_path.display().to_string(),
                "capacité (octets)": u.max_capacity_bytes,
                "utilisé (octets)": u.used_bytes,
                "libre (octets)": u.max_capacity_bytes.saturating_sub(u.used_bytes),
                "utilisé (%)": if u.max_capacity_bytes == 0 { 0.0 } else {
                    (u.used_bytes as f64 * 1000.0 / u.max_capacity_bytes as f64).round() / 10.0 },
                "slots libres (octets)": u.free_slot_bytes,
                "blocs": u.blocks,
                "état": if u.draining { format!("vidage : {} blocs restants", u.blocks) } else { "actif".into() },
                "_actions": actions,
            })
        })
        .collect();
    // Bouton « Ajouter un volume » sous le tableau, formulaire en panneau.
    let add_form = json!({ "nom": "volume_draft_add", "libellé": "Préparer l'ajout",
            "champs": ["chemin", "capacité (Go)", "effacer et réutiliser"],
            "types": { "chemin": "chemin", "capacité (Go)": "number", "effacer et réutiliser": "bool" },
            "aide": { "chemin": "Dossier sur le disque (créé s'il n'existe pas)",
                      "effacer et réutiliser": "Seulement pour un disque d'un autre Nœud : ses données S3m seront effacées" } });
    v["volumes"] = json!({
        "_contenu": rows,
        "_formulaires": [{ "nom": "add_volume", "libellé": "Ajouter un volume", "panneau": {
            "titre": "Ajouter un volume",
            "texte": [
                "1. Choisissez le dossier (« Parcourir… » permet d'en créer un) et la capacité à réserver sur ce disque.",
                "2. L'ajout rejoint les modifications en attente, en haut de la page ; il n'est fait qu'après « Appliquer »."
            ],
            "formulaires": [add_form] } }],
    });
    v["liste des actions"] = if ui.draft.is_empty() {
        json!("aucune")
    } else {
        json!(ui
            .draft
            .iter()
            .enumerate()
            .map(|(i, c)| json!({
                "n°": i + 1,
                "modification": c.describe(),
                "_actions": [{ "nom": "volume_draft_drop", "libellé": "Retirer de la liste",
                               "valeurs": { "n": (i + 1).to_string() } }],
            }))
            .collect::<Vec<_>>())
    };
    v["imports de volumes"] = if ui.imports.is_empty() {
        json!("aucun")
    } else {
        json!(ui
            .imports
            .iter()
            .map(|(id, c)| json!({
                "volume": id,
                "retenus": c.kept,
                "déjà présents": c.already_present,
                "supprimés": c.removed,
                "en attente de partenaires": c.waiting.len(),
                "terminé": c.done,
            }))
            .collect::<Vec<_>>())
    };
    v["journal des volumes"] = json!(ui
        .events
        .iter()
        .rev()
        .map(|(t, e)| json!({ "date": t, "action": e }))
        .collect::<Vec<_>>());
    let confirm = if ui.draft.is_empty() {
        String::new()
    } else {
        format!(
            "Appliquer ces {} action(s) ?\n\n{}",
            ui.draft.len(),
            ui.draft
                .iter()
                .map(|c| format!("• {}", c.describe()))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
        // Modifications en attente : bandeau en haut de la page (`mise_en_avant`).
        if !ui.draft.is_empty() {
            let n = ui.draft.len();
            a.push(json!({ "nom": "volume_apply", "mise_en_avant": true,
                "titre": format!("{n} modification{} de volume en attente", if n > 1 { "s" } else { "" }),
                "texte": ui.draft.iter().map(|c| format!("• {}", c.describe())).collect::<Vec<_>>(),
                "libellé": format!("Appliquer {}", if n > 1 { format!("les {n} modifications") } else { "la modification".into() }),
                "champs": [], "confirmer": confirm }));
            a.push(json!({ "nom": "volume_draft_clear", "mise_en_avant": true, "libellé": "Tout annuler",
                "style": "secondary", "champs": [] }));
        }
    }
}

fn gib(v: &Value, k: &str) -> Result<Option<u64>, String> {
    let s = match v.get(k) {
        Some(Value::String(s)) => s.trim().replace(',', "."),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Ok(None),
    };
    if s.is_empty() {
        return Ok(None);
    }
    let g: f64 = s.parse().map_err(|_| format!("« {k} » : nombre attendu"))?;
    if g.is_nan() || g <= 0.0 {
        return Err(format!("« {k} » : doit être positif"));
    }
    Ok(Some((g * (1u64 << 30) as f64) as u64))
}

fn volume_action(sh: &Shared, name: &str, v: &Value) -> Result<Value, String> {
    use crate::volumes::Change;
    let text = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let num = |k: &str| -> Result<u32, String> {
        match v.get(k) {
            Some(Value::Number(n)) => n
                .as_u64()
                .map(|x| x as u32)
                .ok_or_else(|| format!("« {k} » invalide")),
            _ => text(k)
                .parse()
                .map_err(|_| format!("« {k} » : numéro attendu")),
        }
    };
    let push = |c: Change| -> Result<Value, String> {
        let mut ui = sh.volumes_ui.lock().unwrap();
        if let Some(id) = c.volume() {
            if ui.draft.iter().any(|d| d.volume() == Some(id)) {
                return Err(format!("le volume {id} a déjà une action dans la liste"));
            }
        }
        let m = format!(
            "Préparé : {} — cliquez « Appliquer » en haut de la page Volumes",
            c.describe()
        );
        ui.draft.push(c);
        Ok(json!({ "ok": true, "message": m }))
    };
    match name {
        "volume_draft_add" => {
            let path = text("chemin");
            if path.is_empty() {
                return Err("chemin manquant".into());
            }
            let capacity_bytes = gib(v, "capacité (Go)")?.ok_or("capacité manquante")?;
            let wipe = v
                .get("effacer et réutiliser")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            push(Change::Add {
                path,
                capacity_bytes,
                wipe,
            })
        }
        "volume_draft_edit" => {
            let volume_id = num("volume")?;
            // Valeurs préremplies du panneau : seules celles changées comptent.
            let current = volume_usage(sh)
                .into_iter()
                .find(|u| u.volume_id == volume_id);
            let path = Some(text("nouveau chemin")).filter(|p| {
                !p.is_empty()
                    && current
                        .as_ref()
                        .is_none_or(|u| u.mount_path.display().to_string() != *p)
            });
            let capacity_bytes = gib(v, "nouvelle capacité (Go)")?.filter(|c| {
                current
                    .as_ref()
                    .is_none_or(|u| c.abs_diff(u.max_capacity_bytes) > (1 << 30) / 100)
            });
            if path.is_none() && capacity_bytes.is_none() {
                return Err("rien à modifier".into());
            }
            push(Change::Edit {
                volume_id,
                path,
                capacity_bytes,
            })
        }
        "volume_draft" => {
            let volume_id = num("volume")?;
            push(match text("modification").as_str() {
                "remove" => Change::Remove { volume_id },
                "cancel_remove" => Change::CancelRemove { volume_id },
                "lost" => Change::Lost { volume_id },
                "wipe" => Change::Wipe { volume_id },
                other => return Err(format!("modification inconnue : {other}")),
            })
        }
        "volume_draft_drop" => {
            let n = num("n")? as usize;
            let mut ui = sh.volumes_ui.lock().unwrap();
            if n == 0 || n > ui.draft.len() {
                return Err("modification introuvable".into());
            }
            ui.draft.remove(n - 1);
            Ok(json!({ "ok": true, "message": "Action retirée de la liste" }))
        }
        "volume_draft_clear" => {
            sh.volumes_ui.lock().unwrap().draft.clear();
            Ok(json!({ "ok": true, "message": "Liste des actions vidée" }))
        }
        "volume_apply" => apply_volume_changes(sh),
        _ => Err(format!("action inconnue : {name}")),
    }
}

/// Valide toute la liste des actions puis l'applique
/// (`protocols.gestion-volumes` § Liste des actions).
fn apply_volume_changes(sh: &Shared) -> Result<Value, String> {
    use crate::volumes::{self, Change, Inspection};
    let draft = sh.volumes_ui.lock().unwrap().draft.clone();
    if draft.is_empty() {
        return Err("liste des actions vide".into());
    }
    let node_id = sh.service.lock().unwrap().node_id();
    let usage = volume_usage(sh);
    volumes::validate(&draft, &usage, &node_id)?;
    let path = sh
        .config
        .source
        .clone()
        .ok_or("configuration sans fichier source")?;
    let mut done = Vec::new();
    let mut lost_any = false;
    for c in &draft {
        let r: Result<String, String> = (|| {
            let mut s = sh.service.lock().unwrap();
            let phys = s.store.physical().ok_or("stockage sans volumes")?;
            match c {
                Change::Add {
                    path: p,
                    capacity_bytes,
                    wipe,
                } => {
                    let mount = PathBuf::from(p);
                    let next = phys
                        .volume_usage()
                        .iter()
                        .map(|u| u.volume_id)
                        .max()
                        .map_or(1, |m| m + 1);
                    let (volume_id, import) = match volumes::inspect(&mount, &node_id) {
                        Inspection::Foreign { .. } if *wipe => {
                            volumes::wipe(&mount).map_err(|e| e.to_string())?;
                            (next, false)
                        }
                        Inspection::Mine { volume_id, blocks }
                            if !usage.iter().any(|u| u.volume_id == volume_id) =>
                        {
                            (volume_id, blocks)
                        }
                        Inspection::Mine { blocks, .. } => (next, blocks),
                        Inspection::Unmarked => (next, true),
                        _ => (next, false),
                    };
                    phys.add_volume(crate::VolumeConfig {
                        volume_id,
                        mount_path: mount.clone(),
                        max_capacity_bytes: *capacity_bytes,
                    })
                    .map_err(|e| e.to_string())?;
                    volumes::write_marker(&mount, &sh.priv_node, volume_id)
                        .map_err(|e| e.to_string())?;
                    crate::settings::edit_raw(&path, |f| {
                        if let Some(a) = f["volumes"].as_array_mut() {
                            a.push(json!({ "volume_id": volume_id, "mount_path": p, "max_capacity_bytes": capacity_bytes }));
                        }
                    })?;
                    drop(s);
                    if import {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        volumes::start_import(&mount, now).map_err(|e| e.to_string())?;
                        sh.volumes_ui
                            .lock()
                            .unwrap()
                            .imports
                            .insert(volume_id, Default::default());
                    }
                    Ok(format!(
                        "volume {volume_id} ajouté{}",
                        if import {
                            " (import des blocs trouvés)"
                        } else {
                            ""
                        }
                    ))
                }
                Change::Edit {
                    volume_id,
                    path: p,
                    capacity_bytes,
                } => {
                    phys.update_volume(*volume_id, p.as_ref().map(PathBuf::from), *capacity_bytes)
                        .map_err(|e| e.to_string())?;
                    crate::settings::edit_raw(&path, |f| {
                        if let Some(e) = volume_entry(f, *volume_id) {
                            if let Some(p) = p {
                                e["mount_path"] = json!(p);
                            }
                            if let Some(c) = capacity_bytes {
                                e["max_capacity_bytes"] = json!(c);
                            }
                        }
                    })?;
                    Ok(format!("volume {volume_id} modifié"))
                }
                Change::Remove { volume_id } | Change::CancelRemove { volume_id } => {
                    let on = matches!(c, Change::Remove { .. });
                    phys.set_draining(*volume_id, on)
                        .map_err(|e| e.to_string())?;
                    crate::settings::edit_raw(&path, |f| {
                        if let Some(e) = volume_entry(f, *volume_id) {
                            if on {
                                e["draining"] = json!(true);
                            } else if let Some(o) = e.as_object_mut() {
                                o.remove("draining");
                            }
                        }
                    })?;
                    Ok(if on {
                        format!("volume {volume_id} en vidage")
                    } else {
                        format!("retrait du volume {volume_id} annulé")
                    })
                }
                Change::Lost { volume_id } => {
                    let lost = phys.forget_volume(*volume_id).map_err(|e| e.to_string())?;
                    let mut fragments = 0;
                    for (owner, hashes) in &lost {
                        if owner.owner_type == crate::OwnerType::Partner {
                            if let Ok(p) = <[u8; 32]>::try_from(owner.owner_id.as_slice()) {
                                if let Some(st) = s.partners.get_mut(&p) {
                                    st.ledger.hosted_by_partner = st
                                        .ledger
                                        .hosted_by_partner
                                        .saturating_sub(hashes.len() as u64);
                                }
                            }
                            fragments += hashes.len();
                        }
                    }
                    let blocks: usize = lost.iter().map(|(_, h)| h.len()).sum();
                    crate::settings::edit_raw(&path, |f| remove_volume_entry(f, *volume_id))?;
                    lost_any = true;
                    Ok(format!("volume {volume_id} déclaré perdu : {blocks} blocs ({fragments} fragments de partenaires) à reconstruire"))
                }
                Change::Wipe { volume_id } => {
                    let mount = usage
                        .iter()
                        .find(|u| u.volume_id == *volume_id)
                        .map(|u| u.mount_path.clone())
                        .ok_or("volume inconnu")?;
                    phys.remove_volume(*volume_id).map_err(|e| e.to_string())?;
                    volumes::wipe(&mount).map_err(|e| e.to_string())?;
                    crate::settings::edit_raw(&path, |f| remove_volume_entry(f, *volume_id))?;
                    Ok(format!("volume {volume_id} effacé et retiré"))
                }
            }
        })();
        match r {
            Ok(m) => done.push(m),
            Err(e) => {
                let msg = format!(
                    "arrêt à « {} » : {e} (déjà appliqué : {})",
                    c.describe(),
                    if done.is_empty() {
                        "rien".to_string()
                    } else {
                        done.join(" ; ")
                    }
                );
                let mut ui = sh.volumes_ui.lock().unwrap();
                ui.draft.drain(..done.len());
                ui.log(msg.clone());
                return Err(msg);
            }
        }
    }
    if lost_any {
        // Reconstruction des blocs locaux perdus depuis la parité, sans attendre.
        if let Ok(mut d) = sh.dispersal.try_lock() {
            d.upkeep.last_scrub = 0;
        }
    }
    let _ = save(sh);
    let mut ui = sh.volumes_ui.lock().unwrap();
    ui.draft.clear();
    for m in &done {
        ui.log(m.clone());
    }
    Ok(json!({ "ok": true, "message": format!("Enregistré : {}", done.join(" ; ")) }))
}

fn volume_entry(f: &mut Value, volume_id: u32) -> Option<&mut Value> {
    f["volumes"]
        .as_array_mut()?
        .iter_mut()
        .find(|e| e["volume_id"].as_u64() == Some(volume_id as u64))
}

fn remove_volume_entry(f: &mut Value, volume_id: u32) {
    if let Some(a) = f["volumes"].as_array_mut() {
        a.retain(|e| e["volume_id"].as_u64() != Some(volume_id as u64));
    }
}

/// Tâche de fond : vidage des volumes retirés, import des blocs trouvés.
async fn volumes_tick(sh: &Arc<Shared>, fabric: &NetFabric) {
    let usage = volume_usage(sh);
    for u in usage.iter().filter(|u| u.draining) {
        let started = std::time::Instant::now();
        let mut remaining = usize::MAX;
        // Lots courts, verrou relâché entre deux lots (~1 s par tour).
        while started.elapsed() < Duration::from_secs(1) && remaining > 0 {
            let r = {
                let mut s = sh.service.lock().unwrap();
                match s.store.physical() {
                    Some(p) => {
                        crate::volumes::drain_step(p, u.volume_id, crate::volumes::DRAIN_BATCH)
                    }
                    None => return,
                }
            };
            match r {
                Ok(n) => remaining = n,
                Err(e) => {
                    sh.volumes_ui
                        .lock()
                        .unwrap()
                        .log(format!("vidage du volume {} : {e}", u.volume_id));
                    break;
                }
            }
        }
        if remaining == 0 {
            let removed = {
                let mut s = sh.service.lock().unwrap();
                s.store.physical().map(|p| p.remove_volume(u.volume_id))
            };
            if let Some(Ok(())) = removed {
                let _ = std::fs::remove_file(u.mount_path.join(crate::volumes::MARKER_FILE));
                if let Some(path) = &sh.config.source {
                    let _ =
                        crate::settings::edit_raw(path, |f| remove_volume_entry(f, u.volume_id));
                }
                sh.volumes_ui
                    .lock()
                    .unwrap()
                    .log(format!("volume {} vidé et retiré", u.volume_id));
            }
        }
    }
    for u in usage.iter().filter(|u| !u.draining) {
        if crate::volumes::import_dirs(&u.mount_path).is_empty() {
            continue;
        }
        let mut counts = sh
            .volumes_ui
            .lock()
            .unwrap()
            .imports
            .get(&u.volume_id)
            .cloned()
            .unwrap_or_default();
        let done = crate::volumes::import_step(
            &sh.service,
            &sh.dispersal,
            fabric,
            &u.mount_path,
            &mut counts,
        )
        .await;
        let mut ui = sh.volumes_ui.lock().unwrap();
        ui.imports.insert(u.volume_id, counts.clone());
        if done {
            ui.log(format!(
                "import du volume {} terminé : {} retenus, {} déjà présents, {} supprimés",
                u.volume_id, counts.kept, counts.already_present, counts.removed
            ));
        }
    }
}
