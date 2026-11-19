//! Amorçage et résolution — id `network.bootstrap`, component `connector`
//! (spec V3). Réf. spec : docs/01-network-dht/bootstrap.md.
//!
//! Périmètre arbitré le 2026-11-19 (`impl/SPEC_GAPS.md`) :
//! - entrée dans le réseau par liste de Nœuds d'amorçage en configuration
//!   (traversée de NAT : fonctionnalité séparée, plus tard) ;
//! - cache local minimal ([`LocalCache`]) : Nœud courant, `fs_root_hash`,
//!   horodatage ;
//! - étapes 1 à 3 du chemin à froid (seed → entrée User → `K_self` → Nœud
//!   courant) ; l'étape 4 (récupération du bloc racine auprès du Nœud) est
//!   rattachée à l'id qui définira l'échange de blocs.

use std::path::Path;

use p2p_storage_core::k_self::derive_k_self;
use p2p_storage_core::keys::derive_user_dht_key;
use p2p_storage_protocol::dht::{open_blob, verify_migration_pointer, DhtError, EntryKind};
use p2p_storage_protocol::fb::dht as fb;

use crate::dht_directory::{DhtClient, DhtClientError};

/// Erreurs d'amorçage.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error(transparent)]
    Dht(#[from] DhtClientError),
    #[error(transparent)]
    Entry(#[from] DhtError),
    #[error(transparent)]
    Core(#[from] p2p_storage_core::CoreError),
    #[error("aucune entrée DHT User et aucun cache local")]
    UserNotFound,
    #[error("entrée User sans attachement")]
    NoAttachment,
    #[error("entrée Node introuvable pour le Nœud courant")]
    NodeNotFound,
    #[error("format invalide : {0}")]
    Format(&'static str),
    #[error("cache local : {0}")]
    Cache(String),
}

/// Cache local du Connecteur (« chemin rapide ») — fichier binaire :
/// `u16be(1) ‖ node_id (32 o) ‖ u64be(timestamp) ‖ u32be(len) ‖ fs_root_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCache {
    pub node_id: [u8; 32],
    pub fs_root_hash: Vec<u8>,
    /// Horodatage de l'entrée DHT User dont provient ce cache.
    pub timestamp: u64,
}

const CACHE_VERSION: u16 = 1;

impl LocalCache {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = CACHE_VERSION.to_be_bytes().to_vec();
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&(self.fs_root_hash.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.fs_root_hash);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BootstrapError> {
        let bad = || BootstrapError::Cache("format".into());
        if bytes.len() < 46 || bytes[..2] != CACHE_VERSION.to_be_bytes() {
            return Err(bad());
        }
        let len = u32::from_be_bytes(bytes[42..46].try_into().unwrap()) as usize;
        if bytes.len() != 46 + len {
            return Err(bad());
        }
        Ok(Self {
            node_id: bytes[2..34].try_into().unwrap(),
            timestamp: u64::from_be_bytes(bytes[34..42].try_into().unwrap()),
            fs_root_hash: bytes[46..].to_vec(),
        })
    }

    pub fn load(path: &Path) -> Result<Option<Self>, BootstrapError> {
        match std::fs::read(path) {
            Ok(b) => Self::decode(&b).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BootstrapError::Cache(e.to_string())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), BootstrapError> {
        std::fs::write(path, self.encode()).map_err(|e| BootstrapError::Cache(e.to_string()))
    }
}

/// Origine de la référence `fs_root_hash` retenue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Cache local, aucune entrée DHT plus récente.
    Cache,
    /// Entrée DHT User (pas de cache, ou entrée plus récente : un autre
    /// Connecteur du même User a écrit depuis).
    Dht,
}

/// Suivi du `migration_pointer` du Nœud courant (un seul saut automatique).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// Aucun pointeur valide.
    None,
    /// Pointeur valide suivi : le Nœud courant devient `new_node_id`
    /// (réattache à déclencher).
    Followed { from: [u8; 32] },
    /// Le nouveau Nœud porte lui-même un pointeur : confirmation explicite
    /// de l'utilisateur requise avant tout second saut.
    NeedsConfirmation { next: Vec<u8> },
}

/// Résultat de la résolution.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub source: Source,
    pub node_id: [u8; 32],
    pub node_ip: Option<String>,
    pub node_port: u16,
    pub fs_root_hash: Vec<u8>,
    /// Sel du répertoire racine et version de clé (absents si `Source::Cache`).
    pub root_encryption_salt: Option<Vec<u8>>,
    pub key_version: Option<u16>,
    pub user_entry_timestamp: u64,
    pub migration: Migration,
}

fn payload(envelope: &[u8]) -> Result<&[u8], BootstrapError> {
    let env = flatbuffers::root::<fb::DhtEnvelope>(envelope)
        .map_err(|_| BootstrapError::Format("DhtEnvelope"))?;
    Ok(env
        .payload()
        .ok_or(BootstrapError::Format("payload"))?
        .bytes())
}

struct UserView {
    timestamp: u64,
    node_id: [u8; 32],
    fs_root_hash: Vec<u8>,
    salt: Option<Vec<u8>>,
    key_version: u16,
}

/// Étapes 1 à 3 : `user_dht_key` → entrée User vérifiée → déchiffrement
/// sous `K_self` → Nœud courant (attachement le plus récent).
async fn read_user(
    client: &DhtClient,
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
) -> Result<Option<UserView>, BootstrapError> {
    let key = derive_user_dht_key(priv_user, pub_user)?;
    let Some(envelope) = client.get(key.to_vec()).await? else {
        return Ok(None);
    };
    let entry = fb::root_as_user_entry(payload(&envelope)?)
        .map_err(|_| BootstrapError::Format("UserEntry"))?;
    let blob = entry
        .ciphertext()
        .ok_or(BootstrapError::Format("ciphertext"))?;
    let k_self = derive_k_self(priv_user)?;
    let clear = open_blob(&k_self, EntryKind::User.blob_aad_label(), blob.bytes())?;
    let plain = flatbuffers::root::<fb::UserEntryPlaintext>(&clear)
        .map_err(|_| BootstrapError::Format("UserEntryPlaintext"))?;
    let current = plain
        .attachments()
        .and_then(|a| a.iter().max_by_key(|r| r.timestamp()))
        .ok_or(BootstrapError::NoAttachment)?;
    let node_id: [u8; 32] = current
        .node_id()
        .ok_or(BootstrapError::NoAttachment)?
        .bytes()
        .try_into()
        .map_err(|_| BootstrapError::Format("node_id"))?;
    Ok(Some(UserView {
        timestamp: entry.timestamp(),
        node_id,
        fs_root_hash: plain
            .fs_root_hash()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
        salt: plain.encryption_salt().map(|v| v.bytes().to_vec()),
        key_version: plain.key_version(),
    }))
}

struct NodeView {
    ip: Option<String>,
    port: u16,
    pointer_target: Option<Vec<u8>>,
}

async fn read_node(
    client: &DhtClient,
    node_id: &[u8; 32],
) -> Result<Option<NodeView>, BootstrapError> {
    let Some(envelope) = client.get(node_id.to_vec()).await? else {
        return Ok(None);
    };
    let e = fb::root_as_node_entry(payload(&envelope)?)
        .map_err(|_| BootstrapError::Format("NodeEntry"))?;
    let pointer_target = match (e.migration_pointer(), e.pub_node_recovery()) {
        (Some(p), Some(recovery)) => {
            verify_migration_pointer(p, recovery.bytes(), node_id, None).ok()
        }
        _ => None,
    };
    Ok(Some(NodeView {
        ip: e.ip().map(str::to_owned),
        port: e.port(),
        pointer_target,
    }))
}

/// Résout le Nœud courant et la racine du système de fichiers.
///
/// Chemin rapide (`cache` présent) : l'entrée DHT User est toujours
/// consultée ; si elle est plus récente que le cache, sa racine est adoptée
/// (`Source::Dht`), sinon le cache fait foi. Chemin à froid (pas de cache) :
/// seed seule. Le `migration_pointer` du Nœud est suivi d'un seul saut, et
/// seulement vers une entrée Node existante et valide.
pub async fn resolve(
    client: &DhtClient,
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
    cache: Option<&LocalCache>,
) -> Result<Resolution, BootstrapError> {
    let user = read_user(client, priv_user, pub_user).await?;
    let (source, mut node_id, fs_root_hash, salt, key_version, ts) = match (user, cache) {
        (Some(u), Some(c)) if c.timestamp >= u.timestamp => (
            Source::Cache,
            c.node_id,
            c.fs_root_hash.clone(),
            None,
            None,
            c.timestamp,
        ),
        (Some(u), _) => (
            Source::Dht,
            u.node_id,
            u.fs_root_hash,
            u.salt,
            Some(u.key_version),
            u.timestamp,
        ),
        (None, Some(c)) => (
            Source::Cache,
            c.node_id,
            c.fs_root_hash.clone(),
            None,
            None,
            c.timestamp,
        ),
        (None, None) => return Err(BootstrapError::UserNotFound),
    };
    let mut node = read_node(client, &node_id)
        .await?
        .ok_or(BootstrapError::NodeNotFound)?;
    let mut migration = Migration::None;
    if let Some(target) = node.pointer_target.clone() {
        if let Ok(new_id) = <[u8; 32]>::try_from(target.as_slice()) {
            if let Some(new_node) = read_node(client, &new_id).await? {
                migration = match &new_node.pointer_target {
                    Some(next) => Migration::NeedsConfirmation { next: next.clone() },
                    None => Migration::Followed { from: node_id },
                };
                if matches!(migration, Migration::Followed { .. }) {
                    node_id = new_id;
                    node = new_node;
                }
            }
        }
    }
    Ok(Resolution {
        source,
        node_id,
        node_ip: node.ip,
        node_port: node.port,
        fs_root_hash,
        root_encryption_salt: salt,
        key_version,
        user_entry_timestamp: ts,
        migration,
    })
}
