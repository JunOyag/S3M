//! Partages côté Connecteur (`protocols.partage#connecteur`) : partages
//! donnés (publication du pointeur, retrait) et reçus (dossier virtuel
//! « Partagés avec moi », en lecture seule). Les appels réseau sont faits
//! par le démon ; ce module tient l'état et la lecture.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::drive::{DriveError, Meta, SharedTree};
use crate::fs::{child_key, read_directory_elem, read_file_elem, BlockHash, Entry};
use s3m_protocol::share::{SharePointer, ShareToken};

/// Fichier des partages, dans le répertoire de données.
pub const SHARES_FILE: &str = "shares.json";
/// Republication du pointeur sans changement (`network.dht-directory`).
pub const REPUBLISH_S: u64 = 2_592_000;
/// Relecture des pointeurs reçus.
pub const REFRESH_S: u64 = 600;

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn arr<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// Partage donné.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GivenShare {
    /// `share_id` (hex).
    pub id: String,
    /// Secret `S` (hex).
    pub secret: String,
    /// Chemin de l'élément dans son espace.
    pub path: String,
    pub is_dir: bool,
    /// Destinataire S3m (`user_id` hex) ; absent : lien.
    pub recipient: Option<String>,
    pub created_at: u64,
    /// 0 : sans expiration.
    pub expires_at: u64,
    /// Lien ou invitation à transmettre.
    pub text: String,
    pub seq: u64,
    /// `first_block_hash` publié (hex) et instant de publication.
    pub published_first: String,
    pub published_at: u64,
    pub revoked: bool,
    /// Retrait publié (pointeur `revoked`) et transmis au Nœud.
    pub revoke_done: bool,
    pub last_error: Option<String>,
}

impl GivenShare {
    pub fn token(&self, priv_user: &[u8; 32]) -> Option<ShareToken> {
        Some(ShareToken::new(priv_user, arr(&self.secret)?))
    }

    /// Publication due : élément changé, republication périodique, ou
    /// retrait à publier.
    pub fn publish_due(&self, first: Option<&BlockHash>, now: u64) -> bool {
        if self.revoked {
            return !self.revoke_done;
        }
        match first {
            None => true,
            Some(f) => {
                hx(f) != self.published_first
                    || now >= self.published_at.saturating_add(REPUBLISH_S)
            }
        }
    }
}

/// Pointeur reçu, conservé localement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedPointer {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub modified_at: u64,
    pub first_block_hash: String,
    pub element_key: String,
    pub node_addrs: Vec<String>,
    pub owner_label: String,
    pub grant: String,
    pub grant_signature: String,
    pub revoked: bool,
    pub seq: u64,
}

impl CachedPointer {
    pub fn of(seq: u64, p: &SharePointer) -> Self {
        CachedPointer {
            name: s3m_protocol::pseudo::sanitize(&p.name),
            is_dir: p.is_dir,
            size_bytes: p.size_bytes,
            modified_at: p.modified_at,
            first_block_hash: hx(&p.first_block_hash),
            element_key: hx(&p.element_key),
            node_addrs: p.node_addrs.clone(),
            owner_label: s3m_protocol::pseudo::sanitize(&p.owner_label),
            grant: hx(&p.grant.0),
            grant_signature: hx(&p.grant.1),
            revoked: p.revoked,
            seq,
        }
    }

    fn meta(&self) -> Meta {
        Meta {
            is_dir: self.is_dir,
            size: if self.is_dir { 0 } else { self.size_bytes },
            created_at: self.modified_at,
            modified_at: self.modified_at,
        }
    }
}

/// Partage reçu.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedShare {
    pub id: String,
    pub secret: String,
    pub sig_pub: String,
    pub added_at: u64,
    pub pointer: Option<CachedPointer>,
    pub refreshed_at: u64,
    pub last_error: Option<String>,
    /// Nom du dossier dans « Partagés avec moi », fixé à la première
    /// lecture du pointeur : un changement de pseudo du propriétaire ne le
    /// renomme pas (vide : calculé).
    #[serde(default)]
    pub folder: String,
}

/// Nom proposé pour un partage reçu : `propriétaire — nom`.
pub fn folder_name(p: &CachedPointer) -> String {
    let base = match p.owner_label.is_empty() {
        true => p.name.clone(),
        false => format!("{} — {}", p.owner_label, p.name),
    };
    base.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
}

impl ReceivedShare {
    pub fn of(token: &ShareToken, now: u64) -> Self {
        ReceivedShare {
            id: hx(&token.share_id()),
            secret: hx(&token.secret),
            sig_pub: hx(&token.sig_pub),
            added_at: now,
            ..Default::default()
        }
    }

    pub fn token(&self) -> Option<ShareToken> {
        Some(ShareToken {
            secret: arr(&self.secret)?,
            sig_pub: arr(&self.sig_pub)?,
        })
    }
}

/// État des partages, conservé dans `shares.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareStore {
    pub given: Vec<GivenShare>,
    pub received: Vec<ReceivedShare>,
}

impl ShareStore {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join(SHARES_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let p = dir.join(SHARES_FILE);
        let tmp: PathBuf = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).expect("sérialisable"))?;
        std::fs::rename(tmp, p)
    }

    /// Partages reçus visibles, avec leur nom dans le dossier virtuel :
    /// nom fixé (`propriétaire — nom` au départ), rendu unique.
    pub fn visible(&self) -> Vec<(String, CachedPointer)> {
        let mut out: Vec<(String, CachedPointer)> = Vec::new();
        for r in &self.received {
            let Some(p) = r.pointer.as_ref().filter(|p| !p.revoked) else {
                continue;
            };
            let base = match r.folder.is_empty() {
                true => folder_name(p),
                false => r.folder.clone(),
            };
            let mut name = base.clone();
            let mut n = 2;
            while out.iter().any(|(x, _)| x.eq_ignore_ascii_case(&name)) {
                name = format!("{base} ({n})");
                n += 1;
            }
            out.push((name, p.clone()));
        }
        out
    }
}

/// Lecture d'un bloc d'un partage chez le Nœud de son propriétaire :
/// `(adresses, autorisation, signature, hash)`.
pub type Fetch = Arc<dyn Fn(&[String], &[u8], &[u8], &BlockHash) -> Option<Vec<u8>> + Send + Sync>;

/// Dossier « Partagés avec moi » : lecture seule, blocs lus chez le Nœud
/// du propriétaire et vérifiés comme les siens.
pub struct ReceivedTree {
    pub store: Arc<Mutex<ShareStore>>,
    pub fetch: Fetch,
    cache: Mutex<HashMap<BlockHash, Vec<u8>>>,
}

/// Blocs gardés en mémoire au plus.
const CACHE_BLOCKS: usize = 256;

impl ReceivedTree {
    pub fn new(store: Arc<Mutex<ShareStore>>, fetch: Fetch) -> Self {
        ReceivedTree {
            store,
            fetch,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn getter<'a>(&'a self, p: &'a CachedPointer) -> impl Fn(&BlockHash) -> Option<Vec<u8>> + 'a {
        move |h: &BlockHash| {
            if let Some(b) = self.cache.lock().unwrap().get(h) {
                return Some(b.clone());
            }
            let grant = hex::decode(&p.grant).ok()?;
            let sig = hex::decode(&p.grant_signature).ok()?;
            let b = (self.fetch)(&p.node_addrs, &grant, &sig, h)?;
            let mut c = self.cache.lock().unwrap();
            if c.len() >= CACHE_BLOCKS {
                c.clear();
            }
            c.insert(*h, b.clone());
            Some(b)
        }
    }

    /// Partage et chemin intérieur d'un chemin relatif au dossier virtuel.
    fn split(&self, rel: &str) -> Option<(CachedPointer, Vec<String>)> {
        let parts: Vec<String> = rel
            .split('/')
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect();
        let first = parts.first()?;
        let visible = self.store.lock().unwrap().visible();
        let (_, p) = visible
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(first))?;
        Some((p, parts[1..].to_vec()))
    }

    /// Entrée au bout de `inner` dans le partage `p` : `(entrée, clé)`.
    fn walk(
        &self,
        p: &CachedPointer,
        inner: &[String],
    ) -> Result<Option<(Entry, [u8; 32])>, DriveError> {
        let key: [u8; 32] = arr(&p.element_key).ok_or(DriveError::NotFound)?;
        let first: BlockHash = arr(&p.first_block_hash).ok_or(DriveError::NotFound)?;
        let mut cur = Entry {
            name: p.name.clone(),
            size_bytes: p.size_bytes,
            mime_type: if p.is_dir {
                crate::access::DIRECTORY_MIME.into()
            } else {
                String::new()
            },
            first_block_hash: first,
            modified_at: p.modified_at,
            created_at: p.modified_at,
            ..Default::default()
        };
        let mut k = key;
        let get = self.getter(p);
        for part in inner {
            if cur.mime_type != crate::access::DIRECTORY_MIME {
                return Ok(None);
            }
            let entries = read_directory_elem(&cur.first_block_hash, &k, &get)?;
            let Some(e) = entries
                .into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(part))
            else {
                return Ok(None);
            };
            k = child_key(&k, &e)?;
            cur = e;
        }
        Ok(Some((cur, k)))
    }
}

impl SharedTree for ReceivedTree {
    fn version(&self) -> u64 {
        let v = self.store.lock().unwrap().visible();
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for (n, p) in &v {
            std::hash::Hash::hash(n, &mut h);
            std::hash::Hash::hash(&p.first_block_hash, &mut h);
            std::hash::Hash::hash(&p.seq, &mut h);
        }
        std::hash::Hasher::finish(&h)
    }

    fn stat(&self, rel: &str) -> Result<Option<Meta>, DriveError> {
        if rel == "/" {
            return Ok(Some(Meta {
                is_dir: true,
                size: 0,
                created_at: 0,
                modified_at: 0,
            }));
        }
        let Some((p, inner)) = self.split(rel) else {
            return Ok(None);
        };
        if inner.is_empty() {
            return Ok(Some(p.meta()));
        }
        Ok(self.walk(&p, &inner)?.map(|(e, _)| Meta::of(&e)))
    }

    fn list(&self, rel: &str) -> Result<Vec<(String, Meta)>, DriveError> {
        if rel == "/" {
            let v = self.store.lock().unwrap().visible();
            return Ok(v.into_iter().map(|(n, p)| (n, p.meta())).collect());
        }
        let (p, inner) = self.split(rel).ok_or(DriveError::NotFound)?;
        let (e, k) = self.walk(&p, &inner)?.ok_or(DriveError::NotFound)?;
        if e.mime_type != crate::access::DIRECTORY_MIME {
            return Err(DriveError::NotADirectory);
        }
        let get = self.getter(&p);
        Ok(read_directory_elem(&e.first_block_hash, &k, &get)?
            .iter()
            .map(|e| (e.name.clone(), Meta::of(e)))
            .collect())
    }

    fn read(&self, rel: &str, offset: u64, len: usize) -> Result<Vec<u8>, DriveError> {
        let (p, inner) = self.split(rel).ok_or(DriveError::NotFound)?;
        let (e, k) = self.walk(&p, &inner)?.ok_or(DriveError::NotFound)?;
        if e.mime_type == crate::access::DIRECTORY_MIME {
            return Err(DriveError::IsADirectory);
        }
        let get = self.getter(&p);
        let data = read_file_elem(&e.first_block_hash, e.size_bytes, &k, &get)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len).min(data.len());
        Ok(data[start..end].to_vec())
    }
}
