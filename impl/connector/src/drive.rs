//! Moteur du lecteur monté — id `protocols.acces-applicatif` (backends) et
//! `protocols.ecriture-differee`. Réf. spec :
//! docs/04-protocols/acces-applicatif.md, docs/04-protocols/ecriture-differee.md.
//!
//! Indépendant du système (WinFsp, FUSE) : opérations par chemin (`/a/b`).
//! - Lecture : modifications locales d'abord, sinon système de fichiers
//!   distant (`access::Volume`, récupération paresseuse) avec cache local
//!   par `first_block_hash`.
//! - Écriture : copie locale reconstituée, modifiée par plages d'octets ;
//!   les modifications (fichier, répertoire, déplacement, suppression) sont
//!   journalisées sur disque.
//! - Synchronisation : réémission copy-on-write des fichiers modifiés et des
//!   seuls répertoires ancêtres, envoi des blocs au Nœud, puis validation de
//!   la nouvelle racine (`CommitRoot`) ; un refus = conflit, rien n'est perdu.

use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::access::{AccessError, Root, Volume, DIRECTORY_MIME};
use crate::fs::{write_directory, write_file, BlockHash, Entry, Sealing};
use crate::integrity::BlockSource;

/// Version de clé maîtresse utilisée par ce Connecteur.
pub const KEY_VERSION: u16 = 1;
const FILE_MIME: &str = "application/octet-stream";
const NO_ROOT: BlockHash = [0; 32];

/// Accès aux blocs et à la racine chez le Nœud.
pub trait BlockIo: Send + Sync {
    fn get(&self, hash: &BlockHash) -> Option<Vec<u8>>;
    fn put(&self, hash: &BlockHash, frame: Vec<u8>) -> Result<(), String>;
    /// `Ok(None)` : validée ; `Ok(Some(courante))` : conflit.
    fn commit(&self, base: &BlockHash, new: &BlockHash) -> Result<Option<BlockHash>, String>;
}

struct Source<'a>(&'a dyn BlockIo);

impl BlockSource for Source<'_> {
    fn fetch_from_node(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        self.0.get(hash)
    }
    fn reconstruct(&self, _: &BlockHash) -> Option<Vec<u8>> {
        None
    }
}

/// Erreurs du lecteur.
#[derive(Debug, thiserror::Error)]
pub enum DriveError {
    #[error("introuvable")]
    NotFound,
    #[error("existe déjà")]
    Exists,
    #[error("pas un répertoire")]
    NotADirectory,
    #[error("est un répertoire")]
    IsADirectory,
    #[error("répertoire non vide")]
    NotEmpty,
    #[error("conflit : la racine a changé chez le Nœud")]
    Conflict,
    #[error("Nœud : {0}")]
    Node(String),
    #[error(transparent)]
    Access(#[from] AccessError),
    #[error(transparent)]
    Fs(#[from] crate::fs::FsError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Attributs présentés au système.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub is_dir: bool,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
}

impl Meta {
    fn of(e: &Entry) -> Self {
        Meta {
            is_dir: e.mime_type == DIRECTORY_MIME,
            size: e.size_bytes,
            created_at: e.created_at,
            modified_at: e.modified_at,
        }
    }
}

// --------------------------------------------------- journal persistant

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SavedEntry {
    name: String,
    size_bytes: u64,
    mime_type: String,
    first_block_hash: String,
    encryption_salt: String,
    key_version: u16,
    permissions: u16,
    created_at: u64,
    modified_at: u64,
}

impl From<&Entry> for SavedEntry {
    fn from(e: &Entry) -> Self {
        SavedEntry {
            name: e.name.clone(),
            size_bytes: e.size_bytes,
            mime_type: e.mime_type.clone(),
            first_block_hash: hex::encode(e.first_block_hash),
            encryption_salt: hex::encode(e.encryption_salt),
            key_version: e.key_version,
            permissions: e.permissions,
            created_at: e.created_at,
            modified_at: e.modified_at,
        }
    }
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0; N])
}

impl From<&SavedEntry> for Entry {
    fn from(e: &SavedEntry) -> Self {
        Entry {
            name: e.name.clone(),
            size_bytes: e.size_bytes,
            mime_type: e.mime_type.clone(),
            first_block_hash: arr(&e.first_block_hash),
            encryption_salt: arr(&e.encryption_salt),
            key_version: e.key_version,
            permissions: e.permissions,
            created_at: e.created_at,
            modified_at: e.modified_at,
        }
    }
}

/// Modification locale en attente de synchronisation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum Change {
    /// Contenu local complet (fichier du répertoire de travail).
    File {
        cache: String,
        created_at: u64,
        modified_at: u64,
    },
    /// Nouveau répertoire.
    Dir {
        created_at: u64,
    },
    /// Élément distant inchangé, déplacé ici.
    Moved(SavedEntry),
    Deleted,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Journal {
    fs_root_hash: String,
    encryption_salt: String,
    key_version: u16,
    changes: BTreeMap<String, Change>,
    next_file: u64,
}

// ---------------------------------------------------------------- chemins

fn norm(path: &str) -> String {
    let parts: Vec<&str> = path
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    format!("/{}", parts.join("/"))
}

fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn is_under(path: &str, ancestor: &str) -> bool {
    ancestor == "/" && path != "/"
        || path.len() > ancestor.len()
            && path.starts_with(ancestor)
            && path.as_bytes()[ancestor.len()] == b'/'
}

// ------------------------------------------------------------------ lecteur

/// Lecteur : vue fusionnée (distant + modifications locales).
pub struct Drive {
    io: Arc<dyn BlockIo>,
    keys: HashMap<u16, [u8; 32]>,
    root: Root,
    journal: Journal,
    workspace: PathBuf,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    nonce: Box<dyn FnMut() -> [u8; 12] + Send>,
    salt: Box<dyn FnMut() -> [u8; 16] + Send>,
    /// Incidents d'intégrité relevés en lecture.
    pub incidents: Vec<BlockHash>,
    /// Dernier conflit de synchronisation (racine courante chez le Nœud).
    pub conflict: Option<BlockHash>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

impl Drive {
    /// Ouvre le lecteur : `workspace` contient le journal, les copies
    /// locales et le cache de lecture.
    pub fn open(
        io: Arc<dyn BlockIo>,
        master_key: [u8; 32],
        workspace: PathBuf,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, DriveError> {
        std::fs::create_dir_all(workspace.join("files"))?;
        std::fs::create_dir_all(workspace.join("cache"))?;
        let journal: Journal = match std::fs::read(workspace.join("journal.json")) {
            Ok(b) => serde_json::from_slice(&b).map_err(std::io::Error::other)?,
            Err(_) => Journal {
                fs_root_hash: hex::encode(NO_ROOT),
                encryption_salt: hex::encode([0u8; 16]),
                key_version: KEY_VERSION,
                ..Default::default()
            },
        };
        let root = Root {
            fs_root_hash: arr(&journal.fs_root_hash),
            encryption_salt: arr(&journal.encryption_salt),
            key_version: journal.key_version,
        };
        Ok(Self {
            io,
            keys: [(KEY_VERSION, master_key)].into(),
            root,
            journal,
            workspace,
            clock,
            nonce: Box::new(random::<12>),
            salt: Box::new(random::<16>),
            incidents: Vec::new(),
            conflict: None,
        })
    }

    /// Racine courante (`fs_root_hash`).
    pub fn root_hash(&self) -> BlockHash {
        self.root.fs_root_hash
    }

    /// Racine courante complète (hash, sel, version).
    pub fn root(&self) -> Root {
        self.root.clone()
    }

    /// Nouvel appareil : adopte la racine relue dans l'entrée DHT User si le
    /// lecteur est vide et sans modification en attente.
    pub fn adopt_root(&mut self, root: Root) -> Result<bool, DriveError> {
        if self.root.fs_root_hash != NO_ROOT || self.pending() > 0 || root.fs_root_hash == NO_ROOT {
            return Ok(false);
        }
        self.journal.fs_root_hash = hex::encode(root.fs_root_hash);
        self.journal.encryption_salt = hex::encode(root.encryption_salt);
        self.journal.key_version = root.key_version;
        self.root = root;
        self.persist()?;
        Ok(true)
    }

    /// Nombre de modifications en attente.
    pub fn pending(&self) -> usize {
        self.journal.changes.len()
    }

    fn persist(&self) -> Result<(), DriveError> {
        let tmp = self.workspace.join("journal.json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec(&self.journal).expect("sérialisable"),
        )?;
        std::fs::rename(tmp, self.workspace.join("journal.json"))?;
        Ok(())
    }

    fn with_volume<T>(
        &mut self,
        root: Root,
        f: impl FnOnce(&Volume<'_>) -> Result<T, AccessError>,
    ) -> Result<T, DriveError> {
        let src = Source(self.io.as_ref());
        let v = Volume::new(&src, &self.keys, root);
        let r = f(&v);
        let log = v.integrity.into_inner();
        self.incidents
            .extend(log.pending_incidents.iter().map(|i| i.block_hash));
        Ok(r?)
    }

    /// Entrée distante de `path` en tenant compte des déplacements et
    /// suppressions d'ancêtres (`path` lui-même hors journal).
    fn remote_entry(&mut self, path: &str) -> Result<Option<Entry>, DriveError> {
        let ancestor = self
            .journal
            .changes
            .iter()
            .filter(|(k, _)| is_under(path, k))
            .max_by_key(|(k, _)| k.len())
            .map(|(k, c)| (k.clone(), c.clone()));
        let (root, rel) = match ancestor {
            None => {
                if self.root.fs_root_hash == NO_ROOT {
                    return Ok(None);
                }
                (self.root.clone(), path.to_string())
            }
            Some((k, Change::Moved(e))) if e.mime_type == DIRECTORY_MIME => {
                let e = Entry::from(&e);
                (
                    Root {
                        fs_root_hash: e.first_block_hash,
                        encryption_salt: e.encryption_salt,
                        key_version: e.key_version,
                    },
                    path[k.len()..].to_string(),
                )
            }
            Some(_) => return Ok(None),
        };
        match self.with_volume(root, |v| v.lookup(&rel)) {
            Err(DriveError::Access(AccessError::NotFound(_))) => Ok(None),
            Err(DriveError::Access(AccessError::NotADirectory(_))) => Ok(None),
            r => r,
        }
    }

    /// Attributs de `path` (`None` : absent).
    pub fn stat(&mut self, path: &str) -> Result<Option<Meta>, DriveError> {
        let p = norm(path);
        if p == "/" {
            return Ok(Some(Meta {
                is_dir: true,
                size: 0,
                created_at: 0,
                modified_at: 0,
            }));
        }
        match self.journal.changes.get(&p).cloned() {
            Some(Change::File {
                cache,
                created_at,
                modified_at,
            }) => Ok(Some(Meta {
                is_dir: false,
                size: std::fs::metadata(self.workspace.join("files").join(cache))?.len(),
                created_at,
                modified_at,
            })),
            Some(Change::Dir { created_at }) => Ok(Some(Meta {
                is_dir: true,
                size: 0,
                created_at,
                modified_at: created_at,
            })),
            Some(Change::Moved(e)) => Ok(Some(Meta::of(&Entry::from(&e)))),
            Some(Change::Deleted) => Ok(None),
            None => Ok(self.remote_entry(&p)?.map(|e| Meta::of(&e))),
        }
    }

    /// Entrées distantes du répertoire `path` (avant modifications locales).
    fn base_entries(&mut self, path: &str) -> Result<Vec<Entry>, DriveError> {
        let dir = match self.journal.changes.get(path).cloned() {
            Some(Change::Dir { .. }) => return Ok(Vec::new()),
            Some(Change::Moved(e)) => Some(Entry::from(&e)),
            Some(_) => return Err(DriveError::NotADirectory),
            None if path == "/" => {
                if self.root.fs_root_hash == NO_ROOT {
                    return Ok(Vec::new());
                }
                let root = self.root.clone();
                return self.with_volume(root, |v| v.list("/"));
            }
            None => self.remote_entry(path)?,
        };
        match dir {
            None => Ok(Vec::new()),
            Some(e) if e.mime_type == DIRECTORY_MIME => {
                let root = Root {
                    fs_root_hash: e.first_block_hash,
                    encryption_salt: e.encryption_salt,
                    key_version: e.key_version,
                };
                self.with_volume(root, |v| v.list("/"))
            }
            Some(_) => Err(DriveError::NotADirectory),
        }
    }

    /// Liste le répertoire `path` : `(nom, attributs)`.
    pub fn list(&mut self, path: &str) -> Result<Vec<(String, Meta)>, DriveError> {
        let p = norm(path);
        match self.stat(&p)? {
            None => return Err(DriveError::NotFound),
            Some(m) if !m.is_dir => return Err(DriveError::NotADirectory),
            _ => {}
        }
        let mut out: BTreeMap<String, Meta> = self
            .base_entries(&p)?
            .iter()
            .map(|e| (e.name.clone(), Meta::of(e)))
            .collect();
        let children: Vec<String> = self
            .journal
            .changes
            .keys()
            .filter(|k| parent(k) == p && *k != "/")
            .cloned()
            .collect();
        for k in children {
            let name = base_name(&k).to_string();
            match self.stat(&k)? {
                Some(m) => out.insert(name, m),
                None => out.remove(&name),
            };
        }
        Ok(out.into_iter().collect())
    }

    fn cache_path(&self, e: &Entry) -> PathBuf {
        self.workspace
            .join("cache")
            .join(hex::encode(e.first_block_hash))
    }

    /// Contenu complet d'un fichier distant (cache local par hash).
    fn remote_content(&mut self, e: &Entry) -> Result<Vec<u8>, DriveError> {
        let cache = self.cache_path(e);
        if let Ok(b) = std::fs::read(&cache) {
            return Ok(b);
        }
        let root = Root {
            fs_root_hash: NO_ROOT,
            encryption_salt: e.encryption_salt,
            key_version: e.key_version,
        };
        let entry = e.clone();
        let data = self.with_volume(root, move |v| v.read_entry(&entry))?;
        let _ = std::fs::write(&cache, &data);
        Ok(data)
    }

    fn file_entry(&mut self, p: &str) -> Result<Entry, DriveError> {
        let e = match self.journal.changes.get(p).cloned() {
            Some(Change::Moved(e)) => Some(Entry::from(&e)),
            Some(_) => None,
            None => self.remote_entry(p)?,
        };
        match e {
            None => Err(DriveError::NotFound),
            Some(e) if e.mime_type == DIRECTORY_MIME => Err(DriveError::IsADirectory),
            Some(e) => Ok(e),
        }
    }

    /// Lit `len` octets à partir de `offset`.
    pub fn read(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, DriveError> {
        let p = norm(path);
        if let Some(Change::File { cache, .. }) = self.journal.changes.get(&p) {
            let mut f = std::fs::File::open(self.workspace.join("files").join(cache))?;
            f.seek(SeekFrom::Start(offset))?;
            let mut buf = Vec::with_capacity(len);
            f.take(len as u64).read_to_end(&mut buf)?;
            return Ok(buf);
        }
        let e = self.file_entry(&p)?;
        let data = self.remote_content(&e)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len).min(data.len());
        Ok(data[start..end].to_vec())
    }

    /// Copie locale modifiable de `path` (reconstituée si distante).
    fn ensure_local(&mut self, p: &str) -> Result<PathBuf, DriveError> {
        if let Some(Change::File { cache, .. }) = self.journal.changes.get(p) {
            return Ok(self.workspace.join("files").join(cache));
        }
        let e = self.file_entry(p)?;
        let data = self.remote_content(&e)?;
        let name = self.new_file_name();
        let path = self.workspace.join("files").join(&name);
        std::fs::write(&path, data)?;
        self.journal.changes.insert(
            p.to_string(),
            Change::File {
                cache: name,
                created_at: e.created_at,
                modified_at: (self.clock)(),
            },
        );
        self.persist()?;
        Ok(path)
    }

    fn new_file_name(&mut self) -> String {
        self.journal.next_file += 1;
        format!("{:016x}", self.journal.next_file)
    }

    fn touch(&mut self, p: &str) {
        let now = (self.clock)();
        if let Some(Change::File { modified_at, .. }) = self.journal.changes.get_mut(p) {
            *modified_at = now;
        }
    }

    /// Écrit `data` à `offset` (plage d'octets) ; rend la nouvelle taille.
    pub fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<u64, DriveError> {
        let p = norm(path);
        let local = self.ensure_local(&p)?;
        let mut f = OpenOptions::new().write(true).open(local)?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(data)?;
        let size = f.metadata()?.len();
        self.touch(&p);
        self.persist()?;
        Ok(size)
    }

    /// Fixe la taille du fichier.
    pub fn set_size(&mut self, path: &str, size: u64) -> Result<(), DriveError> {
        let p = norm(path);
        let local = self.ensure_local(&p)?;
        OpenOptions::new().write(true).open(local)?.set_len(size)?;
        self.touch(&p);
        self.persist()
    }

    /// Crée un fichier vide ou un répertoire.
    pub fn create(&mut self, path: &str, is_dir: bool) -> Result<(), DriveError> {
        let p = norm(path);
        if p == "/" || self.stat(&p)?.is_some() {
            return Err(DriveError::Exists);
        }
        match self.stat(parent(&p))? {
            Some(m) if m.is_dir => {}
            Some(_) => return Err(DriveError::NotADirectory),
            None => return Err(DriveError::NotFound),
        }
        let now = (self.clock)();
        let change = if is_dir {
            Change::Dir { created_at: now }
        } else {
            let name = self.new_file_name();
            std::fs::write(self.workspace.join("files").join(&name), [])?;
            Change::File {
                cache: name,
                created_at: now,
                modified_at: now,
            }
        };
        self.journal.changes.insert(p, change);
        self.persist()
    }

    fn drop_change(&mut self, k: &str) {
        if let Some(Change::File { cache, .. }) = self.journal.changes.remove(k) {
            let _ = std::fs::remove_file(self.workspace.join("files").join(cache));
        }
    }

    /// Supprime un fichier ou un répertoire vide.
    pub fn remove(&mut self, path: &str) -> Result<(), DriveError> {
        let p = norm(path);
        let m = self.stat(&p)?.ok_or(DriveError::NotFound)?;
        if m.is_dir && !self.list(&p)?.is_empty() {
            return Err(DriveError::NotEmpty);
        }
        let below: Vec<String> = self
            .journal
            .changes
            .keys()
            .filter(|k| is_under(k, &p))
            .cloned()
            .collect();
        for k in below {
            self.drop_change(&k);
        }
        self.drop_change(&p);
        if self.remote_entry(&p)?.is_some() {
            self.journal.changes.insert(p, Change::Deleted);
        }
        self.persist()
    }

    /// Déplace / renomme `from` vers `to` (`replace` : écrase la cible).
    pub fn rename(&mut self, from: &str, to: &str, replace: bool) -> Result<(), DriveError> {
        let (f, t) = (norm(from), norm(to));
        if f == t {
            return Ok(());
        }
        self.stat(&f)?.ok_or(DriveError::NotFound)?;
        if self.stat(&t)?.is_some() {
            if !replace {
                return Err(DriveError::Exists);
            }
            self.remove(&t)?;
        }
        // Élément déplacé : changement local tel quel, ou entrée distante.
        let moved = match self.journal.changes.remove(&f) {
            Some(Change::Moved(mut e)) => {
                e.name = base_name(&t).to_string();
                Change::Moved(e)
            }
            Some(c) => c,
            None => {
                let mut e = self.remote_entry(&f)?.ok_or(DriveError::NotFound)?;
                e.name = base_name(&t).to_string();
                Change::Moved(SavedEntry::from(&e))
            }
        };
        let below: Vec<(String, Change)> = self
            .journal
            .changes
            .iter()
            .filter(|(k, _)| is_under(k, &f))
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect();
        for (k, c) in below {
            self.journal.changes.remove(&k);
            self.journal
                .changes
                .insert(format!("{t}{}", &k[f.len()..]), c);
        }
        self.journal.changes.insert(t, moved);
        if self.remote_entry(&f)?.is_some() {
            self.journal.changes.insert(f, Change::Deleted);
        }
        self.persist()
    }

    fn upload(&self, chain: &crate::fs::Chain) -> Result<(), DriveError> {
        for (h, frame) in &chain.blocks {
            self.io.put(h, frame.clone()).map_err(DriveError::Node)?;
        }
        Ok(())
    }

    /// Réémet le répertoire `path` et ses descendants modifiés ; rend
    /// `(premier bloc, sel)` du nouveau répertoire.
    fn build_dir(&mut self, path: &str) -> Result<(BlockHash, [u8; 16]), DriveError> {
        let mut entries: BTreeMap<String, Entry> = self
            .base_entries(path)?
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect();
        let touched: Vec<String> = {
            let mut v: Vec<String> = self
                .journal
                .changes
                .keys()
                .filter(|k| is_under(k, path))
                .map(|k| {
                    let rest = &k[if path == "/" { 1 } else { path.len() + 1 }..];
                    join(path, rest.split('/').next().unwrap_or(rest))
                })
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let now = (self.clock)();
        for child in touched {
            let name = base_name(&child).to_string();
            match self.journal.changes.get(&child).cloned() {
                Some(Change::Deleted) => {
                    entries.remove(&name);
                }
                Some(Change::File {
                    cache,
                    created_at,
                    modified_at,
                }) => {
                    let data = std::fs::read(self.workspace.join("files").join(cache))?;
                    let salt = (self.salt)();
                    let master = self.keys[&KEY_VERSION];
                    let chain = {
                        let mut sealing = Sealing {
                            master_key: &master,
                            encryption_salt: &salt,
                            nonce: &mut *self.nonce,
                        };
                        write_file(&data, &mut sealing)?
                    };
                    self.upload(&chain)?;
                    entries.insert(
                        name.clone(),
                        Entry {
                            name: name.clone(),
                            size_bytes: data.len() as u64,
                            mime_type: FILE_MIME.into(),
                            first_block_hash: chain.first,
                            encryption_salt: salt,
                            key_version: KEY_VERSION,
                            permissions: 0o644,
                            created_at,
                            modified_at,
                        },
                    );
                }
                Some(Change::Moved(e)) => {
                    entries.insert(name.clone(), Entry::from(&e));
                }
                Some(Change::Dir { created_at }) => {
                    entries.insert(
                        name.clone(),
                        Entry {
                            name: name.clone(),
                            size_bytes: 0,
                            mime_type: DIRECTORY_MIME.into(),
                            first_block_hash: NO_ROOT,
                            encryption_salt: [0; 16],
                            key_version: KEY_VERSION,
                            permissions: 0o755,
                            created_at,
                            modified_at: created_at,
                        },
                    );
                }
                None => {}
            }
            let is_dir = entries
                .get(&name)
                .is_some_and(|e| e.mime_type == DIRECTORY_MIME);
            let new_dir = matches!(self.journal.changes.get(&child), Some(Change::Dir { .. }));
            let deeper = self.journal.changes.keys().any(|k| is_under(k, &child));
            if is_dir && (deeper || new_dir) {
                let (first, salt) = self.build_dir(&child)?;
                if let Some(e) = entries.get_mut(&name) {
                    e.first_block_hash = first;
                    e.encryption_salt = salt;
                    e.modified_at = now;
                }
            }
        }
        let list: Vec<Entry> = entries.into_values().collect();
        let salt = (self.salt)();
        let master = self.keys[&KEY_VERSION];
        let chain = {
            let mut sealing = Sealing {
                master_key: &master,
                encryption_salt: &salt,
                nonce: &mut *self.nonce,
            };
            write_directory(&list, &mut sealing)?
        };
        self.upload(&chain)?;
        Ok((chain.first, salt))
    }

    /// Synchronise les modifications : nouveaux blocs puis nouvelle racine.
    /// Rend le nombre de modifications appliquées.
    pub fn sync(&mut self) -> Result<usize, DriveError> {
        let n = self.journal.changes.len();
        if n == 0 {
            return Ok(0);
        }
        let (first, salt) = self.build_dir("/")?;
        match self
            .io
            .commit(&self.root.fs_root_hash, &first)
            .map_err(DriveError::Node)?
        {
            Some(current) => {
                self.conflict = Some(current);
                Err(DriveError::Conflict)
            }
            None => {
                let keys: Vec<String> = self.journal.changes.keys().cloned().collect();
                for k in keys {
                    self.drop_change(&k);
                }
                self.root = Root {
                    fs_root_hash: first,
                    encryption_salt: salt,
                    key_version: KEY_VERSION,
                };
                self.journal.fs_root_hash = hex::encode(first);
                self.journal.encryption_salt = hex::encode(salt);
                self.journal.key_version = KEY_VERSION;
                self.conflict = None;
                self.persist()?;
                Ok(n)
            }
        }
    }
}
