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
    /// Racine connue (sel et version) : son descripteur scellé accompagnera
    /// sa validation (`crypto.k-self#k-root`).
    fn note_root(&self, _root: &Root) {}
}

/// `cache` : répertoire où garder les blocs lus (blocs de répertoire,
/// relus hors ligne pour réémettre l'arborescence — écriture d'urgence).
struct Source<'a>(&'a dyn BlockIo, Option<PathBuf>);

impl BlockSource for Source<'_> {
    fn fetch_from_node(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        let Some(dir) = &self.1 else {
            return self.0.get(hash);
        };
        let path = dir.join(hex::encode(hash));
        if let Ok(b) = std::fs::read(&path) {
            return Some(b);
        }
        let b = self.0.get(hash)?;
        let _ = std::fs::write(&path, &b);
        Some(b)
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
    #[error("en lecture seule (partage reçu)")]
    ReadOnly,
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
    pub fn of(e: &Entry) -> Self {
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
            wrapped_key: Vec::new(),
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

/// Arborescence déposée en urgence (`protocols.espace-secours`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct SavedEmergency {
    /// `Journal::revision` au moment du dépôt.
    revision: u64,
    base: String,
    first: String,
    salt: String,
    key_version: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Journal {
    fs_root_hash: String,
    encryption_salt: String,
    key_version: u16,
    changes: BTreeMap<String, Change>,
    next_file: u64,
    /// Incrémenté à chaque modification locale.
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    emergency: Option<SavedEmergency>,
    /// Blocs de l'ancienne racine à libérer chez le Nœud, après un
    /// `CommitRoot` confirmé (`protocols.echange-blocs` § Libération).
    #[serde(default)]
    to_release: Vec<String>,
    /// Blocs remplacés gardés pour l'historique : `(hash, remplacé le)`,
    /// libérés après la durée de conservation
    /// (`protocols.historique-versions`).
    #[serde(default)]
    held: Vec<(String, u64)>,
}

/// Arborescence construite pour un dépôt d'urgence : racine de base,
/// nouvelle racine et blocs chiffrés à déposer.
#[derive(Debug, Clone)]
pub struct EmergencyBuild {
    pub base: BlockHash,
    pub root: Root,
    pub blocks: Vec<(BlockHash, Vec<u8>)>,
}

/// `BlockIo` qui garde les blocs émis au lieu de les envoyer.
struct Collector {
    inner: Arc<dyn BlockIo>,
    blocks: std::sync::Mutex<Vec<(BlockHash, Vec<u8>)>>,
}

impl BlockIo for Collector {
    fn get(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        self.inner.get(hash)
    }
    fn put(&self, hash: &BlockHash, frame: Vec<u8>) -> Result<(), String> {
        self.blocks.lock().unwrap().push((*hash, frame));
        Ok(())
    }
    fn commit(&self, _: &BlockHash, _: &BlockHash) -> Result<Option<BlockHash>, String> {
        Err("dépôt d'urgence : pas de validation".into())
    }
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

/// « dossier/nom (conflit AAAA-MM-JJ HHhMM).ext », unique parmi `taken`.
fn conflict_name(path: &str, now: u64, taken: &[String]) -> String {
    let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
    let (stem, ext) = match file.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (file, String::new()),
    };
    // Date civile UTC (algorithme de H. Hinnant).
    let z = (now / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (h, mi) = ((now % 86_400) / 3600, (now % 3600) / 60);
    let base = format!("{dir}/{stem} (conflit {y}-{m:02}-{d:02} {h:02}h{mi:02})");
    let mut name = format!("{base}{ext}");
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base} {n}{ext}");
        n += 1;
    }
    name
}

fn is_under(path: &str, ancestor: &str) -> bool {
    ancestor == "/" && path != "/"
        || path.len() > ancestor.len()
            && path.starts_with(ancestor)
            && path.as_bytes()[ancestor.len()] == b'/'
}

// ------------------------------------------------------------------ lecteur

/// Lecteur : vue fusionnée (distant + modifications locales).
/// Dossier virtuel des partages reçus (`protocols.partage#connecteur`).
pub const SHARED_DIR: &str = "/Partagés avec moi";

/// Source des partages reçus, en lecture seule ; chemins relatifs à
/// [`SHARED_DIR`] (`/` : sa racine).
pub trait SharedTree: Send + Sync {
    fn stat(&self, rel: &str) -> Result<Option<Meta>, DriveError>;
    fn list(&self, rel: &str) -> Result<Vec<(String, Meta)>, DriveError>;
    fn read(&self, rel: &str, offset: u64, len: usize) -> Result<Vec<u8>, DriveError>;
    /// Change quand les partages reçus changent (ajout, mise à jour,
    /// retrait) : les vues déjà ouvertes se rafraîchissent.
    fn version(&self) -> u64 {
        0
    }
}

/// Élément de son propre espace à partager : version synchronisée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedElement {
    pub is_dir: bool,
    pub name: String,
    pub size_bytes: u64,
    pub modified_at: u64,
    pub first_block_hash: BlockHash,
    pub element_key: [u8; 32],
}

/// Chemin sous [`SHARED_DIR`] : relatif (`/…`), sinon `None`.
fn shared_rel(p: &str) -> Option<String> {
    if p == SHARED_DIR {
        return Some("/".into());
    }
    p.strip_prefix(SHARED_DIR)
        .filter(|r| r.starts_with('/'))
        .map(str::to_string)
}

pub struct Drive {
    /// Partages reçus, montés sous [`SHARED_DIR`].
    pub shared: Option<Arc<dyn SharedTree>>,
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
    /// Conservation de l'historique (s) ; 0 : blocs remplacés libérés
    /// aussitôt.
    retention_s: u64,
    /// Version de la clé maîtresse des nouvelles écritures
    /// (`crypto.master-key-chain`).
    version: u16,
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
        io.note_root(&root);
        Ok(Self {
            shared: None,
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
            retention_s: 0,
            version: KEY_VERSION,
        })
    }

    /// Clés maîtresses connues (anciennes comprises) et version courante,
    /// après une rotation d'identité (`crypto.master-key-chain`).
    pub fn set_keys(&mut self, keys: HashMap<u16, [u8; 32]>, current: u16) {
        self.keys = keys;
        self.version = current;
    }

    /// Clés maîtresses connues.
    pub fn keys(&self) -> HashMap<u16, [u8; 32]> {
        self.keys.clone()
    }

    /// Version de la clé maîtresse des nouvelles écritures.
    pub fn key_version(&self) -> u16 {
        self.version
    }

    /// `path` (dossier : lui ou son contenu) est-il encore chiffré avec une
    /// clé antérieure à la courante (rotation d'identité) ? Au plus
    /// `budget` éléments examinés.
    pub fn uses_old_key(&mut self, path: &str, budget: &mut usize) -> bool {
        if self.version <= KEY_VERSION || *budget == 0 {
            return false;
        }
        *budget -= 1;
        let p = norm(path);
        let own = match self.journal.changes.get(&p) {
            Some(Change::File { .. }) => return false,
            Some(Change::Dir { .. }) => self.version,
            Some(Change::Moved(e)) => Entry::from(e).key_version,
            Some(Change::Deleted) => return false,
            None if p == "/" => self.root.key_version,
            None => match self.remote_entry(&p) {
                Ok(Some(e)) if e.mime_type != DIRECTORY_MIME => return e.key_version < self.version,
                Ok(Some(e)) => e.key_version,
                _ => return false,
            },
        };
        if own < self.version {
            return true;
        }
        let Ok(children) = self.list(&p) else {
            return false;
        };
        children.iter().any(|(n, _)| {
            let c = format!("{}/{n}", p.trim_end_matches('/'));
            c != SHARED_DIR && self.uses_old_key(&c, budget)
        })
    }

    /// Conservation de l'historique, alignée sur celle du Nœud.
    pub fn set_retention(&mut self, s: u64) {
        self.retention_s = s;
    }

    /// Fichiers existants modifiés parmi les modifications en attente
    /// (garde-fou contre un rançongiciel) ; compté seulement au-delà de
    /// `min` modifications.
    pub fn modified_existing(&mut self, min: usize) -> usize {
        if self.journal.changes.len() < min {
            return 0;
        }
        let files: Vec<String> = self
            .journal
            .changes
            .iter()
            .filter(|(_, c)| matches!(c, Change::File { .. }))
            .map(|(k, _)| k.clone())
            .collect();
        let root = self.root.clone();
        files
            .iter()
            .filter(|p| self.lookup_in(&root, p).ok().flatten().is_some())
            .count()
    }

    /// Blocs gardés pour l'historique.
    pub fn held_hashes(&self) -> Vec<BlockHash> {
        self.journal.held.iter().map(|(h, _)| arr(h)).collect()
    }

    /// Blocs gardés à libérer : remplacés depuis plus que la conservation,
    /// ou avant `before` (purge demandée) ; jamais ceux de `keep` (encore
    /// atteints par la racine courante ou une version gardée), qui sont
    /// simplement retirés de l'historique. Rend le nombre de blocs à libérer.
    pub fn mature_held(
        &mut self,
        now: u64,
        before: Option<u64>,
        keep: &std::collections::HashSet<BlockHash>,
    ) -> Result<usize, DriveError> {
        let r = self.retention_s;
        let due = |at: u64| at.saturating_add(r) <= now || before.is_some_and(|b| b == 0 || at < b);
        let mut out = Vec::new();
        self.journal.held.retain(|(h, at)| {
            let hash: BlockHash = arr(h);
            if keep.contains(&hash) {
                return false;
            }
            if due(*at) {
                out.push(h.clone());
                return false;
            }
            true
        });
        let n = out.len();
        if n > 0 {
            self.journal.to_release.extend(out);
            self.journal.to_release.sort();
            self.journal.to_release.dedup();
        }
        self.persist()?;
        Ok(n)
    }

    /// Liste `path` dans la version `root` (lecture seule).
    pub fn list_at(&mut self, root: &Root, path: &str) -> Result<Vec<(String, Meta)>, DriveError> {
        let p = norm(path);
        if root.fs_root_hash == NO_ROOT {
            return Ok(Vec::new());
        }
        let entries = self.with_volume(root.clone(), |v| v.list(&p))?;
        Ok(entries.iter().map(|e| (e.name.clone(), Meta::of(e))).collect())
    }

    /// Attributs de `path` dans la version `root`.
    pub fn stat_at(&mut self, root: &Root, path: &str) -> Result<Option<Meta>, DriveError> {
        let p = norm(path);
        if p == "/" {
            return Ok(Some(Meta {
                is_dir: true,
                size: 0,
                created_at: 0,
                modified_at: 0,
            }));
        }
        Ok(self.lookup_in(root, &p)?.as_ref().map(Meta::of))
    }

    /// Lit `len` octets de `path` dans la version `root`.
    pub fn read_at(
        &mut self,
        root: &Root,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, DriveError> {
        let e = self
            .lookup_in(root, &norm(path))?
            .ok_or(DriveError::NotFound)?;
        if e.mime_type == DIRECTORY_MIME {
            return Err(DriveError::IsADirectory);
        }
        let data = self.remote_content(&e)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len).min(data.len());
        Ok(data[start..end].to_vec())
    }

    /// Racine courante (`fs_root_hash`).
    pub fn root_hash(&self) -> BlockHash {
        self.root.fs_root_hash
    }

    /// Version des partages reçus montés (0 sans partages).
    pub fn shared_version(&self) -> u64 {
        self.shared.as_ref().map_or(0, |t| t.version())
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
        self.io.note_root(&root);
        self.journal.fs_root_hash = hex::encode(root.fs_root_hash);
        self.journal.encryption_salt = hex::encode(root.encryption_salt);
        self.journal.key_version = root.key_version;
        self.root = root;
        self.persist()?;
        Ok(true)
    }

    /// Élément de l'arborescence `root` (sans les modifications locales).
    fn lookup_in(&mut self, root: &Root, path: &str) -> Result<Option<Entry>, DriveError> {
        if root.fs_root_hash == NO_ROOT {
            return Ok(None);
        }
        match self.with_volume(root.clone(), |v| v.lookup(path)) {
            Err(DriveError::Access(AccessError::NotFound(_))) => Ok(None),
            Err(DriveError::Access(AccessError::NotADirectory(_))) => Ok(None),
            r => r,
        }
    }

    /// Résolution d'un conflit (`protocols.write-queue#resolution-de-conflit`) :
    /// la racine `root` écrite par un autre appareil devient la base, et les
    /// modifications locales sont rejouées par-dessus. Un élément modifié
    /// des deux côtés : le plus récent (`modified_at`) gagne, l'autre est
    /// gardé à côté (« nom (conflit …) »). Une suppression locale ne
    /// l'emporte que si l'élément n'a pas changé de l'autre côté. Rend les
    /// copies de conflit créées.
    pub fn rebase(&mut self, root: Root, now: u64) -> Result<Vec<String>, DriveError> {
        if root.fs_root_hash == NO_ROOT {
            return Err(DriveError::Conflict);
        }
        let old = self.root.clone();
        let changes = self.journal.changes.clone();
        let mut before = BTreeMap::new();
        for p in changes.keys() {
            before.insert(p.clone(), self.lookup_in(&old, p)?);
        }
        self.io.note_root(&root);
        self.root = root.clone();
        self.journal.fs_root_hash = hex::encode(root.fs_root_hash);
        self.journal.encryption_salt = hex::encode(root.encryption_salt);
        self.journal.key_version = root.key_version;
        let mut copies = Vec::new();
        for (p, ch) in changes {
            let now_remote = self.lookup_in(&root, &p)?;
            let was = before.remove(&p).flatten();
            // Inchangé de l'autre côté : la modification locale s'applique.
            let untouched = match (&was, &now_remote) {
                (None, None) => true,
                (Some(a), Some(b)) => a.first_block_hash == b.first_block_hash,
                _ => false,
            };
            if untouched {
                continue;
            }
            match (ch, now_remote) {
                (Change::Deleted, Some(_)) => {
                    // Modifié ailleurs entre-temps : gardé.
                    self.journal.changes.remove(&p);
                }
                (Change::Dir { .. }, Some(r)) if r.mime_type == DIRECTORY_MIME => {
                    // Dossier créé des deux côtés : celui du Nœud, avec son
                    // contenu (les ajouts locaux dedans restent).
                    self.journal.changes.remove(&p);
                }
                (
                    ch @ Change::File {
                        modified_at: local, ..
                    },
                    Some(r),
                ) => {
                    let name = conflict_name(&p, now, &copies);
                    if r.mime_type != DIRECTORY_MIME && r.modified_at <= local {
                        // Local plus récent : la version du Nœud est gardée à côté.
                        self.journal
                            .changes
                            .insert(name.clone(), Change::Moved(SavedEntry::from(&r)));
                    } else {
                        // Version du Nœud plus récente (ou dossier) : la locale
                        // est gardée à côté.
                        self.journal.changes.remove(&p);
                        self.journal.changes.insert(name.clone(), ch);
                    }
                    copies.push(name);
                }
                _ => {}
            }
        }
        self.conflict = None;
        self.journal.revision += 1;
        self.persist()?;
        Ok(copies)
    }

    /// Nombre de modifications en attente.
    pub fn pending(&self) -> usize {
        self.journal.changes.len()
    }

    /// Modification locale : nouvelle révision, puis écriture du journal.
    fn changed(&mut self) -> Result<(), DriveError> {
        self.journal.revision += 1;
        self.persist()
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
        let dirs = self.workspace.join("dirs");
        let _ = std::fs::create_dir_all(&dirs);
        let io = self.io.clone();
        self.with_source(Source(io.as_ref(), Some(dirs)), root, f)
    }

    fn with_source<T>(
        &mut self,
        src: Source<'_>,
        root: Root,
        f: impl FnOnce(&Volume<'_>) -> Result<T, AccessError>,
    ) -> Result<T, DriveError> {
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

    /// Élément synchronisé de `path` et sa clé d'élément, à confier par un
    /// partage (`protocols.partage`) ; `/` : la racine.
    pub fn shared_element(&mut self, path: &str) -> Result<Option<SharedElement>, DriveError> {
        let p = norm(path);
        if p == "/" {
            let key = *self
                .keys
                .get(&self.root.key_version)
                .ok_or(DriveError::NotFound)?;
            if self.root.fs_root_hash == NO_ROOT {
                return Ok(None);
            }
            return Ok(Some(SharedElement {
                is_dir: true,
                name: "Mes fichiers".into(),
                size_bytes: 0,
                modified_at: 0,
                first_block_hash: self.root.fs_root_hash,
                element_key: s3m_core::k_block::derive_k_elem(&key, &self.root.encryption_salt)
                    .map_err(crate::fs::FsError::from)?,
            }));
        }
        let Some(e) = self.remote_entry(&p)? else {
            return Ok(None);
        };
        let key = *self.keys.get(&e.key_version).ok_or(DriveError::NotFound)?;
        Ok(Some(SharedElement {
            is_dir: e.mime_type == DIRECTORY_MIME,
            name: e.name.clone(),
            size_bytes: e.size_bytes,
            modified_at: e.modified_at,
            first_block_hash: e.first_block_hash,
            element_key: s3m_core::k_block::derive_k_elem(&key, &e.encryption_salt)
                .map_err(crate::fs::FsError::from)?,
        }))
    }

    /// Attributs de `path` (`None` : absent).
    pub fn stat(&mut self, path: &str) -> Result<Option<Meta>, DriveError> {
        let p = norm(path);
        if let (Some(rel), Some(t)) = (shared_rel(&p), self.shared.clone()) {
            return t.stat(&rel);
        }
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
        if let (Some(rel), Some(t)) = (shared_rel(&p), self.shared.clone()) {
            return t.list(&rel);
        }
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
        if p == "/" && self.shared.is_some() {
            out.entry(base_name(SHARED_DIR).to_string())
                .or_insert(Meta {
                    is_dir: true,
                    size: 0,
                    created_at: 0,
                    modified_at: 0,
                });
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
        let io = self.io.clone();
        let data = self.with_source(Source(io.as_ref(), None), root, move |v| {
            v.read_entry(&entry)
        })?;
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
        if let (Some(rel), Some(t)) = (shared_rel(&p), self.shared.clone()) {
            return t.read(&rel, offset, len);
        }
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
        if shared_rel(&p).is_some() && self.shared.is_some() {
            return Err(DriveError::ReadOnly);
        }
        let local = self.ensure_local(&p)?;
        let mut f = OpenOptions::new().write(true).open(local)?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(data)?;
        let size = f.metadata()?.len();
        self.touch(&p);
        self.changed()?;
        Ok(size)
    }

    /// Fixe la taille du fichier.
    pub fn set_size(&mut self, path: &str, size: u64) -> Result<(), DriveError> {
        let p = norm(path);
        if shared_rel(&p).is_some() && self.shared.is_some() {
            return Err(DriveError::ReadOnly);
        }
        let local = self.ensure_local(&p)?;
        OpenOptions::new().write(true).open(local)?.set_len(size)?;
        self.touch(&p);
        self.changed()
    }

    /// Crée un fichier vide ou un répertoire.
    pub fn create(&mut self, path: &str, is_dir: bool) -> Result<(), DriveError> {
        let p = norm(path);
        if shared_rel(&p).is_some() && self.shared.is_some() {
            return Err(DriveError::ReadOnly);
        }
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
        self.changed()
    }

    fn drop_change(&mut self, k: &str) {
        if let Some(Change::File { cache, .. }) = self.journal.changes.remove(k) {
            let _ = std::fs::remove_file(self.workspace.join("files").join(cache));
        }
    }

    /// Supprime un fichier ou un répertoire vide.
    pub fn remove(&mut self, path: &str) -> Result<(), DriveError> {
        let p = norm(path);
        if shared_rel(&p).is_some() && self.shared.is_some() {
            return Err(DriveError::ReadOnly);
        }
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
        if self.shared.is_some()
            && (shared_rel(&norm(from)).is_some() || shared_rel(&norm(to)).is_some())
        {
            return Err(DriveError::ReadOnly);
        }
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
        self.changed()
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
                    let master = self.keys[&self.version];
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
                            key_version: self.version,
                            permissions: 0o644,
                            created_at,
                            modified_at,
                            wrapped_key: Vec::new(),
                        },
                    );
                }
                Some(Change::Moved(e)) => {
                    // Le nom est celui de l'emplacement (copie de conflit).
                    let mut en = Entry::from(&e);
                    en.name = name.clone();
                    entries.insert(name.clone(), en);
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
                            key_version: self.version,
                            permissions: 0o755,
                            created_at,
                            modified_at: created_at,
                            wrapped_key: Vec::new(),
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
        let master = self.keys[&self.version];
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
    /// Si l'arborescence déposée en urgence est toujours à jour, c'est elle
    /// qui est validée (mêmes blocs). Rend le nombre de modifications
    /// appliquées.
    pub fn sync(&mut self) -> Result<usize, DriveError> {
        let n = self.journal.changes.len();
        if n == 0 {
            return Ok(0);
        }
        // Blocs que la nouvelle racine remplacera, libérés après validation.
        let release = self.release_set();
        let r = self.sync_inner(n);
        if r.is_ok() && !release.is_empty() {
            if self.retention_s > 0 {
                // Gardés pour l'historique (`protocols.historique-versions`).
                let now = (self.clock)();
                self.journal
                    .held
                    .extend(release.iter().map(|h| (hex::encode(h), now)));
            } else {
                self.journal
                    .to_release
                    .extend(release.iter().map(hex::encode));
                self.journal.to_release.sort();
                self.journal.to_release.dedup();
            }
            self.persist()?;
        }
        r
    }

    /// Blocs à libérer chez le Nœud (au plus `max`).
    pub fn pending_release(&self, max: usize) -> Vec<BlockHash> {
        self.journal
            .to_release
            .iter()
            .take(max)
            .map(|h| arr(h))
            .collect()
    }

    /// Blocs atteints par la racine courante (rattrapage des anciennes
    /// versions) ; `None` si une partie en est illisible (rien n'est alors
    /// libéré).
    pub fn reachable(&mut self) -> Option<std::collections::HashSet<BlockHash>> {
        let root = self.root.clone();
        self.reachable_of(&root)
    }

    /// Blocs atteints par la version `root` ; `None` si une partie en est
    /// illisible.
    pub fn reachable_of(&mut self, root: &Root) -> Option<std::collections::HashSet<BlockHash>> {
        let root = root.clone();
        if root.fs_root_hash == NO_ROOT {
            return Some(Default::default());
        }
        let e = Entry {
            first_block_hash: root.fs_root_hash,
            encryption_salt: root.encryption_salt,
            key_version: root.key_version,
            mime_type: DIRECTORY_MIME.into(),
            ..Default::default()
        };
        self.strict_subtree(&e).map(|v| v.into_iter().collect())
    }

    fn strict_subtree(&mut self, e: &Entry) -> Option<Vec<BlockHash>> {
        let k = self.k_elem_of(e)?;
        let io = self.io.clone();
        let is_dir = e.mime_type == DIRECTORY_MIME;
        let mut out =
            crate::fs::chain_hashes(&e.first_block_hash, &k, is_dir, &|h| io.get(h)).ok()?;
        if is_dir {
            let children =
                crate::fs::read_directory_elem(&e.first_block_hash, &k, &|h| io.get(h)).ok()?;
            for c in children {
                if c.first_block_hash == NO_ROOT {
                    continue;
                }
                out.extend(self.strict_subtree(&c)?);
            }
        }
        Some(out)
    }

    /// Ajoute des blocs à libérer (rattrapage).
    pub fn queue_release(&mut self, hashes: &[BlockHash]) -> Result<(), DriveError> {
        self.journal
            .to_release
            .extend(hashes.iter().map(hex::encode));
        self.journal.to_release.sort();
        self.journal.to_release.dedup();
        self.persist()
    }

    /// Libération accusée par le Nœud.
    pub fn confirm_release(&mut self, done: &[BlockHash]) -> Result<(), DriveError> {
        let done: std::collections::HashSet<String> = done.iter().map(hex::encode).collect();
        self.journal.to_release.retain(|h| !done.contains(h));
        self.persist()
    }

    /// Clé d'élément d'une entrée.
    fn k_elem_of(&self, e: &Entry) -> Option<[u8; 32]> {
        let master = self.keys.get(&e.key_version)?;
        s3m_core::k_block::derive_k_elem(master, &e.encryption_salt).ok()
    }

    /// Blocs de la chaîne d'une entrée (vide si illisible : jamais libéré).
    fn chain_of(&mut self, e: &Entry) -> Vec<BlockHash> {
        if e.first_block_hash == NO_ROOT {
            return Vec::new();
        }
        let Some(k) = self.k_elem_of(e) else {
            return Vec::new();
        };
        let io = self.io.clone();
        crate::fs::chain_hashes(
            &e.first_block_hash,
            &k,
            e.mime_type == DIRECTORY_MIME,
            &|h| io.get(h),
        )
        .unwrap_or_default()
    }

    /// Blocs d'une entrée et, pour un répertoire, de tout son contenu.
    fn subtree_of(&mut self, e: &Entry) -> Vec<BlockHash> {
        let mut out = self.chain_of(e);
        if e.mime_type == DIRECTORY_MIME && e.first_block_hash != NO_ROOT {
            let Some(k) = self.k_elem_of(e) else {
                return out;
            };
            let io = self.io.clone();
            let children = crate::fs::read_directory_elem(&e.first_block_hash, &k, &|h| io.get(h))
                .unwrap_or_default();
            for c in children {
                out.extend(self.subtree_of(&c));
            }
        }
        out
    }

    /// Blocs de l'ancienne racine que la nouvelle ne référencera plus :
    /// anciens répertoires réécrits, et tout ce qui se trouvait à un chemin
    /// modifié, supprimé ou déplacé — sauf ce qu'emporte un élément déplacé.
    fn release_set(&mut self) -> Vec<BlockHash> {
        let old = self.root.clone();
        if old.fs_root_hash == NO_ROOT {
            return Vec::new();
        }
        let changes = self.journal.changes.clone();
        let mut cand: std::collections::HashSet<BlockHash> = std::collections::HashSet::new();
        // Répertoires réécrits : la racine et les ancêtres des modifications.
        let mut dirs: std::collections::BTreeSet<String> = ["/".to_string()].into();
        for p in changes.keys() {
            let mut a = p.as_str();
            while let Some((up, _)) = a.rsplit_once('/') {
                if up.is_empty() {
                    break;
                }
                dirs.insert(up.to_string());
                a = up;
            }
        }
        for d in &dirs {
            let e = if d == "/" {
                Some(Entry {
                    first_block_hash: old.fs_root_hash,
                    encryption_salt: old.encryption_salt,
                    key_version: old.key_version,
                    mime_type: DIRECTORY_MIME.into(),
                    ..Default::default()
                })
            } else {
                self.lookup_in(&old, d).ok().flatten()
            };
            if let Some(e) = e.filter(|e| e.mime_type == DIRECTORY_MIME) {
                cand.extend(self.chain_of(&e));
            }
        }
        for p in changes.keys() {
            if let Some(e) = self.lookup_in(&old, p).ok().flatten() {
                cand.extend(self.subtree_of(&e));
            }
        }
        for c in changes.values() {
            if let Change::Moved(se) = c {
                for h in self.subtree_of(&Entry::from(se)) {
                    cand.remove(&h);
                }
            }
        }
        let mut v: Vec<BlockHash> = cand.into_iter().collect();
        v.sort();
        v
    }

    fn sync_inner(&mut self, n: usize) -> Result<usize, DriveError> {
        if let Some(e) = self.current_emergency() {
            let dir = self.workspace.join("emergency");
            for f in std::fs::read_dir(&dir)?.flatten() {
                let hash: BlockHash = arr(&f.file_name().to_string_lossy());
                let frame = std::fs::read(f.path())?;
                self.io.put(&hash, frame).map_err(DriveError::Node)?;
            }
            let (first, salt) = (arr(&e.first), arr(&e.salt));
            return self.commit_new_root(first, salt).map(|_| n);
        }
        let (first, salt) = self.build_dir("/")?;
        self.commit_new_root(first, salt).map(|_| n)
    }

    fn commit_new_root(&mut self, first: BlockHash, salt: [u8; 16]) -> Result<(), DriveError> {
        self.io.note_root(&Root {
            fs_root_hash: first,
            encryption_salt: salt,
            key_version: self.version,
        });
        match self
            .io
            .commit(&self.root.fs_root_hash, &first)
            .map_err(DriveError::Node)?
        {
            // Déjà validée par un autre Connecteur (réconciliation d'un
            // dépôt d'urgence) : même résultat.
            Some(current) if current != first => {
                self.conflict = Some(current);
                Err(DriveError::Conflict)
            }
            _ => {
                let keys: Vec<String> = self.journal.changes.keys().cloned().collect();
                for k in keys {
                    self.drop_change(&k);
                }
                self.root = Root {
                    fs_root_hash: first,
                    encryption_salt: salt,
                    key_version: self.version,
                };
                self.journal.fs_root_hash = hex::encode(first);
                self.journal.encryption_salt = hex::encode(salt);
                self.journal.key_version = self.version;
                self.conflict = None;
                self.clear_emergency();
                self.persist()
            }
        }
    }

    /// Dépôt d'urgence encore à jour : rien de modifié depuis, même base.
    fn current_emergency(&self) -> Option<SavedEmergency> {
        self.journal
            .emergency
            .clone()
            .filter(|e| e.revision == self.journal.revision)
            .filter(|e| arr::<32>(&e.base) == self.root.fs_root_hash)
    }

    fn clear_emergency(&mut self) {
        self.journal.emergency = None;
        let _ = std::fs::remove_dir_all(self.workspace.join("emergency"));
    }

    /// Un dépôt d'urgence couvre-t-il les modifications en attente ?
    pub fn emergency_current(&self) -> bool {
        self.current_emergency().is_some()
    }

    /// Construit l'arborescence à déposer en urgence (Nœud injoignable),
    /// sans rien envoyer : `None` s'il n'y a rien en attente ou si le
    /// dernier dépôt couvre déjà les modifications. Les répertoires
    /// inchangés sont relus dans le cache local.
    pub fn emergency_build(&mut self) -> Result<Option<EmergencyBuild>, DriveError> {
        if self.pending() == 0 || self.current_emergency().is_some() {
            return Ok(None);
        }
        let collector = Arc::new(Collector {
            inner: self.io.clone(),
            blocks: Default::default(),
        });
        let orig = std::mem::replace(&mut self.io, collector.clone());
        let built = self.build_dir("/");
        self.io = orig;
        let (first, salt) = built?;
        let blocks = std::mem::take(&mut *collector.blocks.lock().unwrap());
        Ok(Some(EmergencyBuild {
            base: self.root.fs_root_hash,
            root: Root {
                fs_root_hash: first,
                encryption_salt: salt,
                key_version: self.version,
            },
            blocks,
        }))
    }

    /// Dépôt réussi : l'arborescence déposée sera validée telle quelle au
    /// retour du Nœud si rien ne change d'ici là.
    pub fn emergency_confirm(&mut self, b: &EmergencyBuild) -> Result<(), DriveError> {
        let dir = self.workspace.join("emergency");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        for (h, frame) in &b.blocks {
            std::fs::write(dir.join(hex::encode(h)), frame)?;
        }
        self.journal.emergency = Some(SavedEmergency {
            revision: self.journal.revision,
            base: hex::encode(b.base),
            first: hex::encode(b.root.fs_root_hash),
            salt: hex::encode(b.root.encryption_salt),
            key_version: b.root.key_version,
        });
        self.persist()
    }

    /// Racine validée par un autre Connecteur (réconciliation d'un dépôt
    /// d'urgence) : adoptée si elle part de la racine courante et
    /// qu'aucune modification locale n'est en attente.
    /// Rétablit tout l'espace dans la version `root` (retour arrière choisi
    /// par l'Utilisateur, `protocols.historique-versions#retour-arriere`) :
    /// validée chez le Nœud comme une nouvelle racine ; la version courante
    /// entre dans l'historique.
    pub fn restore_root(&mut self, root: Root) -> Result<(), DriveError> {
        if self.pending() > 0 {
            return Err(DriveError::Node(
                "modifications en attente : synchronisez d'abord".into(),
            ));
        }
        self.io.note_root(&root);
        match self
            .io
            .commit(&self.root.fs_root_hash, &root.fs_root_hash)
            .map_err(DriveError::Node)?
        {
            Some(current) if current != root.fs_root_hash => {
                self.conflict = Some(current);
                Err(DriveError::Conflict)
            }
            _ => {
                self.journal.fs_root_hash = hex::encode(root.fs_root_hash);
                self.journal.encryption_salt = hex::encode(root.encryption_salt);
                self.journal.key_version = root.key_version;
                self.root = root;
                self.journal.revision += 1;
                self.persist()
            }
        }
    }

    pub fn advance_root(&mut self, base: &BlockHash, root: Root) -> Result<bool, DriveError> {
        if self.pending() > 0 || self.root.fs_root_hash != *base {
            return Ok(false);
        }
        self.journal.fs_root_hash = hex::encode(root.fs_root_hash);
        self.journal.encryption_salt = hex::encode(root.encryption_salt);
        self.journal.key_version = root.key_version;
        self.root = root;
        self.persist()?;
        Ok(true)
    }
}
