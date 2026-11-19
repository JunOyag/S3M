//! Accès applicatif — id `protocols.acces-applicatif`, component `connector`
//! (Phase 4). Réf. spec : docs/04-protocols/acces-applicatif.md.
//!
//! Moteur commun des backends de lecteur monté (WinFsp, FUSE) :
//! - résolution d'un chemin depuis `fs_root_hash`, répertoire par
//!   répertoire, en ne lisant **que** les blocs nécessaires (récupération
//!   paresseuse) ;
//! - chaque bloc passe par la vérification d'intégrité
//!   (`protocols.integrite-lecture`) : chemin normal au Nœud, chemin de
//!   secours par reconstruction (lecture seule) ;
//! - sous-répertoire : `mime_type = "inode/directory"` (le schéma
//!   `fs.DirectoryEntry` n'a pas de champ de type — convention retenue le
//!   2026-11-19).
//!
//! Restent à faire pour clore l'id : les backends WinFsp / FUSE et le
//! transport des blocs (protocole d'échange, `impl/SPEC_GAPS.md`).

use std::cell::RefCell;
use std::collections::HashMap;

use crate::fs::{read_directory, read_file, BlockHash, Entry, FsError};
use crate::integrity::{BlockSource, IntegrityLog};

/// Type MIME d'un sous-répertoire.
pub const DIRECTORY_MIME: &str = "inode/directory";

/// Racine du système de fichiers (entrée DHT User).
#[derive(Debug, Clone)]
pub struct Root {
    pub fs_root_hash: BlockHash,
    pub encryption_salt: [u8; 16],
    pub key_version: u16,
}

/// Erreurs d'accès.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error("chemin introuvable : {0}")]
    NotFound(String),
    #[error("pas un répertoire : {0}")]
    NotADirectory(String),
    #[error("clé maîtresse de version {0} inconnue")]
    UnknownKeyVersion(u16),
}

/// Volume monté : vue en lecture du système de fichiers de l'Utilisateur.
pub struct Volume<'a> {
    src: &'a dyn BlockSource,
    master_keys: &'a HashMap<u16, [u8; 32]>,
    root: Root,
    /// Journal d'intégrité (incidents à signaler, blocs corrompus).
    pub integrity: RefCell<IntegrityLog>,
    retries: usize,
}

impl<'a> Volume<'a> {
    /// `master_keys` : `master_key[version]` résolues par
    /// `crypto.master-key-chain`.
    pub fn new(
        src: &'a dyn BlockSource,
        master_keys: &'a HashMap<u16, [u8; 32]>,
        root: Root,
    ) -> Self {
        Self {
            src,
            master_keys,
            root,
            integrity: RefCell::new(IntegrityLog::default()),
            retries: 1,
        }
    }

    fn key(&self, version: u16) -> Result<&[u8; 32], AccessError> {
        self.master_keys
            .get(&version)
            .ok_or(AccessError::UnknownKeyVersion(version))
    }

    fn get(&self, h: &BlockHash) -> Option<Vec<u8>> {
        self.integrity.borrow_mut().read(self.src, h, self.retries)
    }

    fn list_dir(
        &self,
        first: &BlockHash,
        salt: &[u8; 16],
        version: u16,
    ) -> Result<Vec<Entry>, AccessError> {
        let key = self.key(version)?;
        Ok(read_directory(first, key, salt, &|h| self.get(h))?)
    }

    /// Entrée désignée par `path` (`/a/b/c`), en ne lisant que les
    /// répertoires traversés.
    pub fn lookup(&self, path: &str) -> Result<Option<Entry>, AccessError> {
        let mut dir = (
            self.root.fs_root_hash,
            self.root.encryption_salt,
            self.root.key_version,
        );
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let mut current: Option<Entry> = None;
        for (i, name) in parts.iter().enumerate() {
            let entries = self.list_dir(&dir.0, &dir.1, dir.2)?;
            let e = entries
                .into_iter()
                .find(|e| e.name == *name)
                .ok_or_else(|| AccessError::NotFound(path.to_owned()))?;
            if i + 1 < parts.len() && e.mime_type != DIRECTORY_MIME {
                return Err(AccessError::NotADirectory(name.to_string()));
            }
            dir = (e.first_block_hash, e.encryption_salt, e.key_version);
            current = Some(e);
        }
        Ok(current)
    }

    /// Liste un répertoire (`/` = racine).
    pub fn list(&self, path: &str) -> Result<Vec<Entry>, AccessError> {
        match self.lookup(path)? {
            None => self.list_dir(
                &self.root.fs_root_hash,
                &self.root.encryption_salt,
                self.root.key_version,
            ),
            Some(e) if e.mime_type == DIRECTORY_MIME => {
                self.list_dir(&e.first_block_hash, &e.encryption_salt, e.key_version)
            }
            Some(_) => Err(AccessError::NotADirectory(path.to_owned())),
        }
    }

    /// Lit un fichier entier (seule sa chaîne de blocs est récupérée).
    pub fn read(&self, path: &str) -> Result<Vec<u8>, AccessError> {
        let e = self
            .lookup(path)?
            .ok_or_else(|| AccessError::NotFound(path.to_owned()))?;
        let key = self.key(e.key_version)?;
        Ok(read_file(
            &e.first_block_hash,
            e.size_bytes,
            key,
            &e.encryption_salt,
            &|h| self.get(h),
        )?)
    }
}
