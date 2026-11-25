//! Copie locale des blocs envoyés au Nœud, gardée jusqu'à leur dispersion
//! (`protocols.dispersion-transactionnelle#copie-locale`) : un Nœud qui
//! perd un bloc avant de l'avoir dispersé le reçoit de nouveau.
//! Plafonnée par `Q_max` (taille de la file d'écriture) ; au-delà, les plus
//! anciennes copies sont abandonnées.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::fs::BlockHash;

/// Magasin des copies (un fichier par bloc, nommé par son hash).
pub struct Unsent {
    dir: PathBuf,
    max_bytes: u64,
    lock: Mutex<()>,
    /// Blocs renvoyés au Nœud qui les avait perdus.
    pub resent: AtomicU64,
    /// Copies abandonnées faute de place.
    pub dropped: AtomicU64,
}

impl Unsent {
    pub fn new(dir: PathBuf, max_bytes: u64) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self {
            dir,
            max_bytes,
            lock: Mutex::new(()),
            resent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    fn path(&self, h: &BlockHash) -> PathBuf {
        self.dir.join(hex::encode(h))
    }

    /// Garde la copie d'un bloc envoyé.
    pub fn keep(&self, h: &BlockHash, frame: &[u8]) {
        let _g = self.lock.lock().unwrap();
        if std::fs::write(self.path(h), frame).is_err() {
            return;
        }
        // Plafond : les plus anciennes copies d'abord.
        let mut files = self.files();
        let mut total: u64 = files.iter().map(|(_, _, n)| n).sum();
        if total <= self.max_bytes {
            return;
        }
        files.sort_by_key(|(_, t, _)| *t);
        for (p, _, n) in files {
            if total <= self.max_bytes {
                break;
            }
            if std::fs::remove_file(&p).is_ok() {
                total -= n;
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn files(&self) -> Vec<(PathBuf, std::time::SystemTime, u64)> {
        std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let m = e.metadata().ok()?;
                        Some((e.path(), m.modified().ok()?, m.len()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Blocs gardés (au plus `max`).
    pub fn list(&self, max: usize) -> Vec<BlockHash> {
        self.files()
            .iter()
            .filter_map(|(p, _, _)| {
                hex::decode(p.file_name()?.to_str()?)
                    .ok()?
                    .try_into()
                    .ok()
            })
            .take(max)
            .collect()
    }

    /// `(nombre, octets)` des copies gardées.
    pub fn usage(&self) -> (usize, u64) {
        let f = self.files();
        (f.len(), f.iter().map(|(_, _, n)| n).sum())
    }

    pub fn read(&self, h: &BlockHash) -> Option<Vec<u8>> {
        std::fs::read(self.path(h)).ok()
    }

    /// Bloc dispersé ou libéré : copie inutile.
    pub fn remove(&self, h: &BlockHash) {
        let _ = std::fs::remove_file(self.path(h));
    }
}
