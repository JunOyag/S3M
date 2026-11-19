//! Écriture par plages et synchronisation différée — id
//! `protocols.ecriture-differee`, component `connector` (Phase 4). Réf.
//! spec : docs/04-protocols/ecriture-differee.md.
//!
//! - Délai de silence par fichier : `D = clamp(60 s + 0,5 s × taille_MiO,
//!   60 s, 300 s)`, minuteur relancé à chaque écriture ;
//! - attente maximale : 15 min après la première écriture non synchronisée ;
//! - fermeture / flush / fsync ne déclenchent rien ; démontage, arrêt propre
//!   et « synchroniser maintenant » synchronisent tout immédiatement ;
//! - espace de travail : budget indépendant de `Q_max`, plafonné par
//!   l'espace disque libre moins la réserve ; manque → « disque plein » ;
//! - l'ancienne chaîne n'est tombstonée qu'après confirmation complète de la
//!   nouvelle.

use std::collections::BTreeMap;

/// Réglages (dashboard du Connecteur).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteBackConfig {
    pub min_delay_s: u64,
    pub max_delay_s: u64,
    pub max_wait_s: u64,
    pub workspace_reserve_bytes: u64,
}

impl Default for WriteBackConfig {
    fn default() -> Self {
        Self {
            min_delay_s: 60,
            max_delay_s: 300,
            max_wait_s: 15 * 60,
            workspace_reserve_bytes: 0,
        }
    }
}

const MIB: u64 = 1024 * 1024;

/// `D` en secondes pour un fichier de `size_bytes` (0,5 s par MiO, arrondi
/// à la seconde inférieure).
pub fn debounce_delay_s(cfg: &WriteBackConfig, size_bytes: u64) -> u64 {
    let d = cfg.min_delay_s + size_bytes / MIB / 2;
    d.clamp(cfg.min_delay_s, cfg.max_delay_s)
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    first_write: u64,
    last_write: u64,
    size_bytes: u64,
}

/// Erreur standard du lecteur monté quand l'espace de travail manque.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("disque plein : espace de travail insuffisant")]
pub struct DiskFull;

/// Planificateur des synchronisations différées.
#[derive(Debug, Default)]
pub struct Scheduler {
    cfg: WriteBackConfig,
    pending: BTreeMap<String, Pending>,
    sync_all: bool,
}

impl Scheduler {
    pub fn new(cfg: WriteBackConfig) -> Self {
        Self {
            cfg,
            pending: BTreeMap::new(),
            sync_all: false,
        }
    }

    /// Avant d'accepter la première écriture sur un fichier existant : la
    /// copie reconstituée doit tenir dans l'espace de travail
    /// (`free_disk − réserve − déjà utilisé`).
    pub fn reserve_workspace(
        &self,
        file_size: u64,
        free_disk: u64,
        used_workspace: u64,
    ) -> Result<(), DiskFull> {
        let available = free_disk
            .saturating_sub(self.cfg.workspace_reserve_bytes)
            .saturating_sub(used_workspace);
        if file_size > available {
            return Err(DiskFull);
        }
        Ok(())
    }

    /// Écriture sur `path` (taille courante du fichier) à l'instant `now`.
    pub fn on_write(&mut self, path: &str, size_bytes: u64, now: u64) {
        let p = self.pending.entry(path.to_owned()).or_insert(Pending {
            first_write: now,
            last_write: now,
            size_bytes,
        });
        p.last_write = now;
        p.size_bytes = size_bytes;
    }

    /// Fermeture, flush, fsync : la copie locale est durable, mais aucune
    /// synchronisation n'est déclenchée.
    pub fn on_fsync(&mut self, _path: &str) {}

    /// Démontage, arrêt propre, « synchroniser maintenant ».
    pub fn sync_now(&mut self) {
        self.sync_all = true;
    }

    /// Instant de synchronisation prévu d'un fichier en attente.
    pub fn due_at(&self, path: &str) -> Option<u64> {
        self.pending.get(path).map(|p| {
            let quiet = p.last_write + debounce_delay_s(&self.cfg, p.size_bytes);
            quiet.min(p.first_write + self.cfg.max_wait_s)
        })
    }

    /// Fichiers à synchroniser maintenant ; ils sortent de l'attente.
    pub fn take_due(&mut self, now: u64) -> Vec<String> {
        let all = std::mem::take(&mut self.sync_all);
        let due: Vec<String> = self
            .pending
            .keys()
            .filter(|p| all || self.due_at(p).is_some_and(|t| now >= t))
            .cloned()
            .collect();
        for p in &due {
            self.pending.remove(p);
        }
        due
    }

    /// Synchronisations en attente (indicateur du dashboard).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Ordre de suppression : l'ancienne chaîne n'est rendue (à tombstoner)
/// qu'une fois la nouvelle entièrement confirmée par le Nœud.
pub fn old_chain_to_tombstone<T>(new_chain_confirmed: bool, old_chain: T) -> Option<T> {
    new_chain_confirmed.then_some(old_chain)
}
