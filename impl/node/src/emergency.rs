//! Espace de secours — id `protocols.espace-secours`, partie `node`
//! (Phase 4). Réf. spec : docs/04-protocols/espace-secours.md.
//!
//! - **En tant que partenaire de secours** : un Nœud accepte des dépôts
//!   d'urgence de tiers dans la limite de `emergency_backup_capacity`
//!   (`U_backup`) Utilisateurs et de `emergency_reserved_bytes`.
//! - **Au retour du Nœud hébergeur** : il recalcule `emergency_dht_key` pour
//!   chaque Utilisateur rattaché, récupère les blocs et les intègre par
//!   timestamp croissant dans la limite du quota (même règle que
//!   `protocols.quota-sync`), puis calcule et disperse la parité.

use std::collections::BTreeMap;

use s3m_protocol::dht::emergency_dht_key;

use crate::quota_sync::{integrate, Integration, PendingWrite};

/// Erreurs d'admission.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReservationError {
    #[error("capacité d'accueil U_backup atteinte")]
    TooManyUsers,
    #[error("espace réservé au secours épuisé")]
    NoSpace,
}

/// Réserve d'accueil pour tiers en détresse.
#[derive(Debug, Default)]
pub struct EmergencyReserve {
    pub max_users: u32,
    pub reserved_bytes: u64,
    used: BTreeMap<[u8; 32], u64>,
}

impl EmergencyReserve {
    pub fn new(max_users: u32, reserved_bytes: u64) -> Self {
        Self {
            max_users,
            reserved_bytes,
            used: BTreeMap::new(),
        }
    }

    /// Accepte un dépôt de `bytes` pour l'Utilisateur `user` (identifié par
    /// sa clé de secours, jamais par un Connecteur).
    pub fn accept(&mut self, user: [u8; 32], bytes: u64) -> Result<(), ReservationError> {
        if !self.used.contains_key(&user) && self.used.len() as u32 >= self.max_users {
            return Err(ReservationError::TooManyUsers);
        }
        let total: u64 = self.used.values().sum();
        if total + bytes > self.reserved_bytes {
            return Err(ReservationError::NoSpace);
        }
        *self.used.entry(user).or_insert(0) += bytes;
        Ok(())
    }

    /// Libération après réconciliation (ordre de tombstone).
    pub fn release(&mut self, user: &[u8; 32]) {
        self.used.remove(user);
    }

    pub fn users(&self) -> usize {
        self.used.len()
    }
}

/// Clés DHT à consulter au retour : une par Utilisateur rattaché, dérivée
/// de son `K_attach`.
pub fn emergency_keys(attached_k_attach: &[[u8; 32]]) -> Vec<[u8; 32]> {
    attached_k_attach.iter().map(emergency_dht_key).collect()
}

/// Intégration au retour : blocs de secours par timestamp croissant,
/// jusqu'au quota libre de l'Utilisateur.
pub fn integrate_emergency(
    writes: Vec<PendingWrite>,
    free_blocks: u64,
    already_stored: &dyn Fn(&[u8; 32]) -> bool,
) -> Integration {
    integrate(writes, free_blocks, already_stored)
}
