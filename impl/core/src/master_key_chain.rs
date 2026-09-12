//! Chaîne de clés maîtresses (rotation d'identité User sans rechiffrement des
//! blocs existants). Réf. spec §3.8 "Continuité de chiffrement".
//!
//! Principe : re-wrap PLAT (pas de chaînage séquentiel) — chaque clé
//! historique est déchiffrable en une seule étape depuis la clé maîtresse
//! COURANTE, quel que soit le nombre de rotations passées. Invariant à
//! tester : après N rotations simulées, `resolve_master_key(version=0)` doit
//! rester en O(1) (une seule opération d'unwrap), pas O(N).

use crate::error::CoreError;
use std::collections::HashMap;

/// Un maillon `{version, wrapped_key}` tel que publié dans l'entrée DHT User
/// (§3.9) — correspond à `MasterKeyEntry` du schéma `DispersalManifest.fbs`.
pub struct MasterKeyEntry {
    pub version: u16,
    pub wrapped_key: Vec<u8>,
}

/// Re-wrap intégral de toutes les clés maîtresses historiques sous la
/// nouvelle clé courante, au moment d'une rotation (§5.2 "Compromission Clé
/// User"). Le Connecteur détient encore les clés en clair à cet instant —
/// c'est la seule fenêtre où ce re-wrap est possible.
pub fn rewrap_chain_on_rotation(
    _historical_keys_cleartext: &HashMap<u16, [u8; 32]>,
    _new_master_key: &[u8; 32],
) -> Result<Vec<MasterKeyEntry>, CoreError> {
    todo!("Phase 0 — pour chaque (version, clé) : wrap symétrique sous new_master_key")
}

/// Résolution d'une version historique à la lecture d'un bloc ancien (§3.13,
/// key_version porté par DirectoryEntry).
pub fn resolve_master_key(
    _chain: &[MasterKeyEntry],
    _current_master_key: &[u8; 32],
    _wanted_version: u16,
) -> Result<[u8; 32], CoreError> {
    todo!("Phase 0 — trouver l'entrée de version wanted_version, unwrap avec current_master_key")
}
