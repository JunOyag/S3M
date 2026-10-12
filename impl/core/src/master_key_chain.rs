//! Chaîne de clés maîtresses (rotation d'identité User sans rechiffrement des
//! blocs existants). Id `crypto.master-key-chain` (Phase 0). Réf. spec :
//! docs/03-crypto/master-key-chain.md (§3.8).
//!
//! Principe : re-wrap PLAT (pas de chaînage séquentiel) — chaque clé
//! historique est déchiffrable en une seule étape depuis la clé maîtresse
//! COURANTE, quel que soit le nombre de rotations passées. Invariant testé :
//! après N rotations simulées, `resolve_master_key(version=0)` reste en O(1)
//! (une seule opération d'unwrap), pas O(N).
//!
//! Wrap (règle de `crypto.symmetric-suite`, § Clé de wrap) : `K_wrap`
//! dérivée via `symmetric_suite::derive_k_wrap` (**réutilisée, jamais
//! redérivée ici**), ChaCha20-Poly1305 sous nonce nul, trame
//! `chiffré ‖ tag` de **48 o sans en-tête** (l'en-tête de version de
//! protocole, `u16` gros-boutiste fixé par
//! `deploiement.formats-serialisation`, n'existe qu'en AAD :
//! `en-tête ‖ "master-key-wrap" ‖ u16(version_wrappée) ‖
//! u16(version_courante)`).

use std::collections::HashMap;

use crate::error::CoreError;
use crate::symmetric_suite::{self, NONCE_NUL};

/// Un maillon `{version, wrapped_key}` tel que publié dans l'entrée DHT User
/// (§3.9) — correspond à `MasterKeyEntry` du schéma `DispersalManifest.fbs`.
/// `wrapped_key` mesure exactement 48 o (32 o chiffrés ‖ tag 16 o).
pub struct MasterKeyEntry {
    pub version: u16,
    pub wrapped_key: Vec<u8>,
}

/// Construit l'AAD du wrap : `en-tête de version (2 o) ‖ "master-key-wrap"
/// ‖ u16(version_wrappée) ‖ u16(version_courante)`.
fn wrap_aad(protocol_header: &[u8; 2], version_wrappee: u16, version_courante: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        2 + crate::labels::AAD_CONTEXT_MASTER_KEY_WRAP.len() + 2 + 2,
    );
    aad.extend_from_slice(protocol_header);
    aad.extend_from_slice(crate::labels::AAD_CONTEXT_MASTER_KEY_WRAP.as_bytes());
    aad.extend_from_slice(&version_wrappee.to_be_bytes());
    aad.extend_from_slice(&version_courante.to_be_bytes());
    aad
}

/// Wrap symétrique d'une clé historique sous la clé courante (48 o, sans
/// en-tête — l'en-tête n'existe qu'en AAD).
fn wrap_one(
    protocol_header: &[u8; 2],
    historical_key: &[u8; 32],
    version_wrappee: u16,
    current_master_key: &[u8; 32],
    version_courante: u16,
) -> Result<MasterKeyEntry, CoreError> {
    let k_wrap =
        symmetric_suite::derive_k_wrap(current_master_key, version_wrappee, version_courante)?;
    let aad = wrap_aad(protocol_header, version_wrappee, version_courante);
    let wrapped_key =
        symmetric_suite::aead_seal(&k_wrap, &NONCE_NUL, &aad, historical_key)?;
    debug_assert_eq!(wrapped_key.len(), 48);
    Ok(MasterKeyEntry {
        version: version_wrappee,
        wrapped_key,
    })
}

/// Déchiffre un maillon sous la clé courante → `master_key[version]`.
fn unwrap_one(
    protocol_header: &[u8; 2],
    entry: &MasterKeyEntry,
    current_master_key: &[u8; 32],
    version_courante: u16,
) -> Result<[u8; 32], CoreError> {
    let k_wrap =
        symmetric_suite::derive_k_wrap(current_master_key, entry.version, version_courante)?;
    let aad = wrap_aad(protocol_header, entry.version, version_courante);
    let opened =
        symmetric_suite::aead_open(&k_wrap, &NONCE_NUL, &aad, &entry.wrapped_key)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&opened);
    Ok(out)
}

/// Re-wrap intégral de toutes les clés maîtresses historiques sous la
/// nouvelle clé courante, au moment d'une rotation (§5.2 "Compromission Clé
/// User"). Le Connecteur détient encore les clés en clair à cet instant —
/// c'est la seule fenêtre où ce re-wrap est possible. La nouvelle clé
/// elle-même n'est pas wrappée : elle est détenue directement (dérivée au
/// chemin `m/0x703270'/3'/version_courante`, voir
/// `crypto.identity-derivation`).
pub fn rewrap_chain_on_rotation(
    protocol_header: &[u8; 2],
    historical_keys_cleartext: &HashMap<u16, [u8; 32]>,
    new_master_key: &[u8; 32],
    new_version: u16,
) -> Result<Vec<MasterKeyEntry>, CoreError> {
    let mut chain = Vec::with_capacity(historical_keys_cleartext.len());
    let mut versions: Vec<u16> = historical_keys_cleartext.keys().copied().collect();
    versions.sort_unstable();
    for version in versions {
        let key = historical_keys_cleartext[&version];
        chain.push(wrap_one(
            protocol_header,
            &key,
            version,
            new_master_key,
            new_version,
        )?);
    }
    Ok(chain)
}

/// Résolution d'une version historique à la lecture d'un bloc ancien (§3.13,
/// key_version porté par DirectoryEntry). Recherche l'entrée de
/// `wanted_version` dans la chaîne et l'unwrap sous la clé courante —
/// **une seule** opération d'unwrap quel que soit le nombre de rotations
/// (re-wrap plat, O(1)).
pub fn resolve_master_key(
    protocol_header: &[u8; 2],
    chain: &[MasterKeyEntry],
    current_master_key: &[u8; 32],
    current_version: u16,
    wanted_version: u16,
) -> Result<[u8; 32], CoreError> {
    let entry = chain
        .iter()
        .find(|e| e.version == wanted_version)
        .ok_or(CoreError::UnknownKeyVersion {
            version: wanted_version,
        })?;
    unwrap_one(protocol_header, entry, current_master_key, current_version)
        .map_err(|_| CoreError::UnwrapFailure)
}
