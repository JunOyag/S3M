//! K_block — chiffrement du contenu réel des blocs de données/parité.
//! Id `crypto.k-block` (Phase 0). Réf. spec : docs/03-crypto/k-block.md
//! (§3.8). JAMAIS dérivée ni détenue par le Nœud — uniquement par le
//! Connecteur, depuis la seed BIP-39 du User.
//!
//! ```text
//! K_block = KDF(master_key[version], info = "p2p-storage/block/v1",
//!               salt = encryption_salt)
//! ```
//! `master_key[version]` provient de `master_key_chain.rs` (résolution de
//! version). `encryption_salt` est porté par l'entrée FS (`DirectoryEntry`,
//! §3.13), pas par ce module — appelant à charge de le fournir.
//!
//! Choix d'implémentation du « KDF » de la spec : HKDF-SHA-256 (bibliothèque
//! `hkdf`, cf. impl/TECH_STACK.md et `k_attach.rs`), sortie 32 octets.
//! Mapping des deux paramètres nommés par la formule :
//! - `salt` HKDF = `encryption_salt` (aléa public fixé une fois par fichier
//!   ou répertoire — rôle exact d'un salt d'extraction) ;
//! - `info` HKDF = étiquette unique `p2p-storage/block/v1` (registre de
//!   `crypto.symmetric-suite`, `labels::P2P_STORAGE_BLOCK_V1`) — pas
//!   d'encodage canonique (une seule composante, arbitrage de la passe
//!   `crypto.symmetric-suite`, cf. `symmetric_suite.rs`).
//!
//! **Indépendante de `block_hash`** : la formule ne lit aucun hash du
//! chiffrement qu'elle produit (circularité `block_hash` ↔ `K_block`
//! arbitrée dans `impl/SPEC_GAPS.md` — affaiblissement volontaire :
//! une clé par **élément**, révocable au niveau de l'élément). `block_hash`
//! est le hash du **chiffré**, calculé après chiffrement — chiffrement
//! déterministe à nonce synthétique (§ Nonce synthétique).
//!
//! Invariants testés : déterminisme, sensibilité au `encryption_salt`,
//! sensibilité à `master_key[version]` — voir `tests/k_block_vectors.rs`.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CoreError;
use crate::labels;

/// Dérive `K_block` pour un élément (fichier ou répertoire) donné.
///
/// - `master_key_version` : `master_key[version]` résolue via
///   `master_key_chain::resolve_master_key` (le `key_version` vient de
///   `fs.DirectoryEntry`, pas du `DispersalManifest` en fonctionnement
///   normal — voir page spec, section « Versionnement »).
/// - `encryption_salt` : salt fixé par élément, porté par l'entrée FS —
///   partagé par tous les blocs du même fichier/répertoire.
pub fn derive_k_block(
    master_key_version: &[u8; 32],
    encryption_salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(encryption_salt), master_key_version)
        .expand(labels::P2P_STORAGE_BLOCK_V1.as_bytes(), &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}
