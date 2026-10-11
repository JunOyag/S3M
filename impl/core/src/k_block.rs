//! K_block — chiffrement du contenu réel des blocs de données/parité.
//! Id `crypto.k-block` (Phase 0). Réf. spec : docs/03-crypto/k-block.md
//! (§3.8). JAMAIS dérivée ni détenue par le Nœud — uniquement par le
//! Connecteur, depuis la seed BIP-39 du User.
//!
//! ```text
//! K_block = KDF(master_key[version], block_hash, encryption_salt)
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
//! - `info` HKDF = `block_hash` (liaison au bloc : deux blocs du même
//!   fichier/répertoire — même salt, hash distinct — donnent des K_block
//!   distincts ; c'est la révocabilité individuelle exigée par la page).
//! La page ne fixe ni fonction de hachage ni autre domaine de séparation ;
//! `block_hash` en `info` suffit à séparer les blocs entre eux, et un domaine
//! supplémentaire non spécifié serait une improvisation (règle SPEC_GAPS.md).
//!
//! Invariants testés : déterminisme, sensibilité au `block_hash`, sensibilité
//! au `encryption_salt`, sensibilité à `master_key[version]` — voir
//! `tests/k_block_vectors.rs`.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CoreError;

/// Dérive `K_block` pour un bloc donné.
///
/// - `master_key_version` : `master_key[version]` résolue via
///   `master_key_chain::resolve_master_key` (le `key_version` vient de
///   `fs.DirectoryEntry`, pas du `DispersalManifest` en fonctionnement
///   normal — voir page spec, section « Versionnement »).
/// - `block_hash` : hash du bloc (lie la clé au contenu adressé).
/// - `encryption_salt` : salt fixé par fichier/répertoire, porté par
///   l'entrée FS — partagé par tous les blocs du même fichier/répertoire.
pub fn derive_k_block(
    master_key_version: &[u8; 32],
    block_hash: &[u8; 32],
    encryption_salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(encryption_salt), master_key_version)
        .expand(block_hash, &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}
