//! K_dispersal_content / K_dispersal_block — chiffrement des blocs internes
//! de l'arbre d'index (au-delà de la racine). Id `crypto.k-dispersal`
//! (Phase 0). Réf. spec : docs/03-crypto/k-dispersal.md (§3.8).
//!
//! ```text
//! K_dispersal_content = KDF(K_attach, "dispersal-content")
//! K_dispersal_block   = KDF(K_dispersal_content, block_hash)
//! ```
//!
//! Choix d'implémentation du « KDF » de la spec : HKDF-SHA-256 (bibliothèque
//! `hkdf`, cf. impl/TECH_STACK.md et `k_attach.rs`/`k_block.rs`), sortie
//! 32 octets. La formule ne nomme aucun salt externe pour ces deux
//! dérivations — seul le domaine `info` y figure :
//! - `info` = `"dispersal-content"` (premier étage, depuis `K_attach`) ;
//! - `info` = `block_hash` (second étage, liaison au bloc — même principe
//!   que `K_block`, voir `k_block.rs`).
//! Salt HKDF interne par défaut dans les deux cas (comme
//! `derive_sig_priv_dispersal` dans `k_attach.rs`).
//!
//! Propriété de sécurité testée explicitement (invariant de la migration,
//! page spec §« Séparation délibérée en deux étages ») : la dérivation est à
//! sens unique — `K_dispersal_content` ne permet pas de reconstituer
//! `K_attach` (HKDF n'est pas inversible ; le module n'expose aucune fonction
//! dans ce sens — voir `tests/k_dispersal_vectors.rs`). Le stub de `keys.rs`
//! le rappelle : toute fonction ajoutée ici qui prendrait
//! `K_dispersal_content` en entrée pour produire `K_attach` serait un bug de
//! conception.
//!
//! Invariants testés : déterminisme des deux étages, sensibilité au
//! `block_hash`, séparation de domaine (`K_dispersal_content` distinct de
//! `K_attach` et de `sig_priv_dispersal` pour le même `K_attach`) — voir
//! `tests/k_dispersal_vectors.rs`.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CoreError;

/// Premier étage : base commune à tous les blocs internes de l'arbre
/// d'index, transmissible au nouveau Nœud en migration sans exposer
/// `K_attach` (page spec, §« Conséquence pour la migration »).
pub fn derive_k_dispersal_content(k_attach: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, k_attach)
        .expand(b"dispersal-content", &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}

/// Second étage : clé propre à un bloc interne, dérivée bloc par bloc par le
/// nouveau Nœud sans intervention du Connecteur (page spec).
pub fn derive_k_dispersal_block(
    k_dispersal_content: &[u8; 32],
    block_hash: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, k_dispersal_content)
        .expand(block_hash, &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}
