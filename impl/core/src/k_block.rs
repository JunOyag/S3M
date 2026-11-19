//! K_block — chiffrement du contenu réel des blocs. Id `crypto.k-block`
//! (Phase 0, spec V3). Réf. spec : docs/03-crypto/k-block.md (§3.8).
//!
//! ```text
//! K_block = KDF(master_key[version], "block", encryption_salt, u32(index_du_bloc))
//! trame   = version (2 o) ‖ nonce (12 o, aléatoire) ‖ chiffré ‖ tag (16 o) = 65 536 o
//! AAD     = en-tête de version (2 o)
//! ```
//! - Indépendante de `block_hash` (hash du bloc chiffré complet, calculé
//!   après chiffrement) : aucune circularité.
//! - `encryption_salt` : 16 o CSPRNG, neuf à chaque création ou réémission,
//!   jamais réutilisé — une clé par version d'élément et par position, donc
//!   **un seul message par clé** ; le nonce aléatoire (tiré par l'appelant)
//!   n'est qu'une défense en profondeur.
//! - Le clair est complété par du padding à zéro jusqu'à 65 506 o.
//! - Jamais dérivée ni détenue par le Nœud.

use crate::error::CoreError;
use crate::labels;
use crate::symmetric_suite::{aead_open, aead_seal, kdf, AEAD_NONCE_LEN, AEAD_TAG_LEN};

/// Taille exacte d'un bloc stocké.
pub const BLOCK_SIZE: usize = 65_536;
/// Taille de l'en-tête de version en tête de trame.
pub const BLOCK_HEADER_LEN: usize = 2;
/// Clair utile d'un bloc : `65 536 − 2 − 12 − 16`.
pub const BLOCK_PLAINTEXT_LEN: usize =
    BLOCK_SIZE - BLOCK_HEADER_LEN - AEAD_NONCE_LEN - AEAD_TAG_LEN;
/// Taille de `encryption_salt`.
pub const ENCRYPTION_SALT_LEN: usize = 16;

/// `K_block = KDF(master_key[version], "block", encryption_salt, u32(index))`.
pub fn derive_k_block(
    master_key_version: &[u8; 32],
    encryption_salt: &[u8],
    block_index: u32,
) -> Result<[u8; 32], CoreError> {
    if encryption_salt.len() != ENCRYPTION_SALT_LEN {
        return Err(CoreError::InvalidSaltLength {
            expected: ENCRYPTION_SALT_LEN,
            got: encryption_salt.len(),
        });
    }
    kdf(
        master_key_version,
        labels::BLOCK,
        encryption_salt,
        &[&block_index.to_be_bytes()],
    )
}

/// Chiffre un bloc : `header ‖ nonce ‖ chiffré ‖ tag`, exactement
/// [`BLOCK_SIZE`] octets. `plaintext` (≤ [`BLOCK_PLAINTEXT_LEN`]) est
/// complété par des zéros. `nonce` : 12 o aléatoires tirés par l'appelant.
pub fn seal_block(
    k_block: &[u8; 32],
    header: &[u8; BLOCK_HEADER_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if plaintext.len() > BLOCK_PLAINTEXT_LEN {
        return Err(CoreError::BlockFormat {
            reason: "clair supérieur à 65 506 o",
        });
    }
    let mut padded = vec![0u8; BLOCK_PLAINTEXT_LEN];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    let sealed = aead_seal(k_block, nonce, header, &padded)?;
    let mut frame = Vec::with_capacity(BLOCK_SIZE);
    frame.extend_from_slice(header);
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&sealed);
    debug_assert_eq!(frame.len(), BLOCK_SIZE);
    Ok(frame)
}

/// Ouvre une trame de bloc et rend le clair complet de
/// [`BLOCK_PLAINTEXT_LEN`] octets (padding compris). Rejette une trame de
/// taille incorrecte ou d'en-tête différent de `expected_header`, et toute
/// altération (tag AEAD, l'en-tête étant l'AAD).
pub fn open_block(
    k_block: &[u8; 32],
    expected_header: &[u8; BLOCK_HEADER_LEN],
    frame: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if frame.len() != BLOCK_SIZE {
        return Err(CoreError::BlockFormat {
            reason: "trame différente de 65 536 o",
        });
    }
    let (header, rest) = frame.split_at(BLOCK_HEADER_LEN);
    if header != expected_header {
        return Err(CoreError::BlockFormat {
            reason: "en-tête de version inattendu",
        });
    }
    let (nonce, sealed) = rest.split_at(AEAD_NONCE_LEN);
    aead_open(k_block, nonce, header, sealed)
}
