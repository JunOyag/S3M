//! En-tête de version de protocole — id `deploiement.formats-serialisation`,
//! component `core` (Phase 6). Réf. spec :
//! docs/07-deploiement/formats-serialisation.md.
//!
//! - 2 octets, `u16` **gros-boutiste** ; `0x0000` réservé et interdit ;
//!   valeur courante `1` (= suite ChaCha20-Poly1305 + HKDF-SHA256 + SHA-256).
//! - Les versions **coexistent** : un lecteur accepte toute version qu'il
//!   implémente, jamais de bump silencieux.
//! - Portée : préfixe des trames chiffrées et AAD (y compris le wrap, où
//!   l'en-tête n'existe qu'en AAD).

use crate::error::CoreError;

/// Version de protocole courante.
pub const CURRENT_VERSION: u16 = 1;
/// En-tête de la version courante.
pub const CURRENT_HEADER: [u8; 2] = CURRENT_VERSION.to_be_bytes();
/// Versions implémentées par ce code (coexistence).
pub const SUPPORTED_VERSIONS: &[u16] = &[1];

/// Encode l'en-tête d'une version (refuse la valeur réservée 0).
pub fn encode_header(version: u16) -> Result<[u8; 2], CoreError> {
    if version == 0 {
        return Err(CoreError::InvalidVersionHeader { version });
    }
    Ok(version.to_be_bytes())
}

/// Lit l'en-tête en tête de `bytes` : version réservée ou non implémentée
/// rejetée explicitement.
pub fn parse_header(bytes: &[u8]) -> Result<u16, CoreError> {
    let h: [u8; 2] = bytes
        .get(..2)
        .and_then(|b| b.try_into().ok())
        .ok_or(CoreError::InvalidVersionHeader { version: 0 })?;
    let version = u16::from_be_bytes(h);
    if version == 0 || !SUPPORTED_VERSIONS.contains(&version) {
        return Err(CoreError::InvalidVersionHeader { version });
    }
    Ok(version)
}
