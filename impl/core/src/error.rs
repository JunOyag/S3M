//! Type d'erreur unique du crate. Chaque module y ajoute ses variantes plutôt
//! que de définir son propre type — cohérence de propagation vers `impl/node`
//! et vers la frontière WASM (`impl/connector`).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("conversion de clé Ed25519 -> X25519 invalide (point non canonique)")]
    KeyConversion,

    #[error("longueur de clé invalide : attendu {expected} octets, reçu {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("longueur de nonce invalide : attendu {expected} octets, reçu {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("opération AEAD en échec (nonce incorrect ou tag d'authentification rejeté)")]
    AeadFailure,

    #[error("calcul HMAC-SHA256 échoué")]
    HmacFailure,

    #[error("échec de dérivation HKDF")]
    KdfFailure,

    #[error("version de master_key inconnue dans master_key_chain : {version}")]
    UnknownKeyVersion { version: u16 },

    #[error("unwrap de clé échoué (mauvaise clé courante ou donnée corrompue)")]
    UnwrapFailure,

    #[error("dérivation d'identité échouée (PBKDF2-HMAC-SHA512 ou HMAC-SHA512 SLIP-0010)")]
    IdentityDerivation,

    #[error("index de dérivation durcie hors bornes (attendu < 2^31) : {index}")]
    InvalidDerivationIndex { index: u32 },

    // À compléter au fil de la Phase 0 — une variante par échec distinct
    // rencontré, jamais un `Other(String)` fourre-tout (perd l'info côté
    // appelant WASM/FFI).
}
