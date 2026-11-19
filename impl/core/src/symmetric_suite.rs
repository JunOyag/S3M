//! Suite cryptographique symétrique — id `crypto.symmetric-suite` (Phase 0,
//! spec V3). Réf. spec : docs/03-crypto/symmetric-suite.md (§3.8). Unique
//! suite du protocole : AEAD, KDF et hash — les pages de clés renvoient ici.
//!
//! ```text
//! AEAD    ChaCha20-Poly1305 (RFC 8439) — clé 32 o, nonce 12 o, tag 16 o
//! KDF     KDF(secret, label, salt, entrées…) = HKDF-SHA256(IKM = secret, salt,
//!             info = "p2p-storage/kdf/v1" ‖ L(label) ‖ L(entrée_1) ‖ …), 32 o
//!         L(x) = u32 big-endian(len(x)) ‖ x
//! hash    SHA-256
//! K_wrap  KDF(master_key[vc], "master-key-wrap", —, u16(vw), u16(vc))
//! ```
//!
//! Crates liées, jamais réimplémentées : `chacha20poly1305`, `hkdf`, `sha2`.
//! Politique de nonce : `K_wrap` → `NONCE_NUL` (un message par clé) ; blocs
//! et blobs DHT → nonce aléatoire de 12 o tiré par l'appelant. Plus de nonce
//! synthétique (retiré en V3).
//!
//! Vecteurs : `tests/symmetric_suite_vectors.rs` (RFC 8439 §2.8.2,
//! RFC 5869 A.1-A.3, RFC 6234 §8.5, compositions générées par
//! `tests/vectors/gen_symmetric_suite_vectors.py`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::labels;

/// Clé AEAD de 32 octets (§ AEAD).
pub const AEAD_KEY_LEN: usize = 32;
/// Nonce AEAD de 12 octets (§ AEAD).
pub const AEAD_NONCE_LEN: usize = 12;
/// Tag d'authentification de 16 octets (§ AEAD).
pub const AEAD_TAG_LEN: usize = 16;
/// Sortie SHA-256 / HKDF-SHA256 : 32 octets.
pub const HASH_LEN: usize = 32;
/// Nonce nul (12 octets à zéro) — clé à usage unique (ex. `K_wrap`) : le
/// nonce est implicite, la trame est `chiffré ‖ tag` (§ Politique de nonce).
pub const NONCE_NUL: [u8; AEAD_NONCE_LEN] = [0u8; AEAD_NONCE_LEN];

fn check_aead_inputs(key: &[u8], nonce: &[u8]) -> Result<(), CoreError> {
    if key.len() != AEAD_KEY_LEN {
        return Err(CoreError::InvalidKeyLength {
            expected: AEAD_KEY_LEN,
            got: key.len(),
        });
    }
    if nonce.len() != AEAD_NONCE_LEN {
        return Err(CoreError::InvalidNonceLength {
            expected: AEAD_NONCE_LEN,
            got: nonce.len(),
        });
    }
    Ok(())
}

/// Chiffre `plaintext` sous `key` et retourne `chiffré ‖ tag` — **sans**
/// le nonce dans la trame (le transport du nonce relève de la politique de
/// nonce et de l'appelant : implicite pour `NONCE_NUL`, préfixé en clair
/// sinon).
pub fn aead_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    check_aead_inputs(key, nonce)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::AeadFailure)
}

/// Ouvre un `chiffré ‖ tag` : retourne le clair, ou `AeadFailure` si le tag
/// échoue — clé ou nonce incorrects, AAD ou chiffré altérés (§ AEAD :
/// toute transplantation ou falsification échoue à la vérification du tag).
pub fn aead_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_tag: &[u8],
) -> Result<Vec<u8>, CoreError> {
    check_aead_inputs(key, nonce)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_tag,
                aad,
            },
        )
        .map_err(|_| CoreError::AeadFailure)
}

/// HKDF-SHA256 (RFC 5869) avec sortie de `out_len` octets. `salt` vide =
/// `∅` du protocole (sel par défaut du RFC — équivalent HMAC à clé nulle).
/// Sortie 32 o dans le protocole ; `out_len` paramétrable pour les vecteurs
/// RFC 5869 (42 et 82 octets).
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CoreError> {
    let hk = if salt.is_empty() {
        Hkdf::<Sha256>::new(None, ikm)
    } else {
        Hkdf::<Sha256>::new(Some(salt), ikm)
    };
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}

/// Encodage canonique des entrées multiples (§ KDF) :
/// `u32(len(a)) ‖ a ‖ u32(len(b)) ‖ b ‖ …` (u32 gros-boutiste). Deux
/// dérivations aux mêmes composantes mais ordonnées différemment produisent
/// deux entrées HKDF distinctes — la frontière entre composantes ne peut
/// pas être ambiguë.
pub fn canonical_encode(components: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for component in components {
        out.extend_from_slice(&(component.len() as u32).to_be_bytes());
        out.extend_from_slice(component);
    }
    out
}

/// SHA-256 (§ Hash de contenu) — hash d'intégrité unique du protocole
/// (challenges PoS, `block_hash` en lecture, empreintes de blocs).
pub fn hash_sha256(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Convention KDF unique du protocole (§ KDF — HKDF-SHA256) :
/// `HKDF-SHA256(IKM = secret, salt, info = KDF_PREFIX ‖ L(label) ‖
/// L(entrée_1) ‖ …)`, sortie 32 o. `salt` vide = sans sel. Le secret est
/// toujours l'IKM seul ; les entrées publiques ne vont que dans `info`.
pub fn kdf(
    secret: &[u8],
    label: &str,
    salt: &[u8],
    public_inputs: &[&[u8]],
) -> Result<[u8; HASH_LEN], CoreError> {
    let mut components: Vec<&[u8]> = Vec::with_capacity(public_inputs.len() + 1);
    components.push(label.as_bytes());
    components.extend_from_slice(public_inputs);
    let mut info = labels::KDF_PREFIX.as_bytes().to_vec();
    info.extend_from_slice(&canonical_encode(&components));
    let okm = hkdf_sha256(secret, salt, &info, HASH_LEN)?;
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&okm);
    Ok(out)
}

/// `K_wrap = KDF(master_key[vc], "master-key-wrap", —, u16(vw), u16(vc))`
/// (§ Clé de wrap). Clé **à usage unique** côté appelant
/// (`crypto.master-key-chain`) : nonce `NONCE_NUL`, trame de 48 o sans
/// en-tête, AAD = `en-tête (2 o) ‖ "master-key-wrap" ‖ u16(vw) ‖ u16(vc)`.
pub fn derive_k_wrap(
    master_key_current: &[u8],
    version_wrappee: u16,
    version_courante: u16,
) -> Result<[u8; HASH_LEN], CoreError> {
    kdf(
        master_key_current,
        labels::MASTER_KEY_WRAP,
        &[],
        &[
            &version_wrappee.to_be_bytes(),
            &version_courante.to_be_bytes(),
        ],
    )
}
