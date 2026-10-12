//! Suite cryptographique symétrique — id `crypto.symmetric-suite` (Phase 0).
//! Réf. spec : docs/03-crypto/symmetric-suite.md (§3.8). La page fixe
//! l'**unique** suite du protocole : primitive AEAD, KDF et hash — aucune
//! page de clé n'instantie sa propre primitive, elles renvoient ici.
//!
//! ```text
//! AEAD              ChaCha20-Poly1305 (RFC 8439) — clé 32 o, nonce 12 o, tag 16 o
//! KDF               HKDF-SHA256 (RFC 5869) — sortie 32 o dans toute la spec
//! hash              SHA-256
//! K_nonce           HKDF-SHA256(K_enc, info = "p2p-storage/synthetic-nonce/v1"),
//!                   sans sel
//! nonce synthétique 12 premiers octets de
//!                   HMAC-SHA256(K_nonce, u32(len(AAD)) ‖ AAD ‖ clair)
//! K_wrap            HKDF-SHA256(master_key[vc], salt = ∅,
//!                   info = encodage canonique("p2p-storage/master-key-wrap/v1"
//!                       ‖ u16(vw) ‖ u16(vc)))
//! ```
//!
//! Choix d'implémentation (impl/TECH_STACK.md) : les crates `chacha20poly1305`,
//! `hkdf`, `hmac` et `sha2` — liées, jamais réimplémentées.
//!
//! Encodage canonique (§ KDF) : dans `salt`/`info`, chaque composante est
//! préfixée par sa longueur u32 gros-boutiste. Une **étiquette unique**
//! passée seule en `info` y va **brute** (une seule composante : aucune
//! frontière à délimiter — la page n'applique l'encodage qu'aux entrées
//! multiples) ; les dérivations à plusieurs composantes (ex. `K_wrap`) et
//! l'entrée du HMAC de nonce synthétique passent par `canonical_encode`.
//!
//! Politique de nonce rappelée (§ Politique de nonce) : le nonce n'est PAS
//! tiré ici — clé à usage unique → `NONCE_NUL` ; clé multi-messages
//! adressée par contenu → `synthetic_nonce` ; clé multi-messages non
//! adressée → nonce aléatoire 12 o côté appelant (OsRng, hors noyau).
//!
//! Vecteurs : `tests/symmetric_suite_vectors.rs` (RFC 8439 §2.8.2,
//! RFC 5869 A.1-A.3, RFC 4231 TC1-TC4, RFC 6234 §8.5, compositions générées
//! par `tests/vectors/gen_symmetric_suite_vectors.py`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
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

/// HMAC-SHA256 brut — primitive du nonce synthétique (§ Nonce synthétique),
/// testé contre RFC 4231 TC1-TC4 dans `tests/symmetric_suite_vectors.rs`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; HASH_LEN], CoreError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CoreError::HmacFailure)?;
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
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
    hk.expand(info, &mut okm).map_err(|_| CoreError::KdfFailure)?;
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

/// `K_nonce = HKDF-SHA256(K_enc, info = "p2p-storage/synthetic-nonce/v1")`,
/// **sans sel** (§ Nonce synthétique) — `K_enc` est la clé de chiffrement
/// de l'usage concerné (`K_block`, `K_dispersal_block`, …). Règle générique
/// de la suite.
pub fn derive_k_nonce(k_enc: &[u8]) -> Result<[u8; HASH_LEN], CoreError> {
    let okm = hkdf_sha256(
        k_enc,
        &[],
        labels::P2P_STORAGE_SYNTHETIC_NONCE_V1.as_bytes(),
        HASH_LEN,
    )?;
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&okm);
    Ok(out)
}

/// Nonce synthétique déterministe des blocs adressés par contenu
/// (§ Nonce synthétique) : 12 premiers octets de
/// `HMAC-SHA256(K_nonce, u32(len(AAD)) ‖ AAD ‖ clair)` — l'AAD porte
/// l'étiquette de contexte de l'usage (`labels::AAD_CONTEXT_BLOCK`, …).
/// Sous la même clé : un même message produit toujours le même chiffré
/// (bloc adressable par son contenu), deux messages distincts des nonces
/// distincts (collision de HMAC négligeable, borne ~2^48).
pub fn synthetic_nonce(
    k_nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<[u8; AEAD_NONCE_LEN], CoreError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(k_nonce).map_err(|_| CoreError::HmacFailure)?;
    // Entrée du HMAC en encodage canonique : u32(len(AAD)) ‖ AAD ‖ clair —
    // le clair est concaténé brut (formule exacte de la page, aucun préfixe).
    mac.update(&canonical_encode(&[aad]));
    mac.update(plaintext);
    let tag = mac.finalize().into_bytes();
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&tag[..AEAD_NONCE_LEN]);
    Ok(nonce)
}

/// `K_wrap` (§ Clé de wrap de `master_key[version]`) : HKDF-SHA256 sans sel,
/// `info` = encodage canonique de l'étiquette et des deux versions. Les deux
/// versions sont dans l'`info` : deux dérivations distinctes ne partagent
/// jamais de clé. Côté chiffrement (appelant — `crypto.master-key-chain`) :
/// clé **à usage unique** → nonce `NONCE_NUL`, trame `chiffré ‖ tag` de
/// 48 o (sans en-tête), AAD = `en-tête de version (2 o) ‖ "master-key-wrap"
/// ‖ u16(version_wrappée) ‖ u16(version_courante)`.
pub fn derive_k_wrap(
    master_key_current: &[u8],
    version_wrappee: u16,
    version_courante: u16,
) -> Result<[u8; HASH_LEN], CoreError> {
    let info = canonical_encode(&[
        labels::P2P_STORAGE_MASTER_KEY_WRAP_V1.as_bytes(),
        &version_wrappee.to_be_bytes(),
        &version_courante.to_be_bytes(),
    ]);
    let okm = hkdf_sha256(master_key_current, &[], &info, HASH_LEN)?;
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&okm);
    Ok(out)
}

