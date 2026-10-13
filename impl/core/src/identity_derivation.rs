//! Dérivation des identités asymétriques — BIP-39 → SLIP-0010 (ed25519).
//! Id `crypto.identity-derivation` (Phase 0). Réf. spec :
//! docs/03-crypto/identity-derivation.md (§5.2, §7.1).
//!
//! Chaîne complète, entièrement durcie (SLIP-0010 n'autorise que la
//! dérivation durcie pour ed25519) :
//!
//! ```text
//! phrase BIP-39 --PBKDF2-HMAC-SHA512(salt="mnemonic"+passphrase, 2048 it.)-->
//!   seed 64 o
//! seed 64 o --HMAC-SHA512(clé="ed25519 seed")--> clé maître SLIP-0010
//!   (k ‖ c, 32 o + 32 o)
//! clé maître --3 dérivations durcies--> m/0x703270'/<role>'/<index>'
//! ```
//!
//! Choix d'implémentation :
//! - PBKDF2-HMAC-SHA512 composé sur `hmac`/`sha2` déjà présents (RFC 8017
//!   §5.2, PRF = HMAC-SHA-512, sortie fixe 64 o = un seul bloc) — pas de
//!   dépendance additionnelle, conforme à l'esprit d'impl/TECH_STACK.md.
//! - La normalisation NFKD de la phrase et de la passphrase (exigée par
//!   BIP-39 pour les wordlists non-ASCII) est **présumée faite par
//!   l'appelant** — sans effet pour la wordlist anglaise (ASCII pur) ; le
//!   Connecteur applique `String.prototype.normalize("NFKD")` côté TS.
//! - La clé privée SLIP-0010 ed25519 produite **est** une graine Ed25519
//!   RFC 8032 de 32 o (page spec, § « La clé privée SLIP-0010 est une graine
//!   Ed25519 ») — aucune traduction avant `keys.rs` / `k_attach.rs`.
//! - Aucune I/O : la règle de balayage DHT (« Découverte de l'index courant
//!   après perte totale ») appartient au Nœud/Connecteur, pas au noyau.
//!
//! Invariants testés : vecteurs officiels BIP-39 (Trezor) et SLIP-0010,
//! déterminisme, séparation de domaine des rôles, sensibilité à l'index et à
//! la passphrase — voir `tests/identity_derivation_vectors.rs`.

use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::error::CoreError;

type HmacSha512 = Hmac<Sha512>;

/// `purpose'` du chemin — « p2p » en ASCII (0x70='p', 0x32='2', 0x70='p').
/// Page spec, § « Chaîne de dérivation » : indice durci sérialisé
/// `0x80703270` (testé).
pub const PURPOSE: u32 = 0x70_3270;

/// Bit de durcissement SLIP-0010 (ajouté à chaque index de segment).
pub const HARDENED: u32 = 0x8000_0000;

/// Rôles du schéma de chemins (page spec, § « Rôles ») — discriminant = valeur
/// du segment de rôle (avant durcissement). Aucun rôle au-delà de `0'`..`3'`
/// n'est défini à ce jour ; l'énumération rend les autres valeurs
/// inutilisables par construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRole {
    /// `m/0x703270'/0'/<index>'` — User (`priv_user`/`pub_user`).
    User = 0,
    /// `m/0x703270'/1'/<index>'` — Node (`priv_node`/`pub_node`).
    Node = 1,
    /// `m/0x703270'/2'/<index>'` — clé de secours du Node d'index `<index>'`
    /// (clé de secours en miroir : même index que le Node accompagné).
    NodeRecovery = 2,
    /// `m/0x703270'/3'/version'` — `master_key[version]` (compteur `uint16`
    /// indépendant de l'index d'identité ; ne signe jamais, pas d'échange DH).
    MasterKey = 3,
}

/// Étape 1 (BIP-39) : phrase mnémonique + passphrase → seed de 64 octets.
///
/// PBKDF2-HMAC-SHA512, 2048 itérations (standard BIP-39), sel =
/// `"mnemonic" ‖ passphrase`. La passphrase est **vide par défaut** (page
/// spec, § « Passphrase ») ; une passphrase erronée ne produit aucune erreur
/// — elle dérive une identité valide mais différente.
///
/// La phrase et la passphrase doivent être normalisées NFKD par l'appelant
/// (voir en-tête de module).
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64], CoreError> {
    let salt = format!("mnemonic{passphrase}");
    pbkdf2_hmac_sha512_64(mnemonic.as_bytes(), salt.as_bytes(), 2048)
}

/// Étape 2 (SLIP-0010) : seed 64 o → clé maître `(k, c)` —
/// `HMAC-SHA512(clé = "ed25519 seed", données = seed)`, scindé en
/// `k = I[0..32]` (graine ed25519, `parse_256` = identité) et `c = I[32..64]`
/// (chain code).
///
/// Exposée publiquement : couche standard vérifiable directement contre les
/// vecteurs officiels SLIP-0010 (voir tests).
pub fn slip10_master_key(bip39_seed: &[u8; 64]) -> Result<([u8; 32], [u8; 32]), CoreError> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|_| CoreError::IdentityDerivation)?;
    mac.update(bip39_seed);
    let i = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&i[0..32]);
    c.copy_from_slice(&i[32..64]);
    Ok((k, c))
}

/// Étape 3 (SLIP-0010) : dérivation durcie d'un enfant ed25519 —
/// `data = 0x00 ‖ k_parent ‖ ser32(index + HARDENED)`,
/// `I = HMAC-SHA512(clé = c_parent, données = data)`, `k = I[0..32]`,
/// `c = I[32..64]`. Aucun « retry » (contrairement à secp256k1/P-256) :
/// toute graine de 32 o est une graine ed25519 valide.
///
/// `index` est l'index **non durci** (< 2^31) ; le bit de durcissement est
/// ajouté ici (ed25519 n'accepte que des dérivations durcies) — appelant et
/// fonction ne peuvent pas le double-ajouter.
///
/// Exposée publiquement : couche standard vérifiable directement contre les
/// vecteurs officiels SLIP-0010 (voir tests).
pub fn slip10_hardened_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), CoreError> {
    if index >= HARDENED {
        return Err(CoreError::InvalidDerivationIndex { index });
    }
    let mut mac = HmacSha512::new_from_slice(parent_chain_code)
        .map_err(|_| CoreError::IdentityDerivation)?;
    mac.update(&[0x00]); // préfixe ser_P des clés privées ed25519 (SLIP-0010)
    mac.update(parent_key);
    mac.update(&(index + HARDENED).to_be_bytes());
    let i = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&i[0..32]);
    c.copy_from_slice(&i[32..64]);
    Ok((k, c))
}

/// Dérivation complète d'une identité : `m/0x703270'/<role>'/<index>'`.
///
/// `index` est l'index non durci du rôle (`<index>'` pour les identités,
/// `version'` pour `IdentityRole::MasterKey` — borné `uint16` par la spec,
/// cf. `derive_master_key`). Sortie : la graine Ed25519 de 32 o servant de
/// clé privée (`priv_user` / `priv_node` / `priv_node_recovery` /
/// `master_key[version]`).
pub fn derive_identity_seed(
    bip39_seed: &[u8; 64],
    role: IdentityRole,
    index: u32,
) -> Result<[u8; 32], CoreError> {
    let (k, c) = slip10_master_key(bip39_seed)?;
    let (k, c) = slip10_hardened_child(&k, &c, PURPOSE)?;
    let (k, c) = slip10_hardened_child(&k, &c, role as u32)?;
    let (k, _c) = slip10_hardened_child(&k, &c, index)?;
    Ok(k)
}

/// Raccourci typé pour le rôle `3'` : `master_key[version]` au chemin
/// `m/0x703270'/3'/version'`. La borne `uint16` de `version` (page spec,
/// § « Rôles ») est garantie par le type d'entrée.
///
/// `master_key_chain` reste l'**unique** mécanisme de lecture des versions
/// antérieures (page spec, § « Règle d'index ») — ne pas re-dériver une
/// version historique pour lire un bloc ancien.
pub fn derive_master_key(bip39_seed: &[u8; 64], version: u16) -> Result<[u8; 32], CoreError> {
    derive_identity_seed(bip39_seed, IdentityRole::MasterKey, u32::from(version))
}

/// PBKDF2-HMAC-SHA512 (RFC 8017 §5.2), sortie fixe 64 octets — le seul
/// besoin en BIP-39 (seed de 64 o = hLen SHA-512 → exactement un bloc `T`).
fn pbkdf2_hmac_sha512_64(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
) -> Result<[u8; 64], CoreError> {
    debug_assert!(rounds >= 1);
    // U_1 = PRF(P, S ‖ INT_32_BE(1)) ; U_j = PRF(P, U_{j-1}) ;
    // T = U_1 ⊕ U_2 ⊕ … ⊕ U_c  (un seul bloc car dkLen = hLen = 64 o).
    let mut mac =
        HmacSha512::new_from_slice(password).map_err(|_| CoreError::IdentityDerivation)?;
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut t = u;
    for _ in 1..rounds {
        let mut mac =
            HmacSha512::new_from_slice(password).map_err(|_| CoreError::IdentityDerivation)?;
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (ti, ui) in t.iter_mut().zip(u.iter()) {
            *ti ^= ui;
        }
    }
    Ok(*t.as_ref())
}