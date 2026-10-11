//! K_attach — clé partagée Nœud <-> Connecteur pour un couple (User, Node).
//! Id `crypto.k-attach` (Phase 0). Réf. spec : docs/03-crypto/k-attach.md
//! (§3.8). NE chiffre JAMAIS le contenu réel des blocs (c'est le rôle de
//! `k_block`) — uniquement le `DispersalManifest`.
//!
//! ```text
//! priv_user_x25519 = ed25519_to_x25519(priv_user)
//! pub_node_x25519  = ed25519_to_x25519(pub_node)
//! K_attach = KDF(X25519(priv_user_x25519, pub_node_x25519), salt)
//! ```
//! Côté Nœud, calcul symétrique avec (priv_node_x25519, pub_user_x25519).
//! Invariant testé : les deux calculs produisent le même résultat
//! (propriété d'échange X25519) — voir `tests/rfc_vectors.rs`.
//!
//! Choix d'implémentation du « KDF » de la spec : HKDF-SHA-256 (bibliothèque
//! `hkdf`, cf. impl/TECH_STACK.md), salt = le salt fixé par le Connecteur,
//! `info` vide, sortie 32 octets. La page spec ne fixe ni fonction de
//! hachage ni `info` pour cette dérivation — seul le salt y est nommé ; la
//! forme minimale ci-dessus reste fidèle à la formule écrite sans improviser
//! de domaine de séparation non spécifié (le salt joue déjà ce rôle côté
//! attachement).
//!
//! `priv_user` / `priv_node` : graine Ed25519 de 32 octets (voir `keys.rs`).

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CoreError;
use crate::keys::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};

fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}

/// Côté Connecteur (User) : K_attach depuis `priv_user` (graine Ed25519
/// 32 octets) et `pub_node` (clé publique Ed25519 du Nœud), pour le `salt`
/// fixé au moment de l'attachement (stocké côté Nœud dans `node.AttachedUser`,
/// côté Connecteur dans l'historique `attachments` de l'entrée DHT User).
pub fn derive_k_attach_as_user(
    priv_user: &[u8; 32],
    pub_node: &[u8; 32],
    salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    let priv_x = ed25519_priv_to_x25519(priv_user)?;
    let pub_x = ed25519_pub_to_x25519(pub_node)?;
    // `StaticSecret::from` ré-applique le clampage — idempotent ici.
    let shared = StaticSecret::from(priv_x).diffie_hellman(&PublicKey::from(pub_x));
    hkdf_sha256(shared.as_bytes(), Some(salt), &[])
}

/// Côté Nœud : calcul symétrique avec `priv_node` / `pub_user`. Doit produire
/// exactement le même `K_attach` que `derive_k_attach_as_user` pour le même
/// couple et le même salt (testé dans `tests/rfc_vectors.rs`). Le Nœud
/// dispose localement de `pub_user` (stocké comme `user_id` dans
/// `node.AttachedUser`) et du salt — aucune requête DHT n'est nécessaire
/// pour re-dériver K_attach à tout moment.
pub fn derive_k_attach_as_node(
    priv_node: &[u8; 32],
    pub_user: &[u8; 32],
    salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    let priv_x = ed25519_priv_to_x25519(priv_node)?;
    let pub_x = ed25519_pub_to_x25519(pub_user)?;
    let shared = StaticSecret::from(priv_x).diffie_hellman(&PublicKey::from(pub_x));
    hkdf_sha256(shared.as_bytes(), Some(salt), &[])
}

/// `sig_priv_dispersal = KDF(K_attach, "dispersal-signing")` — page
/// k-attach, section « Portée de signature dérivée ». HKDF-SHA-256 avec
/// `info = "dispersal-signing"` et salt interne par défaut (aucun salt
/// externe n'est nommé par la spec pour cette dérivation).
/// Calculable par le Nœud ET le Connecteur, mais seul le Nœud doit s'en
/// servir pour signer en fonctionnement normal (règle applicative, pas
/// cryptographique — rien n'empêche techniquement le Connecteur de signer :
/// c'est un invariant à faire respecter côté impl/connector, pas ici).
pub fn derive_sig_priv_dispersal(k_attach: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    hkdf_sha256(k_attach, None, b"dispersal-signing")
}