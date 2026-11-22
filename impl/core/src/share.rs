//! Clés d'un partage — id `protocols.partage`. Réf. spec :
//! docs/04-protocols/partage.md. Aucun aléa tiré ici : secret, clés
//! éphémères et nonces sont fournis par l'appelant.
//!
//! ```text
//! share_id        = SHA-256(L("s3m/share-id") ‖ S)
//! K_share_content = KDF(S, "share-content")
//! sig_priv_share  = KDF(priv_user, "share-signing", —, share_id)
//! clé d'annuaire  = SHA-256(sig_pub_share ‖ "share")
//! invitation      = éph_pub ‖ nonce ‖ AEAD(KDF(X25519(éph, pub_user_x25519), "share-invite", —, éph_pub), jeton)
//! ```

use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CoreError;
use crate::keys::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};
use crate::labels;
use crate::symmetric_suite::{
    aead_open, aead_seal, canonical_encode, hash_sha256, kdf, AEAD_NONCE_LEN,
};

const INVITE_AAD: &[u8] = b"s3m/share-invite";

/// `share_id = SHA-256(L("s3m/share-id") ‖ S)`.
pub fn share_id(secret: &[u8; 32]) -> [u8; 32] {
    let mut m = canonical_encode(&[b"s3m/share-id"]);
    m.extend_from_slice(secret);
    hash_sha256(&m)
}

/// `K_share_content = KDF(S, "share-content")`.
pub fn share_content_key(secret: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    kdf(secret, labels::SHARE_CONTENT, &[], &[])
}

/// Graine de `sig_priv_share = KDF(priv_user, "share-signing", —, share_id)`.
pub fn share_signing_seed(
    priv_user: &[u8; 32],
    share_id: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    kdf(priv_user, labels::SHARE_SIGNING, &[], &[share_id])
}

/// Clé de l'annuaire : `SHA-256(sig_pub_share ‖ "share")`.
pub fn share_dht_key(sig_pub_share: &[u8; 32]) -> [u8; 32] {
    let mut m = sig_pub_share.to_vec();
    m.extend_from_slice(b"share");
    hash_sha256(&m)
}

fn invite_aad(recipient_pub_user: &[u8; 32]) -> Vec<u8> {
    canonical_encode(&[INVITE_AAD, recipient_pub_user])
}

/// Chiffre `token` pour `recipient_pub_user` seul : `éph_pub ‖ nonce ‖
/// chiffré ‖ tag`. `ephemeral` (32 o) et `nonce` tirés par l'appelant.
pub fn seal_invite(
    recipient_pub_user: &[u8; 32],
    ephemeral: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_LEN],
    token: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let eph = StaticSecret::from(*ephemeral);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let peer = PublicKey::from(ed25519_pub_to_x25519(recipient_pub_user)?);
    let shared = eph.diffie_hellman(&peer);
    let k = kdf(shared.as_bytes(), labels::SHARE_INVITE, &[], &[&eph_pub])?;
    let mut out = eph_pub.to_vec();
    out.extend_from_slice(nonce);
    out.extend(aead_seal(
        &k,
        nonce,
        &invite_aad(recipient_pub_user),
        token,
    )?);
    Ok(out)
}

/// Ouvre une invitation avec `priv_user` du destinataire.
pub fn open_invite(
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
    invite: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if invite.len() < 32 + AEAD_NONCE_LEN + 16 {
        return Err(CoreError::AeadFailure);
    }
    let (eph_pub, rest) = invite.split_at(32);
    let (nonce, ct) = rest.split_at(AEAD_NONCE_LEN);
    let eph_pub: [u8; 32] = eph_pub.try_into().map_err(|_| CoreError::AeadFailure)?;
    let own = StaticSecret::from(ed25519_priv_to_x25519(priv_user)?);
    let shared = own.diffie_hellman(&PublicKey::from(eph_pub));
    let k = kdf(shared.as_bytes(), labels::SHARE_INVITE, &[], &[&eph_pub])?;
    aead_open(&k, nonce, &invite_aad(pub_user), ct)
}
