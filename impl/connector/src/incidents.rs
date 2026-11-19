//! Incidents et compromissions — id `securite.incidents-compromissions`,
//! partie `connector` (Phase 5). Réf. spec :
//! docs/05-securite/incidents-compromissions.md.
//!
//! Compromission d'une clé User : nouvelle identité (index suivant si seule
//! une clé dérivée a fuité, nouvelle phrase mnémonique si la seed a fuité),
//! nouvelle `master_key`, **re-wrap plat** de toutes les clés maîtresses
//! historiques sous la nouvelle (`crypto.master-key-chain`) et réémission de
//! l'entrée DHT. Les blocs existants ne sont pas rechiffrés.

use std::collections::HashMap;

use p2p_storage_core::identity_derivation::{
    derive_identity_seed, derive_master_key, IdentityRole,
};
use p2p_storage_core::master_key_chain::{rewrap_chain_on_rotation, MasterKeyEntry};
use p2p_storage_core::CoreError;

/// Résultat d'une rotation d'identité User.
pub struct UserRotation {
    pub identity_index: u32,
    /// Graine Ed25519 de la nouvelle identité (`priv_user`).
    pub priv_user: [u8; 32],
    pub master_key: [u8; 32],
    pub master_key_version: u16,
    /// `master_key_chain` à publier (sous `K_self` de la nouvelle identité).
    pub chain: Vec<MasterKeyEntry>,
}

/// Rotation : `bip39_seed` est la seed courante (clé dérivée compromise) ou
/// la seed d'une **nouvelle** phrase mnémonique (seed compromise) ;
/// `historical` contient toutes les clés maîtresses encore détenues en clair
/// à cet instant (seule fenêtre où le re-wrap est possible).
pub fn rotate_user_identity(
    bip39_seed: &[u8; 64],
    new_identity_index: u32,
    new_master_key_version: u16,
    historical: &HashMap<u16, [u8; 32]>,
    protocol_header: &[u8; 2],
) -> Result<UserRotation, CoreError> {
    let priv_user = derive_identity_seed(bip39_seed, IdentityRole::User, new_identity_index)?;
    let master_key = derive_master_key(bip39_seed, new_master_key_version)?;
    let chain = rewrap_chain_on_rotation(
        protocol_header,
        historical,
        &master_key,
        new_master_key_version,
    )?;
    Ok(UserRotation {
        identity_index: new_identity_index,
        priv_user,
        master_key,
        master_key_version: new_master_key_version,
        chain,
    })
}
