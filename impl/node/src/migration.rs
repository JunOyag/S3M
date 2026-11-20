//! Migration vers un nouveau Nœud — id `protocols.migration-noeud`, partie
//! `node` (Phase 4). Réf. spec : docs/04-protocols/migration-noeud.md.
//!
//! Le nouveau Nœud reçoit du Connecteur `dispersal_root_hash`, les
//! partenaires de la racine, son sel et `K_dispersal_content` ; il
//! déchiffre l'arbre d'index nœud par nœud, reconstruit chaque stripe à
//! partir de k fragments de parité, puis recalcule et disperse une nouvelle
//! parité vers **ses** partenaires (`protocols.dispersion-transactionnelle`)
//! et publie une nouvelle entrée `DispersalManifest` sous sa propre
//! `sig_pub_dispersal` (dérivée du **nouveau** `K_attach`). L'ancienne
//! entrée devient orpheline et expire (6 mois).

use s3m_core::erasure::{encode_parity, reconstruct_data};
use s3m_core::k_attach::{derive_k_attach_as_node, derive_sig_priv_dispersal};
use s3m_core::CoreError;

/// `(k blocs de données, nouvelle parité)`.
pub type RebuiltStripe = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Reconstruit les k blocs de données d'une stripe depuis les fragments de
/// parité récupérés chez les anciens partenaires (`parity[i]` = fragment
/// d'indice k+i, `None` si indisponible), puis calcule la nouvelle parité à
/// disperser.
pub fn rebuild_stripe(
    parity: Vec<Option<Vec<u8>>>,
    k: usize,
    coef: usize,
) -> Result<RebuiltStripe, CoreError> {
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; k];
    shards.extend(parity);
    let data = reconstruct_data(shards, k, coef)?;
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let new_parity = encode_parity(&refs, coef)?;
    Ok((data, new_parity))
}

/// Graine de la nouvelle `sig_priv_dispersal` : dérivée du **nouveau**
/// `K_attach` (nouvel attachement, nouveau sel) — sans lien avec l'ancienne.
pub fn new_sig_priv_dispersal(
    priv_node: &[u8; 32],
    pub_user: &[u8; 32],
    new_salt: &[u8],
) -> Result<[u8; 32], CoreError> {
    derive_sig_priv_dispersal(&derive_k_attach_as_node(priv_node, pub_user, new_salt)?)
}
