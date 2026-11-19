//! Arbre d'index adaptatif — id `protocols.index-adaptatif` (Phase 3,
//! partie commune Nœud/Connecteur). Réf. spec :
//! docs/04-protocols/index-adaptatif.md, docs/03-crypto/k-dispersal.md.
//!
//! - Facteur de branchement **mesuré** sur les types générés : nombre de
//!   `Stripe` complètes (k = 4, coef = 3 → N = 16 `BlockEntry`) tenant dans
//!   un `IndexNode` sérialisé de 65 506 o.
//! - La profondeur ne grandit que si nécessaire : jusqu'à F stripes, la
//!   racine les porte directement ; au-delà, un niveau d'indirection est
//!   ajouté, et ainsi de suite.
//! - Chaque `IndexNode` émis en bloc est chiffré sous
//!   `K_dispersal_block = KDF(K_dispersal_content, "dispersal-block", sel)`,
//!   sel de 16 o neuf par émission, au format de bloc de `crypto.k-block`.

use flatbuffers::FlatBufferBuilder;
use p2p_storage_core::k_block::{open_block, seal_block, BLOCK_HEADER_LEN, BLOCK_PLAINTEXT_LEN};
use p2p_storage_core::k_dispersal::derive_k_dispersal_block;
use p2p_storage_core::CoreError;

use crate::fb::dispersal::{
    BlockEntry, BlockEntryArgs, IndexNode, IndexNodeArgs, Stripe, StripeArgs,
};

/// Facteur de branchement mesuré (k = 4, coef = 3) — voir
/// [`measure_branching_factor`] et `tests/index.rs`.
pub const BRANCHING_FACTOR: usize = 68;

/// Sérialise un `IndexNode` feuille de `stripes` stripes complètes de
/// `n_blocks` `BlockEntry` (hash 32 o, `stripe_id` 32 o) — mesure.
pub fn serialized_leaf_len(stripes: usize, n_blocks: usize) -> usize {
    let mut fbb = FlatBufferBuilder::with_capacity(BLOCK_PLAINTEXT_LEN);
    let items: Vec<_> = (0..stripes)
        .map(|_| {
            let entries: Vec<_> = (0..n_blocks)
                .map(|i| {
                    let h = fbb.create_vector(&[0xFFu8; 32]);
                    BlockEntry::create(
                        &mut fbb,
                        &BlockEntryArgs {
                            block_hash: Some(h),
                            block_index: i as u16,
                            partner_id: u16::MAX,
                            key_version: u16::MAX,
                            is_padding: false,
                        },
                    )
                })
                .collect();
            let blocks = fbb.create_vector(&entries);
            let id = fbb.create_vector(&[0xFFu8; 32]);
            Stripe::create(
                &mut fbb,
                &StripeArgs {
                    stripe_id: Some(id),
                    k: 4,
                    m: 12,
                    blocks: Some(blocks),
                    encryption_salt: None,
                },
            )
        })
        .collect();
    let stripes = fbb.create_vector(&items);
    let node = IndexNode::create(
        &mut fbb,
        &IndexNodeArgs {
            is_leaf: true,
            stripes: Some(stripes),
            children: None,
        },
    );
    fbb.finish_minimal(node);
    fbb.finished_data().len()
}

/// Plus grand nombre de stripes de `n_blocks` blocs par `IndexNode` qui
/// tient dans le clair d'un bloc.
pub fn measure_branching_factor(n_blocks: usize) -> usize {
    (1..)
        .take_while(|&f| serialized_leaf_len(f, n_blocks) <= BLOCK_PLAINTEXT_LEN)
        .last()
        .unwrap_or(0)
}

/// Forme de l'arbre pour `stripes` stripes et un facteur `f` : nombre de
/// nœuds par niveau, des feuilles vers la racine (dernier élément = 1).
/// Profondeur minimale : un seul niveau (la racine) tant que `stripes ≤ f`.
pub fn tree_shape(stripes: usize, f: usize) -> Vec<usize> {
    assert!(f >= 2, "facteur de branchement ≥ 2");
    let mut levels = vec![stripes.div_ceil(f).max(1)];
    while *levels.last().unwrap() > 1 {
        let n = levels.last().unwrap().div_ceil(f);
        levels.push(n);
    }
    levels
}

/// Répartit `items` en groupes d'au plus `f`, niveau par niveau, jusqu'à
/// une racine unique : rend les groupes de chaque niveau (indices dans le
/// niveau inférieur), feuilles d'abord.
pub fn group_levels(items: usize, f: usize) -> Vec<Vec<std::ops::Range<usize>>> {
    let mut out = Vec::new();
    let mut n = items.max(1);
    loop {
        let groups: Vec<_> = (0..n).step_by(f).map(|s| s..(s + f).min(n)).collect();
        let len = groups.len();
        out.push(groups);
        if len == 1 {
            return out;
        }
        n = len;
    }
}

/// Chiffre un `IndexNode` sérialisé en bloc sous
/// `K_dispersal_block(sel)` (format de `crypto.k-block`).
pub fn seal_index_node(
    k_dispersal_content: &[u8; 32],
    salt: &[u8; 16],
    header: &[u8; BLOCK_HEADER_LEN],
    nonce: &[u8; 12],
    node_bytes: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let k = derive_k_dispersal_block(k_dispersal_content, salt)?;
    seal_block(&k, header, nonce, node_bytes)
}

/// Déchiffre un bloc d'index (clair complet, padding compris — le buffer
/// FlatBuffers se lit depuis le début).
pub fn open_index_node(
    k_dispersal_content: &[u8; 32],
    salt: &[u8; 16],
    header: &[u8; BLOCK_HEADER_LEN],
    frame: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let k = derive_k_dispersal_block(k_dispersal_content, salt)?;
    open_block(&k, header, frame)
}
