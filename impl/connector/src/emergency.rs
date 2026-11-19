//! Espace de secours — id `protocols.espace-secours`, partie `connector`
//! (Phase 4). Réf. spec : docs/04-protocols/espace-secours.md.
//!
//! - Partenaires de secours : les `n_secours` Nœuds les plus proches de
//!   l'identité **Utilisateur** au sens XOR (pas du Nœud hébergeur, exclu).
//! - Dispersion sans erasure coding : blocs répartis à parts égales,
//!   charge maximale `Q_max / n_secours` par partenaire.
//! - Écriture de l'`EmergencyManifest` : lecture, **fusion sans perte**,
//!   publication avec `seq + 1` (les pairs rejettent `seq ≤` le leur).
//! - Réconciliation idempotente : une mutation n'est appliquée que si tous
//!   ses blocs sont présents sur le Nœud, et jamais deux fois.
//! - Dimensionnement : `E_secours = U_backup × Q_max / n_secours`.

use std::collections::BTreeSet;

use crate::fs::BlockHash;
use crate::write_queue::{Op, Queued, BLOCK_BYTES};

/// Nombre de partenaires de secours par défaut.
pub const DEFAULT_N_SECOURS: usize = 4;

/// Erreurs de l'espace de secours.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmergencyError {
    #[error("pas assez de partenaires candidats")]
    NotEnoughPartners,
    #[error("charge maximale par partenaire dépassée")]
    PartnerOverloaded,
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Sélectionne les `n` candidats les plus proches de `user_identity` au
/// sens XOR, hors Nœud hébergeur.
pub fn select_partners(
    user_identity: &[u8; 32],
    host_node: &[u8; 32],
    candidates: &[[u8; 32]],
    n: usize,
) -> Result<Vec<[u8; 32]>, EmergencyError> {
    let mut c: Vec<_> = candidates
        .iter()
        .filter(|c| *c != host_node)
        .copied()
        .collect();
    c.sort_by_key(|id| xor_distance(id, user_identity));
    c.dedup();
    if c.len() < n {
        return Err(EmergencyError::NotEnoughPartners);
    }
    c.truncate(n);
    Ok(c)
}

/// Répartit les blocs à parts égales (tour de rôle) entre `n` partenaires,
/// dans la limite de `q_max / n` octets chacun. Rend l'indice de partenaire
/// de chaque bloc.
pub fn assign_blocks(blocks: usize, n: usize, q_max: u64) -> Result<Vec<usize>, EmergencyError> {
    if n == 0 {
        return Err(EmergencyError::NotEnoughPartners);
    }
    let per_partner = blocks.div_ceil(n) as u64 * BLOCK_BYTES;
    if per_partner > q_max / n as u64 {
        return Err(EmergencyError::PartnerOverloaded);
    }
    Ok((0..blocks).map(|i| i % n).collect())
}

/// Contenu (déchiffré) d'un `EmergencyManifest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmergencyState {
    pub partners: BTreeSet<[u8; 32]>,
    /// `(block_hash, node_id du partenaire)`.
    pub blocks: BTreeSet<(BlockHash, [u8; 32])>,
    pub mutations: Vec<Queued>,
    pub base_fs_root_hash: BlockHash,
}

/// Lecture-fusion-écriture : fusionne `mine` dans l'entrée courante
/// (`current = (seq, état)` si elle existe) sans perdre aucun bloc,
/// partenaire ni mutation ; rend `(seq + 1, état fusionné)`.
pub fn merge(
    current: Option<(u64, &EmergencyState)>,
    mine: &EmergencyState,
) -> (u64, EmergencyState) {
    let (seq, mut out) = match current {
        Some((s, st)) => (s, st.clone()),
        None => (
            0,
            EmergencyState {
                base_fs_root_hash: mine.base_fs_root_hash,
                ..Default::default()
            },
        ),
    };
    out.partners.extend(mine.partners.iter().copied());
    out.blocks.extend(mine.blocks.iter().copied());
    for m in &mine.mutations {
        if !out.mutations.contains(m) {
            out.mutations.push(m.clone());
        }
    }
    out.mutations.sort_by_key(|m| m.timestamp);
    (seq + 1, out)
}

/// Réconciliation FS idempotente : mutations à appliquer, par timestamp
/// croissant, en sautant celles déjà appliquées (`applied`) et en refusant
/// toute mutation référençant un bloc absent du Nœud.
pub fn reconcile<'a>(
    state: &'a EmergencyState,
    applied: &dyn Fn(&Queued) -> bool,
    node_has_block: &dyn Fn(&BlockHash) -> bool,
) -> Vec<&'a Queued> {
    let mut v: Vec<_> = state
        .mutations
        .iter()
        .filter(|m| !applied(m))
        .filter(|m| match &m.op {
            Op::WriteBlock { block_hash } => node_has_block(block_hash),
            Op::UpdateEntry { entry } => node_has_block(&entry.first_block_hash),
            Op::DeleteEntry { .. } => true,
        })
        .collect();
    v.sort_by_key(|m| m.timestamp);
    v
}

/// `E_secours = U_backup × (Q_max / n_secours)` (octets).
pub fn emergency_capacity(u_backup: u64, q_max: u64, n_secours: u64) -> u64 {
    u_backup * (q_max / n_secours)
}
