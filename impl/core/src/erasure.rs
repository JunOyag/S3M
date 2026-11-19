//! Codage d'effacement — id `protocols.erasure-coding`, component `core`
//! (Phase 3). Réf. spec : docs/04-protocols/erasure-coding.md.
//!
//! - `N = k + coef×k` blocs par stripe (coef = 3 par défaut) ; la donnée se
//!   reconstruit à partir de **n'importe quels** k blocs sur N, y compris k
//!   blocs de parité seuls. Reed-Solomon GF(2⁸) de la crate
//!   `reed-solomon-erasure` — liée, jamais réimplémentée (impl/TECH_STACK.md).
//! - La parité se calcule sur les blocs **chiffrés** (opération linéaire) :
//!   le Nœud n'a jamais besoin de `K_block`.
//! - Les coef×k blocs de parité vont chez coef×k partenaires **distincts**.
//! - Assemblage progressif : paquets de k blocs, complétés par des blocs de
//!   padding (zéros) après `duree_max_idle_seconds` sans k blocs.

use std::collections::HashSet;

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::error::CoreError;
use crate::k_block::BLOCK_SIZE;

/// Coefficient de parité par défaut (N = 4k).
pub const DEFAULT_COEF: usize = 3;
/// Limite du corps GF(2⁸) : `k + coef×k ≤ 256`.
pub const MAX_SHARDS: usize = 256;

fn codec(k: usize, coef: usize) -> Result<ReedSolomon, CoreError> {
    let m = k.checked_mul(coef).ok_or(CoreError::ErasureParameters)?;
    if k == 0 || coef == 0 || k + m > MAX_SHARDS {
        return Err(CoreError::ErasureParameters);
    }
    ReedSolomon::new(k, m).map_err(|_| CoreError::ErasureParameters)
}

/// Calcule les `coef×k` blocs de parité de `k` blocs de données de même
/// taille (65 536 o dans le protocole). Ordre : indices k..N-1.
pub fn encode_parity(data: &[&[u8]], coef: usize) -> Result<Vec<Vec<u8>>, CoreError> {
    let k = data.len();
    let rs = codec(k, coef)?;
    let len = data.first().map(|d| d.len()).unwrap_or(0);
    if len == 0 || data.iter().any(|d| d.len() != len) {
        return Err(CoreError::ErasureShardSize);
    }
    let mut parity = vec![vec![0u8; len]; k * coef];
    rs.encode_sep(data, &mut parity)
        .map_err(|_| CoreError::ErasureShardSize)?;
    Ok(parity)
}

/// Reconstruit les `k` blocs de données à partir de `shards` (N entrées,
/// indices 0..k-1 données, k..N-1 parité ; `None` = bloc indisponible).
/// Échoue si moins de k blocs sont présents.
pub fn reconstruct_data(
    shards: Vec<Option<Vec<u8>>>,
    k: usize,
    coef: usize,
) -> Result<Vec<Vec<u8>>, CoreError> {
    let rs = codec(k, coef)?;
    if shards.len() != k + k * coef {
        return Err(CoreError::ErasureParameters);
    }
    if shards.iter().filter(|s| s.is_some()).count() < k {
        return Err(CoreError::ErasureNotEnoughShards);
    }
    let mut shards = shards;
    rs.reconstruct_data(&mut shards)
        .map_err(|_| CoreError::ErasureShardSize)?;
    Ok(shards
        .into_iter()
        .take(k)
        .map(|s| s.expect("reconstruit"))
        .collect())
}

/// Vérifie la dispersion multi-partenaires : un partenaire par bloc de
/// parité, jamais deux blocs de la même stripe chez le même partenaire.
pub fn check_parity_placement(partner_ids: &[u16], k: usize, coef: usize) -> Result<(), CoreError> {
    if partner_ids.len() != k * coef {
        return Err(CoreError::ErasureParameters);
    }
    let distinct: HashSet<_> = partner_ids.iter().collect();
    if distinct.len() != partner_ids.len() {
        return Err(CoreError::ErasureDuplicatePartner);
    }
    Ok(())
}

/// Bloc de padding (zéros, `is_padding = true`).
pub fn padding_block() -> Vec<u8> {
    vec![0u8; BLOCK_SIZE]
}

/// Paquet de k blocs prêt pour le calcul de parité.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledStripe<T> {
    /// Blocs réels, dans l'ordre d'arrivée.
    pub blocks: Vec<T>,
    /// Nombre de blocs de padding qui complètent le paquet jusqu'à k.
    pub padding: usize,
}

/// Assemblage progressif (§ Assemblage progressif des stripes) : regroupe
/// les blocs reçus séquentiellement par paquets de k ; un paquet incomplet
/// est émis avec padding après `idle_timeout_s` sans nouveau bloc.
#[derive(Debug)]
pub struct StripeAssembler<T> {
    k: usize,
    idle_timeout_s: u64,
    pending: Vec<T>,
    last_arrival: u64,
}

impl<T> StripeAssembler<T> {
    pub fn new(k: usize, idle_timeout_s: u64) -> Result<Self, CoreError> {
        if k == 0 {
            return Err(CoreError::ErasureParameters);
        }
        Ok(Self {
            k,
            idle_timeout_s,
            pending: Vec::new(),
            last_arrival: 0,
        })
    }

    /// Ajoute un bloc reçu à l'instant `now` ; rend un paquet complet de k.
    pub fn push(&mut self, block: T, now: u64) -> Option<AssembledStripe<T>> {
        self.pending.push(block);
        self.last_arrival = now;
        (self.pending.len() == self.k).then(|| AssembledStripe {
            blocks: std::mem::take(&mut self.pending),
            padding: 0,
        })
    }

    /// À appeler périodiquement : rend le paquet incomplet, complété de
    /// padding, si aucun bloc n'est arrivé depuis plus de `idle_timeout_s`.
    pub fn poll(&mut self, now: u64) -> Option<AssembledStripe<T>> {
        if self.pending.is_empty() || now.saturating_sub(self.last_arrival) <= self.idle_timeout_s {
            return None;
        }
        let blocks = std::mem::take(&mut self.pending);
        let padding = self.k - blocks.len();
        Some(AssembledStripe { blocks, padding })
    }

    /// Blocs en attente.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}
