//! Volatilité et sur-redondance — id `protocols.volatilite-reparation`,
//! component `node` (Phase 4). Réf. spec :
//! docs/04-protocols/volatilite-reparation.md.
//!
//! - Analyse quotidienne de la disponibilité des partenaires qui hébergent
//!   les coef×k fragments de parité (les k blocs de données locaux ne sont
//!   jamais concernés).
//! - **Réparation préventive** quand les fragments disponibles descendent
//!   vers k : seuil retenu `k + 2`, comme le seuil de confirmation de
//!   `protocols.dispersion-transactionnelle` (la spec dit « vers le seuil
//!   minimal k » sans valeur) ; les fragments manquants sont régénérés depuis
//!   la copie locale des k blocs (`erasure::encode_parity`) et réémis vers de
//!   nouveaux partenaires distincts.
//! - **Résolution du surplus** : si un partenaire réapparaît avant la purge,
//!   les copies temporaires réémises sont supprimées.
//! - Purge après 6 mois hors ligne (`securite.incidents-compromissions`).
//! - La fraude avérée (PoS) déclenche une réparation immédiate, hors cycle
//!   (`securite.blacklist-fraude`).

use std::collections::BTreeSet;

/// Période de l'analyse.
pub const ANALYSIS_PERIOD_S: u64 = 86_400;
/// Purge d'un partenaire après 6 mois sans réponse.
pub const PURGE_AFTER_S: u64 = 15_552_000;

/// Hébergement d'un fragment de parité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    /// Indice du fragment dans la stripe (k..N-1).
    pub index: usize,
    pub partner: u16,
    /// Dernière réponse (PoS réussie) du partenaire.
    pub last_seen: u64,
}

/// Décision de l'analyse pour une stripe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Fragments à régénérer et réémettre (indisponibles), si réparation.
    pub repair: Vec<usize>,
    /// Partenaires hors ligne depuis plus de 6 mois : à purger.
    pub purge: Vec<u16>,
}

/// Analyse d'une stripe : un partenaire est « disponible » s'il a répondu
/// depuis moins de `available_window_s`.
pub fn analyze(holders: &[Holder], k: usize, now: u64, available_window_s: u64) -> Plan {
    let available = |h: &Holder| now.saturating_sub(h.last_seen) <= available_window_s;
    let up = holders.iter().filter(|h| available(h)).count();
    let mut plan = Plan::default();
    if up < k + 2 {
        plan.repair = holders
            .iter()
            .filter(|h| !available(h))
            .map(|h| h.index)
            .collect();
    }
    plan.purge = holders
        .iter()
        .filter(|h| now.saturating_sub(h.last_seen) > PURGE_AFTER_S)
        .map(|h| h.partner)
        .collect();
    plan
}

/// Choisit, pour chaque fragment à réparer, un nouveau partenaire distinct
/// de tous ceux qui hébergent déjà un fragment de la stripe.
pub fn choose_new_partners(
    holders: &[Holder],
    repair: &[usize],
    candidates: &[u16],
) -> Option<Vec<(usize, u16)>> {
    let taken: BTreeSet<u16> = holders.iter().map(|h| h.partner).collect();
    let free: Vec<u16> = candidates
        .iter()
        .copied()
        .filter(|c| !taken.contains(c))
        .collect();
    if free.len() < repair.len() {
        return None;
    }
    Some(repair.iter().copied().zip(free).collect())
}

/// Copie temporaire réémise pendant une absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporaryCopy {
    pub index: usize,
    pub original_partner: u16,
    pub temporary_partner: u16,
}

/// Résolution du surplus : copies temporaires à supprimer parce que leur
/// partenaire d'origine est revenu (et n'a pas été purgé).
pub fn surplus_to_delete(
    temps: &[TemporaryCopy],
    back_online: &BTreeSet<u16>,
) -> Vec<TemporaryCopy> {
    temps
        .iter()
        .filter(|t| back_online.contains(&t.original_partner))
        .copied()
        .collect()
}
