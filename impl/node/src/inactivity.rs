//! Durée d'inactivité des Utilisateurs
//! (`protocols.partenariat-automatique#inactivite`) : un Utilisateur dont
//! aucun Connecteur ne s'est adressé au Nœud depuis sa durée d'inactivité
//! est supprimé définitivement ; 0 jour : éternel.

use std::sync::Mutex;

use s3m_protocol::dispersal::Id;

use crate::chunk_store::Space;
use crate::dispersal_engine::{retire, DispersalState, UserDispersal};
use crate::exchange::NodeService;

/// Durée minimale (jours) ; 0 : éternel.
pub const MIN_DAYS: u64 = 180;
/// Durée par défaut des Utilisateurs rattachés automatiquement (jours).
pub const DEFAULT_DAYS: u64 = 180;
pub const DAY_S: u64 = 86_400;

/// Durée saisie : 0 (éternel) ou au moins [`MIN_DAYS`].
pub fn validate_days(d: u64) -> Result<u64, String> {
    if d == 0 || d >= MIN_DAYS {
        Ok(d)
    } else {
        Err(format!("durée d'inactivité : 0 (éternel) ou au moins {MIN_DAYS} jours"))
    }
}

/// Durée applicable à `u` : la sienne si l'opérateur l'a fixée, sinon celle
/// de la politique pour un Utilisateur rattaché automatiquement ; un
/// Utilisateur rattaché à la main est éternel.
pub fn effective_days(s: &NodeService, u: &Id) -> u64 {
    if let Some(d) = s.inactivity_days.get(u) {
        *d
    } else if s.auto_attached.contains(u) {
        s.attach_policy.inactivity_days
    } else {
        0
    }
}

/// Jours restants avant suppression (arrondis au-dessus) ; `None` : éternel.
pub fn remaining_days(s: &NodeService, u: &Id, now: u64) -> Option<u64> {
    let days = effective_days(s, u);
    if days == 0 {
        return None;
    }
    let last = s.last_active.get(u).copied().unwrap_or(now);
    let deadline = last.saturating_add(days.saturating_mul(DAY_S));
    Some(deadline.saturating_sub(now).div_ceil(DAY_S))
}

/// Temps d'arrêt du Nœud rendu à chaque Utilisateur : un Nœud éteint ne
/// supprime personne à son redémarrage.
pub fn credit_downtime(s: &mut NodeService, saved_at: u64, now: u64) {
    if saved_at == 0 || now <= saved_at {
        return;
    }
    let off = now - saved_at;
    for t in s.last_active.values_mut() {
        *t = t.saturating_add(off).min(now);
    }
}

/// Supprime définitivement les Utilisateurs inactifs : compte, blocs
/// locaux, descripteur de racine ; leurs fragments sont libérés chez les
/// partenaires (fragments à purger) et leur fiche de dispersion n'est plus
/// republiée. Rend les Utilisateurs supprimés.
pub fn purge_expired(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    now: u64,
) -> Vec<Id> {
    let expired: Vec<Id> = {
        let mut s = service.lock().unwrap();
        let users: Vec<Id> = s.users.keys().copied().collect();
        for u in &users {
            s.last_active.entry(*u).or_insert(now);
        }
        users
            .into_iter()
            .filter(|u| remaining_days(&s, u, now) == Some(0))
            .collect()
    };
    for u in &expired {
        let mut s = service.lock().unwrap();
        s.users.remove(u);
        s.store.remove_owner(Space::UserBlock, u);
        s.root_seals.remove(u);
        s.root_history.remove(u);
        s.undispersed.remove(u);
        s.root_since.remove(u);
        s.last_active.remove(u);
        s.inactivity_days.remove(u);
        s.auto_attached.remove(u);
        s.adopt_next_root.remove(u);
        s.restoring.remove(u);
        s.released.remove(u);
        s.last_user_ip.remove(u);
        s.user_labels.remove(u);
        s.reclaim.retain(|(x, _)| x != u);
        s.dispersal_queue.retain(|(x, _)| x != u);
        drop(s);
        let key = hex::encode(u);
        if let Some(d) = state.users.remove(&key) {
            let mut retired = d.retired;
            for rec in d.stripes.iter().chain(d.index.iter()) {
                retire(rec, &mut retired, now);
            }
            if !retired.is_empty() {
                state.users.insert(
                    key,
                    UserDispersal {
                        retired,
                        ..Default::default()
                    },
                );
            }
        }
    }
    // Restes d'Utilisateurs supprimés dont tous les fragments sont libérés.
    let s = service.lock().unwrap();
    state.users.retain(|k, d| {
        !d.retired.is_empty()
            || hex::decode(k)
                .ok()
                .and_then(|b| <Id>::try_from(b).ok())
                .is_some_and(|u| s.users.contains_key(&u))
    });
    expired
}
