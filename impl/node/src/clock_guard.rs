//! Garde-fou d'horloge (`deploiement.packaging#horloge`) : un saut de
//! l'heure système (ou un très long arrêt) gèle toutes les suppressions
//! liées au temps jusqu'à confirmation de l'opérateur.

use serde::{Deserialize, Serialize};

/// Écart toléré entre l'heure système et le temps écoulé (s).
pub const MAX_JUMP_S: i64 = 86_400;
/// Arrêt au-delà duquel l'heure est à confirmer au redémarrage (s).
pub const LONG_STOP_S: u64 = 7 * 86_400;

/// Gel en cours : instant de détection, écart (s) et cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freeze {
    pub at: u64,
    pub jump_s: i64,
    pub reason: String,
}

/// Écart entre l'heure système `wall` et l'heure attendue
/// `last_wall + elapsed` ; `Some` au-delà de [`MAX_JUMP_S`].
pub fn jump(last_wall: u64, elapsed_s: u64, wall: u64) -> Option<i64> {
    let j = wall as i64 - (last_wall as i64 + elapsed_s as i64);
    (j.abs() > MAX_JUMP_S).then_some(j)
}

/// Texte de l'alerte.
pub fn describe(f: &Freeze) -> String {
    let days = f.jump_s.abs() as f64 / 86_400.0;
    format!(
        "{} ({days:.1} jour(s)) : suppressions liées au temps suspendues (utilisateurs inactifs, versions, partenaires silencieux, dépôts de secours). Vérifiez l'heure de la machine puis confirmez.",
        f.reason
    )
}
