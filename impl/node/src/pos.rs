//! Challenges de possession (PoS) et QoS — id `securite.pos-challenges`,
//! component `node` (Phase 5). Réf. spec : docs/05-securite/pos-challenges.md.
//!
//! - Challenge : `SHA-256(fragment ‖ nonce)` ; la référence est recalculée
//!   **en local** (Reed-Solomon sur la copie locale des k blocs chiffrés),
//!   sans appel à un tiers ; seuls les partenaires (parité) sont challengés.
//! - Délai : `max(1 s, 2 × latence moyenne + 500 ms)`, latence moyenne
//!   glissante (EWMA α = 1/8) — valeurs retenues le 2026-11-19, la spec
//!   disant seulement « selon la latence moyenne mesurée ».
//! - Toute demande de bloc complet vaut challenge : contenu incorrect =
//!   échec PoS (fraude), distinct d'une absence de réponse (timeout).
//! - QoS : le bridage de bande passante ne s'applique jamais aux messages PoS.

use p2p_storage_core::erasure::encode_parity;
use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_core::CoreError;

/// Réponse attendue à un challenge : `SHA-256(fragment ‖ nonce)`.
pub fn challenge_response(fragment: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    hash_sha256(&[fragment, &nonce[..]].concat())
}

/// Référence locale du fragment de parité `parity_index` (0-based parmi les
/// coef×k) d'une stripe, recalculée depuis les k blocs de données locaux.
pub fn expected_response(
    local_data: &[&[u8]],
    coef: usize,
    parity_index: usize,
    nonce: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    let parity = encode_parity(local_data, coef)?;
    let fragment = parity
        .get(parity_index)
        .ok_or(CoreError::ErasureParameters)?;
    Ok(challenge_response(fragment, nonce))
}

/// Issue d'un challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Passed,
    /// Absence de réponse dans le délai : parcours de volatilité.
    Timeout,
    /// Réponse incorrecte : fraude ou corruption avérée → rupture immédiate.
    Fraud,
}

/// Évalue une réponse à un petit challenge (`None` = pas de réponse à temps).
pub fn judge(expected: &[u8; 32], answer: Option<&[u8; 32]>) -> Verdict {
    match answer {
        None => Verdict::Timeout,
        Some(a) if a == expected => Verdict::Passed,
        Some(_) => Verdict::Fraud,
    }
}

/// Évalue une demande de bloc complet : même règle que le challenge.
pub fn judge_full_block(expected_fragment: &[u8], returned: Option<&[u8]>) -> Verdict {
    match returned {
        None => Verdict::Timeout,
        Some(b) if b == expected_fragment => Verdict::Passed,
        Some(_) => Verdict::Fraud,
    }
}

/// Latence moyenne glissante d'un partenaire et délai qui en découle.
#[derive(Debug, Clone, Copy, Default)]
pub struct LatencyTracker {
    mean_ms: Option<u64>,
}

impl LatencyTracker {
    pub fn record(&mut self, rtt_ms: u64) {
        self.mean_ms = Some(match self.mean_ms {
            None => rtt_ms,
            Some(m) => (7 * m + rtt_ms) / 8,
        });
    }

    pub fn mean_ms(&self) -> Option<u64> {
        self.mean_ms
    }

    /// `max(1 s, 2 × moyenne + 500 ms)` ; 1 s sans mesure.
    pub fn timeout_ms(&self) -> u64 {
        self.mean_ms.map_or(1_000, |m| (2 * m + 500).max(1_000))
    }
}

/// Classe de trafic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traffic {
    Pos,
    BlockTransfer,
}

/// Bridage de bande passante (seau à jetons) — jamais appliqué au PoS.
#[derive(Debug, Clone)]
pub struct Throttle {
    capacity: u64,
    tokens: u64,
    rate_per_s: u64,
    last: u64,
}

impl Throttle {
    pub fn new(bytes_per_s: u64) -> Self {
        Self {
            capacity: bytes_per_s,
            tokens: bytes_per_s,
            rate_per_s: bytes_per_s,
            last: 0,
        }
    }

    /// Autorise-t-on l'envoi de `bytes` à l'instant `now_s` ?
    pub fn allow(&mut self, class: Traffic, bytes: u64, now_s: u64) -> bool {
        if class == Traffic::Pos {
            return true;
        }
        let refill = now_s.saturating_sub(self.last) * self.rate_per_s;
        self.tokens = (self.tokens + refill).min(self.capacity);
        self.last = now_s;
        if bytes <= self.tokens {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}
