//! 2FA des Utilisateurs et opérations différées
//! (`securite.incidents-compromissions#2fa`) : changer d'identité, purger
//! l'historique ou retirer le 2FA exigent un code TOTP (ou de secours) ;
//! sans 2FA, ces opérations sont différées (72 h, 7 jours pour le retrait
//! du 2FA) et annulables par tout appareil de l'identité, qui en est
//! prévenu.

use s3m_core::symmetric_suite::hash_sha256;
use serde::{Deserialize, Serialize};

use crate::admin::{hotp, TOTP_STEP};

/// Délai d'une opération sensible sans 2FA (s).
pub const DEFER_S: u64 = 72 * 3_600;
/// Délai du retrait du 2FA sans code (s).
pub const REMOVE_DEFER_S: u64 = 7 * 86_400;
/// Codes de secours au plus.
pub const MAX_RECOVERY: usize = 16;

/// 2FA d'un Utilisateur : secret TOTP, empreintes des codes de secours
/// restants, dernier pas TOTP accepté (anti-rejeu).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFa {
    pub secret: String,
    pub recovery: Vec<String>,
    #[serde(default)]
    pub last_step: u64,
}

/// Opération différée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    Rotate { new_user: String, salt: String },
    Purge { before: u64 },
    Remove2fa,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub id: u64,
    pub kind: PendingKind,
    pub created_at: u64,
    pub due_at: u64,
}

impl PendingKind {
    pub fn label(&self) -> &'static str {
        match self {
            PendingKind::Rotate { .. } => "changement d'identité",
            PendingKind::Purge { .. } => "purge de l'historique",
            PendingKind::Remove2fa => "retrait du 2FA",
        }
    }
}

/// Empreinte d'un code de secours (sans espaces ni tirets, en majuscules).
pub fn recovery_hash(code: &str) -> [u8; 32] {
    let norm: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect();
    hash_sha256(norm.as_bytes())
}

/// Code TOTP valide pour `secret` (pas courant ± 1, postérieur à
/// `last_step`) : rend le pas accepté.
pub fn totp_step(secret: &[u8], code: &str, last_step: u64, now: u64) -> Option<u64> {
    let c: u32 = code.trim().parse().ok().filter(|_| code.trim().len() == 6)?;
    let step = now / TOTP_STEP;
    [step.saturating_sub(1), step, step + 1]
        .into_iter()
        .find(|s| *s > last_step && hotp(secret, *s, 6) == c)
}

impl TwoFa {
    /// Vérifie un code TOTP ou de secours (consommé).
    pub fn verify(&mut self, code: &str, now: u64) -> bool {
        let Ok(secret) = hex::decode(&self.secret) else {
            return false;
        };
        if let Some(s) = totp_step(&secret, code, self.last_step, now) {
            self.last_step = s;
            return true;
        }
        let h = hex::encode(recovery_hash(code));
        if let Some(i) = self.recovery.iter().position(|r| *r == h) {
            self.recovery.remove(i);
            return true;
        }
        false
    }
}
