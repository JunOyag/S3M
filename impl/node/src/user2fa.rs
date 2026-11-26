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
    /// Message de sécurité envoyé aux appareils (accordé à l'opération).
    pub fn notice(&self, hours: u64) -> String {
        let (op, e, la) = match self {
            PendingKind::Rotate { .. } => ("un changement d'identité a été demandé", "il", "annulez-le"),
            PendingKind::Purge { .. } => ("une purge de l'historique a été demandée", "elle", "annulez-la"),
            PendingKind::Remove2fa => ("un retrait du 2FA a été demandé", "il", "annulez-le"),
        };
        format!(
            "Sécurité : {op} pour votre compte ; {e} prendra effet dans {hours} h. Si ce n'est pas vous, {la} depuis « Mon compte » et activez le 2FA."
        )
    }

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

/// Opération différée ↔ `PendingUserOp` du snapshot.
pub fn to_snap(p: &Pending) -> s3m_protocol::snapshot::SnapPending {
    let mut s = s3m_protocol::snapshot::SnapPending { id: p.id, created_at: p.created_at, due_at: p.due_at, ..Default::default() };
    match &p.kind {
        PendingKind::Rotate { new_user, salt } => {
            s.new_user_id = hex::decode(new_user).unwrap_or_default();
            s.new_salt = hex::decode(salt).unwrap_or_default();
        }
        PendingKind::Purge { before } => {
            s.kind = 1;
            s.before = *before;
        }
        PendingKind::Remove2fa => s.kind = 2,
    }
    s
}

pub fn from_snap(s: &s3m_protocol::snapshot::SnapPending) -> Option<Pending> {
    let kind = match s.kind {
        0 => PendingKind::Rotate { new_user: hex::encode(&s.new_user_id), salt: hex::encode(&s.new_salt) },
        1 => PendingKind::Purge { before: s.before },
        2 => PendingKind::Remove2fa,
        _ => return None,
    };
    Some(Pending { id: s.id, kind, created_at: s.created_at, due_at: s.due_at })
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
