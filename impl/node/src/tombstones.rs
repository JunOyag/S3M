//! Suppression bilatérale (tombstones 1:1) — id `protocols.tombstones`,
//! component `node` (Phase 3). Réf. spec : docs/04-protocols/tombstones.md.
//!
//! - Le Nœud qui supprime ses blocs de parité chez un partenaire lui envoie
//!   un **avis signé** (preuve d'identité + timestamp) — suppression
//!   légitime, notifiée, pas une sanction.
//! - Signature Ed25519 sur `L("s3m/sig/tombstone/v1") ‖ u64be(ts) ‖
//!   hash₁ ‖ … ‖ hashₙ` (même séparation de contexte que les entrées DHT).
//! - Anti-rejeu : le timestamp d'un avis doit être strictement supérieur à
//!   celui du dernier avis appliqué pour ce partenaire.
//! - Libération bilatérale équivalente : les deux comptes
//!   (`node.PartnerAccount`) sont décrémentés du même nombre de blocs
//!   effectivement libérés ; côté disque, le slot est libéré
//!   (`PhysicalStore::remove_block`).

use s3m_protocol::dht::{sign, verify_signature, DhtError};

/// Libellé de signature des avis de suppression.
pub const SIG_LABEL_TOMBSTONE: &str = "s3m/sig/tombstone/v1";

/// Avis de suppression adressé à un partenaire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneNotice {
    pub timestamp: u64,
    pub block_hashes: Vec<[u8; 32]>,
    pub signature: [u8; 64],
}

fn signed_payload(timestamp: u64, hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut p = timestamp.to_be_bytes().to_vec();
    for h in hashes {
        p.extend_from_slice(h);
    }
    p
}

impl TombstoneNotice {
    /// Construit et signe un avis avec la graine `priv_node` de l'émetteur.
    pub fn sign(node_seed: &[u8; 32], timestamp: u64, block_hashes: Vec<[u8; 32]>) -> Self {
        let signature = sign(
            node_seed,
            SIG_LABEL_TOMBSTONE,
            &signed_payload(timestamp, &block_hashes),
        );
        Self {
            timestamp,
            block_hashes,
            signature,
        }
    }

    /// Vérifie la preuve d'identité de l'émetteur (`pub_node`).
    pub fn verify(&self, sender_pub_node: &[u8; 32]) -> Result<(), DhtError> {
        verify_signature(
            sender_pub_node,
            SIG_LABEL_TOMBSTONE,
            &signed_payload(self.timestamp, &self.block_hashes),
            &self.signature,
        )
    }
}

/// Solde de troc avec un partenaire (`node.PartnerAccount`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PartnerLedger {
    /// Blocs de ce Nœud stockés chez le partenaire.
    pub hosted_for_partner: u64,
    /// Blocs du partenaire stockés par ce Nœud.
    pub hosted_by_partner: u64,
    /// Timestamp du dernier avis de suppression reçu et appliqué.
    pub last_tombstone_at: u64,
}

/// Erreurs d'application d'un avis.
#[derive(Debug, thiserror::Error)]
pub enum TombstoneError {
    #[error(transparent)]
    Signature(#[from] DhtError),
    #[error("avis rejoué ou antérieur au dernier avis appliqué")]
    Replay,
}

/// Côté **récepteur** : vérifie l'avis du partenaire, libère les blocs qu'il
/// héberge effectivement pour lui (`remove` rend vrai si le bloc existait)
/// et décrémente `hosted_by_partner` d'autant. Rend le nombre libéré.
pub fn apply_received(
    ledger: &mut PartnerLedger,
    sender_pub_node: &[u8; 32],
    notice: &TombstoneNotice,
    remove: &mut dyn FnMut(&[u8; 32]) -> bool,
) -> Result<u64, TombstoneError> {
    notice.verify(sender_pub_node)?;
    if notice.timestamp <= ledger.last_tombstone_at {
        return Err(TombstoneError::Replay);
    }
    let freed = notice.block_hashes.iter().filter(|h| remove(h)).count() as u64;
    ledger.hosted_by_partner = ledger.hosted_by_partner.saturating_sub(freed);
    ledger.last_tombstone_at = notice.timestamp;
    Ok(freed)
}

/// Côté **émetteur** : à l'accusé de réception du partenaire (nombre de
/// blocs effectivement libérés), décrémente `hosted_for_partner` d'autant —
/// les deux comptes restent équivalents.
pub fn apply_acknowledged(ledger: &mut PartnerLedger, freed: u64) {
    ledger.hosted_for_partner = ledger.hosted_for_partner.saturating_sub(freed);
}
