//! Vérification d'intégrité à la lecture — id `protocols.integrite-lecture`,
//! component `connector` (Phase 4). Réf. spec :
//! docs/04-protocols/integrite-lecture.md.
//!
//! Chaque bloc reçu est vérifié (SHA-256 du chiffré = `block_hash` attendu).
//! En cas d'incohérence : nouvelle tentative auprès du Nœud, puis
//! reconstruction par la parité des partenaires (chemin de secours) ; si le
//! hash reconstruit est correct, la copie du Nœud est déclarée corrompue et
//! un incident lui est signalé ; sinon le bloc est irrécupérable et marqué
//! corrompu localement.

use std::collections::BTreeSet;

use p2p_storage_core::symmetric_suite::hash_sha256;

/// Hash d'un bloc chiffré.
pub type BlockHash = [u8; 32];

/// Accès aux blocs (le transport réel relève du protocole d'échange de
/// blocs, `impl/SPEC_GAPS.md`).
pub trait BlockSource {
    /// Chemin normal : bloc demandé directement au Nœud hébergeur.
    fn from_node(&self, hash: &BlockHash) -> Option<Vec<u8>>;
    /// Chemin de secours : reconstruction Reed-Solomon à partir de k
    /// fragments de parité chez les partenaires.
    fn reconstruct(&self, hash: &BlockHash) -> Option<Vec<u8>>;
}

/// Incident à signaler au Nœud (réparation, `securite.integrite-autoreparation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    pub block_hash: BlockHash,
}

/// Résultat d'une lecture vérifiée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    /// Bloc correct, servi par le Nœud.
    Ok(Vec<u8>),
    /// Copie du Nœud corrompue : version reconstruite servie, incident à
    /// signaler.
    Repaired { block: Vec<u8>, incident: Incident },
    /// Irrécupérable (hash toujours faux ou moins de k fragments).
    Irrecoverable,
}

fn valid(block: &Option<Vec<u8>>, hash: &BlockHash) -> bool {
    block.as_ref().is_some_and(|b| &hash_sha256(b) == hash)
}

/// Lecture vérifiée avec `retries` nouvelles tentatives auprès du Nœud.
pub fn fetch_verified(src: &dyn BlockSource, hash: &BlockHash, retries: usize) -> ReadOutcome {
    for _ in 0..=retries {
        let b = src.from_node(hash);
        if valid(&b, hash) {
            return ReadOutcome::Ok(b.unwrap());
        }
    }
    let r = src.reconstruct(hash);
    if valid(&r, hash) {
        return ReadOutcome::Repaired {
            block: r.unwrap(),
            incident: Incident { block_hash: *hash },
        };
    }
    ReadOutcome::Irrecoverable
}

/// État local : blocs marqués corrompus et incidents à signaler.
#[derive(Debug, Default)]
pub struct IntegrityLog {
    pub corrupted: BTreeSet<BlockHash>,
    pub pending_incidents: Vec<Incident>,
}

impl IntegrityLog {
    /// Lecture vérifiée qui journalise : incident en attente d'envoi au
    /// Nœud, ou bloc marqué corrompu (l'appelant affiche l'erreur critique
    /// en nommant le fichier concerné).
    pub fn read(
        &mut self,
        src: &dyn BlockSource,
        hash: &BlockHash,
        retries: usize,
    ) -> Option<Vec<u8>> {
        match fetch_verified(src, hash, retries) {
            ReadOutcome::Ok(b) => Some(b),
            ReadOutcome::Repaired { block, incident } => {
                self.pending_incidents.push(incident);
                Some(block)
            }
            ReadOutcome::Irrecoverable => {
                self.corrupted.insert(*hash);
                None
            }
        }
    }
}
