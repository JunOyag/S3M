//! File d'écriture hors-ligne — id `protocols.write-queue`, component
//! `connector` (Phase 4). Réf. spec : docs/04-protocols/write-queue.md,
//! schéma `fs.WriteQueue`.
//!
//! - Mise en file : blocs déjà chiffrés + mutations FS horodatées, sans
//!   modifier `fs_root_hash` ; budget `Q_max` (4 GiO par défaut).
//! - Rejeu **strictement par horodatage**, sans réordonnancement : une
//!   mutation n'est rejouée qu'après confirmation des précédentes ; tout
//!   `update_entry` exige que le premier bloc qu'il référence ait été écrit.
//! - Conflit : `base_fs_root_hash` ≠ `fs_root_hash` réel ; résolution
//!   « dernier écrit gagne » (`modified_at`), le perdant est conservé sous un
//!   nom suffixé.
//! - Vue pendant la panne : dernière mutation en file par chemin.

use std::collections::{HashMap, HashSet};

use flatbuffers::FlatBufferBuilder;
use s3m_protocol::fb::fs as fb;

use crate::fs::{BlockHash, Entry};

/// Budget par défaut (`Q_max`), partagé avec l'espace de secours.
pub const DEFAULT_Q_MAX: u64 = 4 * 1024 * 1024 * 1024;
/// Taille d'un bloc en file.
pub const BLOCK_BYTES: u64 = 65_536;

/// Mutation FS en attente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    WriteBlock {
        block_hash: BlockHash,
    },
    UpdateEntry {
        entry: Entry,
    },
    /// Chaîne complète à tombstoner.
    DeleteEntry {
        blocks_to_delete: Vec<BlockHash>,
    },
}

/// Mutation horodatée, rattachée à un chemin logique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub timestamp: u64,
    pub fs_path: String,
    pub op: Op,
}

/// Erreurs de la file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QueueError {
    #[error("budget Q_max atteint")]
    QueueFull,
    #[error("update_entry sans écriture préalable de son premier bloc")]
    OrphanPointer,
    #[error("format de file invalide : {0}")]
    Format(&'static str),
}

/// Destination du rejeu (le Nœud, via le protocole d'échange de blocs).
pub trait ReplaySink {
    /// Rend `true` si la mutation est confirmée par le Nœud.
    fn apply(&mut self, m: &Queued) -> bool;
}

/// File d'attente locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteQueue {
    pub base_fs_root_hash: BlockHash,
    pub mutations: Vec<Queued>,
    pub q_max: u64,
}

impl WriteQueue {
    pub fn new(base_fs_root_hash: BlockHash, q_max: u64) -> Self {
        Self {
            base_fs_root_hash,
            mutations: Vec::new(),
            q_max,
        }
    }

    /// Octets de blocs en file.
    pub fn used_bytes(&self) -> u64 {
        self.mutations
            .iter()
            .filter(|m| matches!(m.op, Op::WriteBlock { .. }))
            .count() as u64
            * BLOCK_BYTES
    }

    /// Met en file une mutation ; un `write_block` au-delà de `Q_max` est
    /// refusé ; un `update_entry` doit suivre l'écriture de son premier bloc.
    pub fn enqueue(&mut self, m: Queued) -> Result<(), QueueError> {
        match &m.op {
            Op::WriteBlock { .. } if self.used_bytes() + BLOCK_BYTES > self.q_max => {
                return Err(QueueError::QueueFull)
            }
            Op::UpdateEntry { entry } => {
                let written = self.mutations.iter().any(|q| {
                    matches!(q.op, Op::WriteBlock { block_hash } if block_hash == entry.first_block_hash)
                        && q.timestamp <= m.timestamp
                });
                if !written {
                    return Err(QueueError::OrphanPointer);
                }
            }
            _ => {}
        }
        self.mutations.push(m);
        Ok(())
    }

    /// Rejeu par horodatage croissant (ordre d'insertion à horodatage égal) ;
    /// s'arrête à la première mutation non confirmée, sans rien réordonner.
    /// Rend le nombre de mutations confirmées (retirées de la file).
    pub fn replay(&mut self, sink: &mut dyn ReplaySink) -> usize {
        self.mutations.sort_by_key(|m| m.timestamp);
        let done = self.mutations.iter().take_while(|m| sink.apply(m)).count();
        self.mutations.drain(..done);
        done
    }

    /// Divergence : un autre appareil a écrit entre-temps.
    pub fn has_conflict(&self, current_fs_root_hash: &BlockHash) -> bool {
        &self.base_fs_root_hash != current_fs_root_hash
    }

    /// Vue pendant la panne : dernier état connu en file pour `path`
    /// (`Some(None)` = supprimé, `None` = rien en file).
    pub fn view(&self, path: &str) -> Option<Option<&Entry>> {
        self.mutations
            .iter()
            .filter(|m| m.fs_path == path)
            .max_by_key(|m| m.timestamp)
            .and_then(|m| match &m.op {
                Op::UpdateEntry { entry } => Some(Some(entry)),
                Op::DeleteEntry { .. } => Some(None),
                Op::WriteBlock { .. } => None,
            })
    }

    /// Chemins dont au moins un bloc figure dans `rejected` (rejet pour
    /// dépassement de quota, `protocols.quota-sync`) : un fichier peut être
    /// partiellement accepté si sa chaîne est coupée.
    pub fn paths_affected_by(&self, rejected: &[BlockHash]) -> Vec<String> {
        let r: HashSet<_> = rejected.iter().collect();
        let mut out: Vec<String> = self
            .mutations
            .iter()
            .filter(|m| matches!(&m.op, Op::WriteBlock { block_hash } if r.contains(block_hash)))
            .map(|m| m.fs_path.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Sérialise en `fs.WriteQueue` (FlatBuffers).
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let items: Vec<_> = self
            .mutations
            .iter()
            .map(|m| {
                let path = fbb.create_string(&m.fs_path);
                let (op, hash, entry, del) = match &m.op {
                    Op::WriteBlock { block_hash } => (
                        "write_block",
                        Some(fbb.create_vector(block_hash)),
                        None,
                        None,
                    ),
                    Op::UpdateEntry { entry } => (
                        "update_entry",
                        None,
                        Some(encode_entry(&mut fbb, entry)),
                        None,
                    ),
                    Op::DeleteEntry { blocks_to_delete } => {
                        let flat: Vec<u8> = blocks_to_delete.iter().flatten().copied().collect();
                        ("delete_entry", None, None, Some(fbb.create_vector(&flat)))
                    }
                };
                let op = fbb.create_string(op);
                fb::QueuedMutation::create(
                    &mut fbb,
                    &fb::QueuedMutationArgs {
                        timestamp: m.timestamp,
                        op: Some(op),
                        fs_path: Some(path),
                        block_hash: hash,
                        entry,
                        blocks_to_delete: del,
                    },
                )
            })
            .collect();
        let muts = fbb.create_vector(&items);
        let base = fbb.create_vector(&self.base_fs_root_hash);
        let q = fb::WriteQueue::create(
            &mut fbb,
            &fb::WriteQueueArgs {
                base_fs_root_hash: Some(base),
                mutations: Some(muts),
            },
        );
        fb::finish_write_queue_buffer(&mut fbb, q);
        fbb.finished_data().to_vec()
    }

    /// Relit une file persistée.
    pub fn decode(bytes: &[u8], q_max: u64) -> Result<Self, QueueError> {
        let q = fb::root_as_write_queue(bytes).map_err(|_| QueueError::Format("WriteQueue"))?;
        let h32 = |v: Option<flatbuffers::Vector<'_, u8>>| -> Result<BlockHash, QueueError> {
            v.and_then(|v| v.bytes().try_into().ok())
                .ok_or(QueueError::Format("hash"))
        };
        let mut mutations = Vec::new();
        for m in q.mutations().iter().flatten() {
            let op = match m.op() {
                Some("write_block") => Op::WriteBlock {
                    block_hash: h32(m.block_hash())?,
                },
                Some("update_entry") => Op::UpdateEntry {
                    entry: decode_entry(m.entry().ok_or(QueueError::Format("entry"))?)?,
                },
                Some("delete_entry") => {
                    let flat = m.blocks_to_delete().map(|v| v.bytes()).unwrap_or_default();
                    if flat.len() % 32 != 0 {
                        return Err(QueueError::Format("blocks_to_delete"));
                    }
                    Op::DeleteEntry {
                        blocks_to_delete: flat.chunks(32).map(|c| c.try_into().unwrap()).collect(),
                    }
                }
                _ => return Err(QueueError::Format("op")),
            };
            mutations.push(Queued {
                timestamp: m.timestamp(),
                fs_path: m.fs_path().unwrap_or_default().to_owned(),
                op,
            });
        }
        Ok(Self {
            base_fs_root_hash: h32(q.base_fs_root_hash())?,
            mutations,
            q_max,
        })
    }
}

fn encode_entry<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    e: &Entry,
) -> flatbuffers::WIPOffset<fb::DirectoryEntry<'a>> {
    let name = fbb.create_string(&e.name);
    let mime = fbb.create_string(&e.mime_type);
    let h = fbb.create_vector(&e.first_block_hash);
    let s = fbb.create_vector(&e.encryption_salt);
    let a = fb::Attributes::create(
        fbb,
        &fb::AttributesArgs {
            permissions: e.permissions,
            created_at: e.created_at,
            modified_at: e.modified_at,
        },
    );
    fb::DirectoryEntry::create(
        fbb,
        &fb::DirectoryEntryArgs {
            name: Some(name),
            size_bytes: e.size_bytes,
            mime_type: Some(mime),
            first_block_hash: Some(h),
            attributes: Some(a),
            encryption_salt: Some(s),
            key_version: e.key_version,
            metadata: None,
        },
    )
}

fn decode_entry(e: fb::DirectoryEntry<'_>) -> Result<Entry, QueueError> {
    let a = e.attributes();
    Ok(Entry {
        name: e.name().unwrap_or_default().to_owned(),
        size_bytes: e.size_bytes(),
        mime_type: e.mime_type().unwrap_or_default().to_owned(),
        first_block_hash: e
            .first_block_hash()
            .and_then(|v| v.bytes().try_into().ok())
            .ok_or(QueueError::Format("first_block_hash"))?,
        encryption_salt: e
            .encryption_salt()
            .and_then(|v| v.bytes().try_into().ok())
            .ok_or(QueueError::Format("encryption_salt"))?,
        key_version: e.key_version(),
        permissions: a.map_or(0, |a| a.permissions()),
        created_at: a.map_or(0, |a| a.created_at()),
        modified_at: a.map_or(0, |a| a.modified_at()),
    })
}

/// Résolution « dernier écrit gagne » d'un conflit sur un même élément :
/// rend `(gagnant, perdant renommé)`. Le perdant est conservé hors
/// arborescence sous `<nom>.conflit-<modified_at>` — jamais écrasé.
pub fn resolve_conflict(local: &Entry, remote: &Entry) -> (Entry, Entry) {
    let (winner, loser) = if local.modified_at > remote.modified_at {
        (local, remote)
    } else {
        (remote, local)
    };
    let mut kept = loser.clone();
    kept.name = format!("{}.conflit-{}", loser.name, loser.modified_at);
    (winner.clone(), kept)
}

/// Index utilitaire : mutations par chemin (tests et dashboard).
pub fn by_path(q: &WriteQueue) -> HashMap<&str, usize> {
    let mut m = HashMap::new();
    for x in &q.mutations {
        *m.entry(x.fs_path.as_str()).or_insert(0) += 1;
    }
    m
}
