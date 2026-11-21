//! Espace de secours — id `protocols.espace-secours`, partie commune
//! Nœud/Connecteur, sans I/O. Réf. spec : docs/04-protocols/espace-secours.md.
//!
//! - Clés dérivées de `K_attach` : `K_emergency_content`,
//!   `sig_priv_emergency` (et sa clé publique `emergency_pub`).
//! - Modèle de l'`EmergencyManifest`, codage FlatBuffers, entrée DHT
//!   chiffrée et signée (`EmergencyEntry`, séquence monotone).
//! - Fusion sans perte de l'entrée courante et choix du changement de
//!   racine à réconcilier.

use ed25519_dalek::SigningKey;
use flatbuffers::FlatBufferBuilder;
use s3m_core::labels::{EMERGENCY_CONTENT, EMERGENCY_SIGNING};
use s3m_core::symmetric_suite::kdf;

use crate::dht::{build_envelope, open_blob, seal_blob, sign, DhtError, EntryKind};
use crate::fb::dht as fbd;
use crate::fb::emergency as fbe;
use crate::fb::fs as fbf;

pub type Id = [u8; 32];

/// Chemin et opération d'un changement de racine.
const ROOT_PATH: &str = "/";
const OP_UPDATE_ENTRY: &str = "update_entry";
const DIRECTORY_MIME: &str = "inode/directory";

/// Clés de secours d'un Utilisateur (communes à tous ses Connecteurs et
/// connues de son Nœud).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyKeys {
    /// `K_emergency_content = KDF(K_attach, "emergency-content")`.
    pub content: Id,
    /// `sig_priv_emergency = KDF(K_attach, "emergency-signing")`.
    pub sig_priv: Id,
    /// `emergency_pub` : identifie les dépôts chez les partenaires.
    pub sig_pub: Id,
}

pub fn emergency_keys(k_attach: &Id) -> Result<EmergencyKeys, DhtError> {
    let content = kdf(k_attach, EMERGENCY_CONTENT, &[], &[])?;
    let sig_priv = kdf(k_attach, EMERGENCY_SIGNING, &[], &[])?;
    let sig_pub = SigningKey::from_bytes(&sig_priv).verifying_key().to_bytes();
    Ok(EmergencyKeys {
        content,
        sig_priv,
        sig_pub,
    })
}

/// Partenaire de secours (`EmergencyPartner`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Partner {
    pub node_id: Id,
    pub ip: String,
    pub port: u16,
}

/// Changement de racine en attente : mutation `update_entry` sur `/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootChange {
    pub timestamp: u64,
    pub new_root: Id,
    pub encryption_salt: [u8; 16],
    pub key_version: u16,
}

/// `EmergencyManifest` déchiffré.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    pub user_id: Id,
    pub partners: Vec<Partner>,
    /// `(hash du bloc, node_id du partenaire)`.
    pub blocks: Vec<(Id, Id)>,
    pub roots: Vec<RootChange>,
    /// Racine sur laquelle les changements ont été construits.
    pub base_fs_root_hash: Id,
    pub timestamp: u64,
}

impl Manifest {
    /// Changement de racine à réconcilier sur `current_root` : le plus
    /// récent, s'il a été construit sur cette racine.
    pub fn pending_root(&self, current_root: &Id) -> Option<&RootChange> {
        if self.base_fs_root_hash != *current_root {
            return None;
        }
        self.roots.iter().max_by_key(|r| r.timestamp)
    }

    /// Hashes déposés chez `node_id`.
    pub fn blocks_at(&self, node_id: &Id) -> Vec<Id> {
        self.blocks
            .iter()
            .filter(|(_, n)| n == node_id)
            .map(|(h, _)| *h)
            .collect()
    }
}

fn id_of(v: Option<flatbuffers::Vector<'_, u8>>) -> Result<Id, DhtError> {
    v.and_then(|x| x.bytes().try_into().ok())
        .ok_or(DhtError::Format("identifiant de 32 o"))
}

/// Sérialise l'`EmergencyManifest`.
pub fn encode_manifest(m: &Manifest) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let partners: Vec<_> = m
        .partners
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let n = b.create_vector(&p.node_id);
            let ip = b.create_string(&p.ip);
            fbe::EmergencyPartner::create(
                &mut b,
                &fbe::EmergencyPartnerArgs {
                    partner_id: i as u16,
                    node_id: Some(n),
                    ip: Some(ip),
                    port: p.port,
                },
            )
        })
        .collect();
    let index = |n: &Id| m.partners.iter().position(|p| p.node_id == *n);
    let blocks: Vec<_> = m
        .blocks
        .iter()
        .filter_map(|(h, n)| Some((h, index(n)?)))
        .map(|(h, i)| {
            let h = b.create_vector(h);
            fbe::EmergencyBlockEntry::create(
                &mut b,
                &fbe::EmergencyBlockEntryArgs {
                    block_hash: Some(h),
                    partner_id: i as u16,
                },
            )
        })
        .collect();
    let mutations: Vec<_> = m
        .roots
        .iter()
        .map(|r| {
            let name = b.create_string("");
            let mime = b.create_string(DIRECTORY_MIME);
            let first = b.create_vector(&r.new_root);
            let salt = b.create_vector(&r.encryption_salt);
            let entry = fbf::DirectoryEntry::create(
                &mut b,
                &fbf::DirectoryEntryArgs {
                    name: Some(name),
                    mime_type: Some(mime),
                    first_block_hash: Some(first),
                    encryption_salt: Some(salt),
                    key_version: r.key_version,
                    ..Default::default()
                },
            );
            let op = b.create_string(OP_UPDATE_ENTRY);
            let path = b.create_string(ROOT_PATH);
            let h = b.create_vector(&r.new_root);
            fbe::EmergencyMutation::create(
                &mut b,
                &fbe::EmergencyMutationArgs {
                    timestamp: r.timestamp,
                    op: Some(op),
                    fs_path: Some(path),
                    block_hash: Some(h),
                    entry: Some(entry),
                    blocks_to_delete: None,
                },
            )
        })
        .collect();
    let user = b.create_vector(&m.user_id);
    let partners = b.create_vector(&partners);
    let blocks = b.create_vector(&blocks);
    let mutations = b.create_vector(&mutations);
    let base = b.create_vector(&m.base_fs_root_hash);
    let o = fbe::EmergencyManifest::create(
        &mut b,
        &fbe::EmergencyManifestArgs {
            user_id: Some(user),
            partners: Some(partners),
            blocks: Some(blocks),
            mutations: Some(mutations),
            base_fs_root_hash: Some(base),
            timestamp: m.timestamp,
        },
    );
    b.finish_minimal(o);
    b.finished_data().to_vec()
}

/// Désérialise l'`EmergencyManifest` ; les mutations autres qu'un
/// changement de racine sont ignorées.
pub fn decode_manifest(buf: &[u8]) -> Result<Manifest, DhtError> {
    let m = flatbuffers::root::<fbe::EmergencyManifest>(buf)
        .map_err(|_| DhtError::Format("EmergencyManifest"))?;
    let mut partners: Vec<(u16, Partner)> = Vec::new();
    for p in m.partners().iter().flatten() {
        partners.push((
            p.partner_id(),
            Partner {
                node_id: id_of(p.node_id())?,
                ip: p.ip().unwrap_or_default().to_string(),
                port: p.port(),
            },
        ));
    }
    let mut blocks = Vec::new();
    for e in m.blocks().iter().flatten() {
        let Some((_, p)) = partners.iter().find(|(i, _)| *i == e.partner_id()) else {
            return Err(DhtError::Format("partner_id inconnu"));
        };
        blocks.push((id_of(e.block_hash())?, p.node_id));
    }
    let mut roots = Vec::new();
    for x in m.mutations().iter().flatten() {
        if x.op() != Some(OP_UPDATE_ENTRY) || x.fs_path() != Some(ROOT_PATH) {
            continue;
        }
        let e = x.entry().ok_or(DhtError::Format("entry"))?;
        roots.push(RootChange {
            timestamp: x.timestamp(),
            new_root: id_of(e.first_block_hash())?,
            encryption_salt: e
                .encryption_salt()
                .and_then(|v| v.bytes().try_into().ok())
                .ok_or(DhtError::Format("encryption_salt"))?,
            key_version: e.key_version(),
        });
    }
    Ok(Manifest {
        user_id: id_of(m.user_id())?,
        partners: partners.into_iter().map(|(_, p)| p).collect(),
        blocks,
        roots,
        base_fs_root_hash: id_of(m.base_fs_root_hash())?,
        timestamp: m.timestamp(),
    })
}

/// Enveloppe DHT de l'`EmergencyEntry` : manifeste chiffré sous
/// `K_emergency_content`, signé par `sig_priv_emergency`.
pub fn emergency_entry_envelope(
    k_attach: &Id,
    seq: u64,
    timestamp: u64,
    nonce: &[u8; 12],
    manifest: &Manifest,
) -> Result<Vec<u8>, DhtError> {
    let keys = emergency_keys(k_attach)?;
    let blob = seal_blob(
        &keys.content,
        EntryKind::Emergency.blob_aad_label(),
        nonce,
        &encode_manifest(manifest),
    )?;
    let mut b = FlatBufferBuilder::new();
    let key = b.create_vector(&keys.sig_pub);
    let ct = b.create_vector(&blob);
    let e = fbd::EmergencyEntry::create(
        &mut b,
        &fbd::EmergencyEntryArgs {
            sig_pub_emergency: Some(key),
            seq,
            timestamp,
            ciphertext: Some(ct),
        },
    );
    fbd::finish_emergency_entry_buffer(&mut b, e);
    let payload = b.finished_data().to_vec();
    let sig = sign(
        &keys.sig_priv,
        EntryKind::Emergency.signature_label(),
        &payload,
    );
    Ok(build_envelope(&payload, &sig))
}

/// `(seq, manifeste)` d'une enveloppe déjà vérifiée par l'adaptateur DHT.
pub fn open_emergency_entry(k_attach: &Id, envelope: &[u8]) -> Result<(u64, Manifest), DhtError> {
    let keys = emergency_keys(k_attach)?;
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope)
        .map_err(|_| DhtError::Format("DhtEnvelope"))?;
    let payload = env.payload().ok_or(DhtError::Format("payload"))?.bytes();
    let e =
        fbd::root_as_emergency_entry(payload).map_err(|_| DhtError::Format("EmergencyEntry"))?;
    let blob = e.ciphertext().ok_or(DhtError::Format("ciphertext"))?;
    let clear = open_blob(
        &keys.content,
        EntryKind::Emergency.blob_aad_label(),
        blob.bytes(),
    )?;
    Ok((e.seq(), decode_manifest(&clear)?))
}

/// Lecture-fusion : ajoute `mine` à l'entrée courante sans rien perdre.
/// Une entrée construite sur une autre racine est périmée (réconciliée ou
/// en conflit) : `mine` la remplace.
pub fn merge_manifest(current: Option<&Manifest>, mine: &Manifest) -> Manifest {
    let Some(cur) = current.filter(|c| c.base_fs_root_hash == mine.base_fs_root_hash) else {
        return mine.clone();
    };
    let mut out = cur.clone();
    for p in &mine.partners {
        if !out.partners.iter().any(|q| q.node_id == p.node_id) {
            out.partners.push(p.clone());
        }
    }
    for b in &mine.blocks {
        if !out.blocks.contains(b) {
            out.blocks.push(*b);
        }
    }
    for r in &mine.roots {
        if !out.roots.contains(r) {
            out.roots.push(*r);
        }
    }
    out.roots.sort_by_key(|r| r.timestamp);
    out.timestamp = out.timestamp.max(mine.timestamp);
    out
}
