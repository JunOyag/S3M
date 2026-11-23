//! Construction des entrées DHT Node et User — id `network.dht-directory`,
//! partie commune, sans I/O. Réf. spec : docs/01-network-dht/dht-directory.md,
//! docs/01-network-dht/vdf-identity.md.
//!
//! La preuve VDF porte sur l'identité marquée `0x00 ‖ pub_node` (Node) ou
//! `0x00 ‖ sig_pub_user` (User) ; elle est calculée une fois (≈ 30 s à
//! 1,5 min) puis réutilisée à chaque republication.

use ed25519_dalek::SigningKey;
use flatbuffers::{FlatBufferBuilder, WIPOffset};
use s3m_core::k_node_self::derive_k_node_self;
use s3m_core::k_self::derive_k_self;
use s3m_core::keys::{derive_sig_priv_user, derive_sig_pub_user, derive_user_dht_key};
use s3m_core::vdf::{tagged_identity, VdfProof, KEY_ALGORITHM_ED25519};
use s3m_core::CoreError;

use crate::dht::{build_envelope, open_blob, seal_blob, sign, DhtError, EntryKind};
use crate::fb::dht as fb;

/// Identité marquée dont la preuve VDF accompagne l'entrée Node.
pub fn node_identity(pub_node: &[u8; 32]) -> Result<[u8; 33], CoreError> {
    tagged_identity(KEY_ALGORITHM_ED25519, pub_node)
}

/// Identité marquée dont la preuve VDF accompagne l'entrée User.
pub fn user_identity(priv_user: &[u8; 32], pub_user: &[u8; 32]) -> Result<[u8; 33], CoreError> {
    let sig_priv = derive_sig_priv_user(priv_user, pub_user)?;
    tagged_identity(KEY_ALGORITHM_ED25519, &derive_sig_pub_user(&sig_priv))
}

/// Sérialisation compacte d'une preuve (cache local) : `u16be(|y|) ‖ y ‖ π`.
pub fn encode_proof(p: &VdfProof) -> Vec<u8> {
    let mut out = (p.y.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&p.y);
    out.extend_from_slice(&p.pi);
    out
}

pub fn decode_proof(b: &[u8]) -> Option<VdfProof> {
    let n = u16::from_be_bytes(b.get(..2)?.try_into().ok()?) as usize;
    Some(VdfProof {
        y: b.get(2..2 + n)?.to_vec(),
        pi: b.get(2 + n..)?.to_vec(),
    })
}

fn proof_fb<'a>(
    b: &mut FlatBufferBuilder<'a>,
    identity: &[u8; 33],
    p: &VdfProof,
) -> WIPOffset<fb::VdfProof<'a>> {
    let id = b.create_vector(identity);
    let y = b.create_vector(&p.y);
    let pi = b.create_vector(&p.pi);
    fb::VdfProof::create(
        b,
        &fb::VdfProofArgs {
            identity: Some(id),
            y: Some(y),
            pi: Some(pi),
        },
    )
}

/// Entrée Node publiée sous la clé `pub_node`.
pub struct NodeEntryParams<'a> {
    pub ip: &'a str,
    pub port: u16,
    pub timestamp: u64,
    pub proof: &'a VdfProof,
    pub pub_node_recovery: &'a [u8; 32],
    /// `NodeSnapshotPointer` sérialisé (chiffré ici sous `K_node_self`).
    pub snapshot_pointer: Option<&'a [u8]>,
    /// Multiaddrs joignables, directes d'abord puis via relais
    /// (`network.traversee-nat`).
    pub addrs: &'a [String],
    /// Clé d'annonce, hors seed (`protocols.canal-noeud`).
    pub pub_node_announce: Option<&'a [u8; 32]>,
    /// Nom du Nœud (`deploiement.pseudos`), nettoyé à l'encodage.
    pub name: Option<&'a str>,
}

/// Enveloppe signée de l'entrée Node.
pub fn node_entry_envelope(
    priv_node: &[u8; 32],
    p: &NodeEntryParams<'_>,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, DhtError> {
    let pub_node = SigningKey::from_bytes(priv_node).verifying_key().to_bytes();
    let blob = match p.snapshot_pointer {
        Some(ptr) => Some(seal_blob(
            &derive_k_node_self(priv_node)?,
            EntryKind::Node.blob_aad_label(),
            nonce,
            ptr,
        )?),
        None => None,
    };
    let mut b = FlatBufferBuilder::new();
    let proof = proof_fb(&mut b, &node_identity(&pub_node)?, p.proof);
    let ip = b.create_string(p.ip);
    let rec = b.create_vector(p.pub_node_recovery);
    let ct = blob.map(|x| b.create_vector(&x));
    let addrs: Vec<_> = p.addrs.iter().map(|a| b.create_string(a)).collect();
    let addrs = b.create_vector(&addrs);
    let announce = p.pub_node_announce.map(|k| b.create_vector(k));
    let name = p
        .name
        .map(crate::pseudo::sanitize)
        .filter(|n| !n.is_empty())
        .map(|n| b.create_string(&n));
    let e = fb::NodeEntry::create(
        &mut b,
        &fb::NodeEntryArgs {
            ip: Some(ip),
            port: p.port,
            timestamp: p.timestamp,
            vdf_proof: Some(proof),
            pub_node_recovery: Some(rec),
            migration_pointer: None,
            snapshot_ciphertext: ct,
            addrs: Some(addrs),
            pub_node_announce: announce,
            name,
        },
    );
    fb::finish_node_entry_buffer(&mut b, e);
    let payload = b.finished_data().to_vec();
    Ok(build_envelope(
        &payload,
        &sign(priv_node, EntryKind::Node.signature_label(), &payload),
    ))
}

/// Attachement (User, Node) publié dans l'entrée User.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachment {
    pub node_id: [u8; 32],
    pub salt: Vec<u8>,
    pub timestamp: u64,
    pub inactivity_detected_at: u64,
    /// Nom donné au Nœud par l'Utilisateur (`deploiement.pseudos`).
    pub node_label: String,
}

/// Contenu chiffré de l'entrée User (`UserEntryPlaintext`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserPlain {
    pub fs_root_hash: [u8; 32],
    pub encryption_salt: [u8; 16],
    pub key_version: u16,
    pub attachments: Vec<Attachment>,
    /// Pseudo de l'identité (`deploiement.pseudos`).
    pub pseudo: String,
}

fn encode_user_plain(u: &UserPlain) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let recs: Vec<_> = u
        .attachments
        .iter()
        .map(|a| {
            let n = b.create_vector(&a.node_id);
            let s = b.create_vector(&a.salt);
            let label = crate::pseudo::sanitize(&a.node_label);
            let label = (!label.is_empty()).then(|| b.create_string(&label));
            fb::AttachmentRecord::create(
                &mut b,
                &fb::AttachmentRecordArgs {
                    node_id: Some(n),
                    salt: Some(s),
                    timestamp: a.timestamp,
                    inactivity_detected_at: a.inactivity_detected_at,
                    node_label: label,
                    ..Default::default()
                },
            )
        })
        .collect();
    let recs = b.create_vector(&recs);
    let root = b.create_vector(&u.fs_root_hash);
    let salt = b.create_vector(&u.encryption_salt);
    let pseudo = crate::pseudo::sanitize(&u.pseudo);
    let pseudo = (!pseudo.is_empty()).then(|| b.create_string(&pseudo));
    let p = fb::UserEntryPlaintext::create(
        &mut b,
        &fb::UserEntryPlaintextArgs {
            fs_root_hash: Some(root),
            encryption_salt: Some(salt),
            key_version: u.key_version,
            attachments: Some(recs),
            master_key_chain: None,
            schema_version: 1,
            pseudo,
            // deploiement.contacts : pas encore publiés.
            contacts: None,
            padding: None,
        },
    );
    b.finish_minimal(p);
    b.finished_data().to_vec()
}

/// `(clé DHT, enveloppe)` de l'entrée User.
pub fn user_entry_envelope(
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
    timestamp: u64,
    proof: &VdfProof,
    plain: &UserPlain,
    nonce: &[u8; 12],
) -> Result<([u8; 32], Vec<u8>), DhtError> {
    let sig_priv = derive_sig_priv_user(priv_user, pub_user)?;
    let sig_pub = derive_sig_pub_user(&sig_priv);
    let blob = seal_blob(
        &derive_k_self(priv_user)?,
        EntryKind::User.blob_aad_label(),
        nonce,
        &encode_user_plain(plain),
    )?;
    let mut b = FlatBufferBuilder::new();
    let key = b.create_vector(&sig_pub);
    let pr = proof_fb(
        &mut b,
        &tagged_identity(KEY_ALGORITHM_ED25519, &sig_pub)?,
        proof,
    );
    let ct = b.create_vector(&blob);
    let e = fb::UserEntry::create(
        &mut b,
        &fb::UserEntryArgs {
            sig_pub_user: Some(key),
            timestamp,
            vdf_proof: Some(pr),
            ciphertext: Some(ct),
        },
    );
    fb::finish_user_entry_buffer(&mut b, e);
    let payload = b.finished_data().to_vec();
    let env = build_envelope(
        &payload,
        &sign(&sig_priv, EntryKind::User.signature_label(), &payload),
    );
    Ok((derive_user_dht_key(priv_user, pub_user)?, env))
}

/// Déchiffre l'entrée User (enveloppe déjà vérifiée).
pub fn open_user_entry(priv_user: &[u8; 32], envelope: &[u8]) -> Result<UserPlain, DhtError> {
    let env = flatbuffers::root::<fb::DhtEnvelope>(envelope)
        .map_err(|_| DhtError::Format("DhtEnvelope"))?;
    let e = fb::root_as_user_entry(env.payload().ok_or(DhtError::Format("payload"))?.bytes())
        .map_err(|_| DhtError::Format("UserEntry"))?;
    let clear = open_blob(
        &derive_k_self(priv_user)?,
        EntryKind::User.blob_aad_label(),
        e.ciphertext()
            .ok_or(DhtError::Format("ciphertext"))?
            .bytes(),
    )?;
    let p = flatbuffers::root::<fb::UserEntryPlaintext>(&clear)
        .map_err(|_| DhtError::Format("UserEntryPlaintext"))?;
    let arr32 = |v: Option<flatbuffers::Vector<'_, u8>>| -> Result<[u8; 32], DhtError> {
        v.and_then(|x| x.bytes().try_into().ok())
            .ok_or(DhtError::Format("32 o"))
    };
    Ok(UserPlain {
        fs_root_hash: arr32(p.fs_root_hash())?,
        encryption_salt: p
            .encryption_salt()
            .and_then(|x| x.bytes().try_into().ok())
            .ok_or(DhtError::Format("encryption_salt"))?,
        key_version: p.key_version(),
        attachments: p
            .attachments()
            .map(|v| {
                v.iter()
                    .map(|a| {
                        Ok(Attachment {
                            node_id: arr32(a.node_id())?,
                            salt: a.salt().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                            timestamp: a.timestamp(),
                            inactivity_detected_at: a.inactivity_detected_at(),
                            node_label: crate::pseudo::sanitize(a.node_label().unwrap_or_default()),
                        })
                    })
                    .collect::<Result<Vec<_>, DhtError>>()
            })
            .transpose()?
            .unwrap_or_default(),
        pseudo: crate::pseudo::sanitize(p.pseudo().unwrap_or_default()),
    })
}

/// `(multiaddrs du champ addrs, (ip, port) direct)` d'une entrée Node.
pub type NodeAddrs = (Vec<String>, Option<(String, u16)>);

/// Adresses publiées par une entrée Node (enveloppe déjà vérifiée).
pub fn node_entry_addrs(envelope: &[u8]) -> Option<NodeAddrs> {
    let env = flatbuffers::root::<fb::DhtEnvelope>(envelope).ok()?;
    let e = fb::root_as_node_entry(env.payload()?.bytes()).ok()?;
    let addrs = e
        .addrs()
        .map(|v| v.iter().map(str::to_string).collect())
        .unwrap_or_default();
    let direct = e
        .ip()
        .filter(|i| !i.is_empty())
        .map(|i| (i.to_string(), e.port()));
    Some((addrs, direct))
}

/// Clé d'annonce publiée par une entrée Node (enveloppe déjà vérifiée).
pub fn node_entry_announce(envelope: &[u8]) -> Option<[u8; 32]> {
    let env = flatbuffers::root::<fb::DhtEnvelope>(envelope).ok()?;
    let e = fb::root_as_node_entry(env.payload()?.bytes()).ok()?;
    e.pub_node_announce()?.bytes().try_into().ok()
}

/// Nom publié par une entrée Node (enveloppe déjà vérifiée), nettoyé.
pub fn node_entry_name(envelope: &[u8]) -> Option<String> {
    let env = flatbuffers::root::<fb::DhtEnvelope>(envelope).ok()?;
    let e = fb::root_as_node_entry(env.payload()?.bytes()).ok()?;
    Some(crate::pseudo::sanitize(e.name()?)).filter(|n| !n.is_empty())
}
