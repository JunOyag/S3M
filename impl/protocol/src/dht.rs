//! Annuaire DHT — id `network.dht-directory`, partie commune Nœud/Connecteur
//! (component `protocol`, spec V3). Réf. spec :
//! docs/01-network-dht/dht-directory.md. Aucune I/O : l'adaptateur réseau
//! (Kademlia) vit dans `impl/node` et `impl/connector`.
//!
//! - enveloppe signée : signature Ed25519 sur `L(libellé du type) ‖ payload`,
//!   octets exacts reçus, jamais réserialisés ;
//! - `file_identifier` par type, tag `key_algorithm`, preuve VDF (Node, User),
//!   expiration et séquences vérifiés avant de rendre une entrée ;
//! - blobs AEAD `nonce ‖ chiffré ‖ tag`, AAD = `L(libellé) ‖ u16be(1)` ;
//! - TTL en secondes et lissage des republications.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use flatbuffers::FlatBufferBuilder;
use p2p_storage_core::symmetric_suite::{
    aead_open, aead_seal, canonical_encode, hash_sha256, AEAD_NONCE_LEN, AEAD_TAG_LEN,
};
use p2p_storage_core::vdf::{
    check_key_algorithm, VdfProof, KEY_ALGORITHM_ED25519, TAGGED_IDENTITY_LEN,
};
use p2p_storage_core::CoreError;
use thiserror::Error;

use crate::fb::dht;

/// « 6 mois » : durée de vie Node, DispersalManifest, EmergencyManifest.
pub const TTL_SIX_MONTHS_S: u64 = 15_552_000;
/// « 1 an » : republication de secours d'une entrée User sans écriture.
pub const ONE_YEAR_S: u64 = 31_536_000;
/// « 10 ans » : durée de vie User.
pub const TTL_TEN_YEARS_S: u64 = 315_360_000;
/// Période de republication (« mensuelle »).
pub const REPUBLISH_PERIOD_S: u64 = 2_592_000;
/// Version de protocole portée par l'AAD des blobs (`schema_version`).
pub const SCHEMA_VERSION: u16 = 1;
/// Libellé de signature du pointeur de migration.
pub const SIG_LABEL_MIGRATION_POINTER: &str = "p2p-storage/sig/migration-pointer/v1";

/// Erreurs de vérification d'une entrée DHT — chaque cause est distincte.
#[derive(Debug, Error)]
pub enum DhtError {
    #[error("buffer FlatBuffers invalide : {0}")]
    Format(&'static str),
    #[error("file_identifier inattendu pour ce type d'entrée")]
    WrongFileIdentifier,
    #[error("algorithme de clé non supporté (tag {0})")]
    UnsupportedKeyAlgorithm(u8),
    #[error("tag key_algorithm inconnu : {0}")]
    UnknownKeyAlgorithm(u8),
    #[error("tag incohérent entre l'identité VDF et l'enveloppe")]
    InconsistentKeyAlgorithm,
    #[error("signature invalide")]
    BadSignature,
    #[error("preuve VDF absente, mal formée ou invalide")]
    InvalidVdf,
    #[error("entrée expirée")]
    Expired,
    #[error("séquence non strictement croissante")]
    StaleSequence,
    #[error("pointeur de migration incohérent avec l'entrée qui le porte")]
    MigrationMismatch,
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// Les quatre types d'entrée DHT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Node,
    User,
    Dispersal,
    Emergency,
}

impl EntryKind {
    /// Libellé de signature (séparation de contexte uniforme, ❓3).
    pub fn signature_label(self) -> &'static str {
        match self {
            Self::Node => "p2p-storage/sig/node-entry/v1",
            Self::User => "p2p-storage/sig/user-entry/v1",
            Self::Dispersal => "p2p-storage/sig/dispersal-entry/v1",
            Self::Emergency => "p2p-storage/sig/emergency-entry/v1",
        }
    }

    /// Libellé AAD du blob chiffré porté par l'entrée.
    pub fn blob_aad_label(self) -> &'static str {
        match self {
            Self::Node => "dht-node-snapshot",
            Self::User => "dht-user-plaintext",
            Self::Dispersal => "dht-dispersal-root",
            Self::Emergency => "dht-emergency-manifest",
        }
    }

    /// `file_identifier` FlatBuffers du payload.
    pub fn file_identifier(self) -> &'static str {
        match self {
            Self::Node => dht::NODE_ENTRY_IDENTIFIER,
            Self::User => dht::USER_ENTRY_IDENTIFIER,
            Self::Dispersal => dht::DISPERSAL_ENTRY_IDENTIFIER,
            Self::Emergency => dht::EMERGENCY_ENTRY_IDENTIFIER,
        }
    }

    /// Durée de vie de l'entrée, en secondes.
    pub fn ttl_seconds(self) -> u64 {
        match self {
            Self::User => TTL_TEN_YEARS_S,
            _ => TTL_SIX_MONTHS_S,
        }
    }
}

/// Message signé : `L(label) ‖ payload` (L = longueur u32 big-endian).
pub fn signed_message(label: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = canonical_encode(&[label.as_bytes()]);
    m.extend_from_slice(payload);
    m
}

/// Signe `payload` sous le libellé `label` avec la graine Ed25519 `seed`.
pub fn sign(seed: &[u8; 32], label: &str, payload: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed)
        .sign(&signed_message(label, payload))
        .to_bytes()
}

/// Vérifie une signature sur les octets exacts reçus.
pub fn verify_signature(
    public_key: &[u8],
    label: &str,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), DhtError> {
    let pk: [u8; 32] = public_key.try_into().map_err(|_| DhtError::BadSignature)?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| DhtError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| DhtError::BadSignature)?;
    // `verify_strict` : rejette aussi les signatures malléables et les clés
    // de petit ordre (entrée venant d'un pair hostile).
    vk.verify_strict(
        &signed_message(label, payload),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| DhtError::BadSignature)
}

/// AAD d'un blob DHT : `L(libellé) ‖ u16be(schema_version)`.
pub fn blob_aad(label: &str) -> Vec<u8> {
    let mut aad = canonical_encode(&[label.as_bytes()]);
    aad.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    aad
}

/// Chiffre un blob : `nonce ‖ chiffré ‖ tag`. `nonce` : 12 o aléatoires
/// tirés par l'appelant.
pub fn seal_blob(
    key: &[u8; 32],
    label: &str,
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, DhtError> {
    let mut out = nonce.to_vec();
    out.extend_from_slice(&aead_seal(key, nonce, &blob_aad(label), plaintext)?);
    Ok(out)
}

/// Ouvre un blob `nonce ‖ chiffré ‖ tag`.
pub fn open_blob(key: &[u8; 32], label: &str, blob: &[u8]) -> Result<Vec<u8>, DhtError> {
    if blob.len() < AEAD_NONCE_LEN + AEAD_TAG_LEN {
        return Err(DhtError::Format("blob trop court"));
    }
    let (nonce, sealed) = blob.split_at(AEAD_NONCE_LEN);
    Ok(aead_open(key, nonce, &blob_aad(label), sealed)?)
}

/// `offset_s = int_be(SHA-256(identifiant)) mod 2 592 000`.
pub fn republish_offset(identifier: &[u8]) -> u64 {
    let digest = hash_sha256(identifier);
    // Réduction modulaire octet par octet de l'entier big-endian de 256 bits.
    digest.iter().fold(0u64, |acc, &b| {
        ((acc << 8) | u64::from(b)) % REPUBLISH_PERIOD_S
    })
}

/// Prochain instant Unix `t ≥ now` tel que `t ≡ offset_s (mod 2 592 000)`.
pub fn next_republish_at(identifier: &[u8], now: u64) -> u64 {
    let offset = republish_offset(identifier);
    let base = now - now % REPUBLISH_PERIOD_S + offset;
    if base >= now {
        base
    } else {
        base + REPUBLISH_PERIOD_S
    }
}

/// `dht_key` du DispersalManifest : `SHA-256(K_attach)`.
pub fn dispersal_dht_key(k_attach: &[u8; 32]) -> [u8; 32] {
    hash_sha256(k_attach)
}

/// `emergency_dht_key = SHA-256(K_attach ‖ "emergency")`.
pub fn emergency_dht_key(k_attach: &[u8; 32]) -> [u8; 32] {
    hash_sha256(&[&k_attach[..], b"emergency"].concat())
}

/// Sérialise une `DhtEnvelope` (tag 0).
pub fn build_envelope(payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();
    let p = fbb.create_vector(payload);
    let s = fbb.create_vector(signature);
    let env = dht::DhtEnvelope::create(
        &mut fbb,
        &dht::DhtEnvelopeArgs {
            key_algorithm: KEY_ALGORITHM_ED25519,
            payload: Some(p),
            signature: Some(s),
        },
    );
    fbb.finish_minimal(env);
    fbb.finished_data().to_vec()
}

/// Contexte de vérification fourni par l'adaptateur.
#[derive(Debug, Clone, Copy)]
pub struct VerifyContext<'a> {
    /// Instant Unix courant (secondes).
    pub now: u64,
    /// Clé de recherche de l'entrée Node (`pub_node`) — requise pour `Node`.
    pub node_lookup_key: Option<&'a [u8; 32]>,
    /// Dernier `seq` détenu (EmergencyEntry), s'il y en a un.
    pub previous_seq: Option<u64>,
}

/// Vérificateur VDF injecté : `chiavdf` en production
/// (`p2p_storage_core::vdf::verify_identity_proof`), un double en test.
pub type VdfVerifier<'a> =
    &'a dyn Fn(&[u8; TAGGED_IDENTITY_LEN], &VdfProof) -> Result<bool, CoreError>;

fn map_tag(e: CoreError) -> DhtError {
    match e {
        CoreError::UnsupportedKeyAlgorithm { tag } => DhtError::UnsupportedKeyAlgorithm(tag),
        CoreError::UnknownKeyAlgorithm { tag } => DhtError::UnknownKeyAlgorithm(tag),
        other => DhtError::Core(other),
    }
}

fn check_vdf(
    envelope_tag: u8,
    signer_key: &[u8],
    proof: Option<dht::VdfProof<'_>>,
    vdf: VdfVerifier<'_>,
) -> Result<(), DhtError> {
    let proof = proof.ok_or(DhtError::InvalidVdf)?;
    let identity: [u8; TAGGED_IDENTITY_LEN] = proof
        .identity()
        .ok_or(DhtError::InvalidVdf)?
        .bytes()
        .try_into()
        .map_err(|_| DhtError::InvalidVdf)?;
    check_key_algorithm(identity[0]).map_err(map_tag)?;
    if identity[0] != envelope_tag {
        return Err(DhtError::InconsistentKeyAlgorithm);
    }
    if &identity[1..] != signer_key {
        return Err(DhtError::InvalidVdf);
    }
    let p = VdfProof {
        y: proof.y().ok_or(DhtError::InvalidVdf)?.bytes().to_vec(),
        pi: proof.pi().ok_or(DhtError::InvalidVdf)?.bytes().to_vec(),
    };
    match vdf(&identity, &p) {
        Ok(true) => Ok(()),
        Ok(false) => Err(DhtError::InvalidVdf),
        Err(e) => Err(DhtError::Core(e)),
    }
}

fn check_ttl(kind: EntryKind, timestamp: u64, now: u64) -> Result<(), DhtError> {
    if now > timestamp.saturating_add(kind.ttl_seconds()) {
        return Err(DhtError::Expired);
    }
    Ok(())
}

/// Vérifie une enveloppe reçue et rend les octets exacts du payload.
/// Ordre (page § Règles de vérification à la lecture) : `file_identifier`,
/// tag, signature, preuve VDF (Node, User) et cohérence du tag, expiration,
/// séquence (Emergency).
pub fn verify_envelope(
    envelope: &[u8],
    kind: EntryKind,
    ctx: &VerifyContext<'_>,
    vdf: VdfVerifier<'_>,
) -> Result<Vec<u8>, DhtError> {
    let env = flatbuffers::root::<dht::DhtEnvelope>(envelope)
        .map_err(|_| DhtError::Format("DhtEnvelope"))?;
    let payload = env
        .payload()
        .ok_or(DhtError::Format("payload absent"))?
        .bytes();
    let signature = env.signature().ok_or(DhtError::BadSignature)?.bytes();
    if !flatbuffers::buffer_has_identifier(payload, kind.file_identifier(), false) {
        return Err(DhtError::WrongFileIdentifier);
    }
    let tag = env.key_algorithm();
    check_key_algorithm(tag).map_err(map_tag)?;
    let label = kind.signature_label();
    match kind {
        EntryKind::Node => {
            let e = dht::root_as_node_entry(payload).map_err(|_| DhtError::Format("NodeEntry"))?;
            let key = ctx
                .node_lookup_key
                .ok_or(DhtError::Format("clé Node absente"))?;
            verify_signature(key, label, payload, signature)?;
            check_vdf(tag, key, e.vdf_proof(), vdf)?;
            check_ttl(kind, e.timestamp(), ctx.now)?;
        }
        EntryKind::User => {
            let e = dht::root_as_user_entry(payload).map_err(|_| DhtError::Format("UserEntry"))?;
            let key = e.sig_pub_user().ok_or(DhtError::BadSignature)?.bytes();
            verify_signature(key, label, payload, signature)?;
            check_vdf(tag, key, e.vdf_proof(), vdf)?;
            check_ttl(kind, e.timestamp(), ctx.now)?;
        }
        EntryKind::Dispersal => {
            let e = dht::root_as_dispersal_entry(payload)
                .map_err(|_| DhtError::Format("DispersalEntry"))?;
            let key = e.sig_pub_dispersal().ok_or(DhtError::BadSignature)?.bytes();
            verify_signature(key, label, payload, signature)?;
            check_ttl(kind, e.timestamp(), ctx.now)?;
        }
        EntryKind::Emergency => {
            let e = dht::root_as_emergency_entry(payload)
                .map_err(|_| DhtError::Format("EmergencyEntry"))?;
            let key = e.sig_pub_emergency().ok_or(DhtError::BadSignature)?.bytes();
            verify_signature(key, label, payload, signature)?;
            check_ttl(kind, e.timestamp(), ctx.now)?;
            if ctx.previous_seq.is_some_and(|prev| e.seq() <= prev) {
                return Err(DhtError::StaleSequence);
            }
        }
    }
    Ok(payload.to_vec())
}

/// Résumé d'une enveloppe **non vérifiée** : type (déduit du
/// `file_identifier` du payload), `timestamp` et `seq` éventuel. Sert à
/// l'adaptateur DHT pour choisir la règle de vérification et la date
/// d'expiration ; ne remplace jamais [`verify_envelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeSummary {
    pub kind: EntryKind,
    pub timestamp: u64,
    pub seq: Option<u64>,
}

impl EnvelopeSummary {
    /// Instant Unix d'expiration : `timestamp + TTL du type`.
    pub fn expires_at(&self) -> u64 {
        self.timestamp.saturating_add(self.kind.ttl_seconds())
    }
}

/// Lit le type, le `timestamp` et le `seq` d'une enveloppe.
pub fn inspect_envelope(envelope: &[u8]) -> Result<EnvelopeSummary, DhtError> {
    let env = flatbuffers::root::<dht::DhtEnvelope>(envelope)
        .map_err(|_| DhtError::Format("DhtEnvelope"))?;
    let payload = env
        .payload()
        .ok_or(DhtError::Format("payload absent"))?
        .bytes();
    let has =
        |k: EntryKind| flatbuffers::buffer_has_identifier(payload, k.file_identifier(), false);
    let bad = |what| move |_| DhtError::Format(what);
    let summary = if has(EntryKind::Node) {
        let e = dht::root_as_node_entry(payload).map_err(bad("NodeEntry"))?;
        (EntryKind::Node, e.timestamp(), None)
    } else if has(EntryKind::User) {
        let e = dht::root_as_user_entry(payload).map_err(bad("UserEntry"))?;
        (EntryKind::User, e.timestamp(), None)
    } else if has(EntryKind::Dispersal) {
        let e = dht::root_as_dispersal_entry(payload).map_err(bad("DispersalEntry"))?;
        (EntryKind::Dispersal, e.timestamp(), None)
    } else if has(EntryKind::Emergency) {
        let e = dht::root_as_emergency_entry(payload).map_err(bad("EmergencyEntry"))?;
        (EntryKind::Emergency, e.timestamp(), Some(e.seq()))
    } else {
        return Err(DhtError::WrongFileIdentifier);
    };
    Ok(EnvelopeSummary {
        kind: summary.0,
        timestamp: summary.1,
        seq: summary.2,
    })
}

/// Vérifie le `migration_pointer` d'une entrée Node : signature par
/// `pub_node_recovery` sous [`SIG_LABEL_MIGRATION_POINTER`], `old_node_id`
/// égal au `node_id` de l'entrée porteuse, `seq` strictement croissant.
/// Rend `new_node_id` (le Connecteur vérifie ensuite son entrée Node, un seul
/// saut automatique).
pub fn verify_migration_pointer(
    pointer: dht::SignedMigrationPointer<'_>,
    pub_node_recovery: &[u8],
    carrier_node_id: &[u8; 32],
    previous_seq: Option<u64>,
) -> Result<Vec<u8>, DhtError> {
    let payload = pointer
        .payload()
        .ok_or(DhtError::Format("payload absent"))?
        .bytes();
    let sig = pointer.signature().ok_or(DhtError::BadSignature)?.bytes();
    verify_signature(pub_node_recovery, SIG_LABEL_MIGRATION_POINTER, payload, sig)?;
    let p = flatbuffers::root::<dht::MigrationPointerPayload>(payload)
        .map_err(|_| DhtError::Format("MigrationPointerPayload"))?;
    if p.old_node_id().map(|v| v.bytes()) != Some(&carrier_node_id[..]) {
        return Err(DhtError::MigrationMismatch);
    }
    if p.seq() == 0 || previous_seq.is_some_and(|prev| p.seq() <= prev) {
        return Err(DhtError::StaleSequence);
    }
    Ok(p.new_node_id()
        .ok_or(DhtError::Format("new_node_id"))?
        .bytes()
        .to_vec())
}
