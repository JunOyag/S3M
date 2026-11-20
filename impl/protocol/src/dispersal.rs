//! Catalogue de dispersion — ids `protocols.dispersion-transactionnelle`
//! (orchestration) et `protocols.index-adaptatif`, partie commune, sans
//! I/O. Réf. spec : docs/04-protocols/dispersion-transactionnelle.md
//! § Orchestration, docs/02-schemas/network/DispersalRootPointer.md.
//!
//! Modèle Rust des `Stripe`, `IndexNode`, `DispersalManifest` et
//! `DispersalRootPointer`, leur codage, l'entrée DHT DispersalManifest et
//! les règles de placement (distance XOR, `stripe_id`).

use ed25519_dalek::SigningKey;
use flatbuffers::{FlatBufferBuilder, WIPOffset};
use s3m_core::k_attach::derive_sig_priv_dispersal;
use s3m_core::symmetric_suite::hash_sha256;
use s3m_core::CoreError;

use crate::dht::{build_envelope, open_blob, seal_blob, sign, DhtError, EntryKind};
use crate::fb::{dht as fbd, dispersal as fbs};

pub type Id = [u8; 32];

/// Entrées par `IndexNode` retenues à l'émission : marge sous le facteur
/// mesuré (68, `index::BRANCHING_FACTOR`) pour les sels des stripes
/// d'index et la table `Partner` de la racine.
pub const INDEX_FANOUT: usize = 60;

/// Un fragment d'un stripe (`BlockEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    pub hash: Id,
    /// 0..k-1 : données (locales) ; k..N-1 : parité.
    pub index: u16,
    /// 0 pour les données ; référence `Partner` pour la parité.
    pub partner_id: u16,
    pub key_version: u16,
    pub is_padding: bool,
}

/// `Stripe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeDesc {
    pub stripe_id: Id,
    pub k: u8,
    pub m: u8,
    pub blocks: Vec<BlockRef>,
    /// Sel du nœud d'index encodé par ce stripe (stripes d'index seulement).
    pub encryption_salt: Option<[u8; 16]>,
}

/// `Partner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerDesc {
    pub partner_id: u16,
    pub node_id: Id,
    pub ip: String,
    pub port: u16,
}

/// `IndexNode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexNodeDesc {
    pub is_leaf: bool,
    /// Stripes de données (feuille) ou stripes d'index enfants.
    pub entries: Vec<StripeDesc>,
}

/// `DispersalManifest` (nœud racine de l'arbre).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDesc {
    pub user_id: Id,
    pub node_id: Id,
    pub partners: Vec<PartnerDesc>,
    pub root: IndexNodeDesc,
    pub timestamp: u64,
}

/// `DispersalRootPointer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootPointer {
    pub root_hash: Id,
    pub partners: Vec<PartnerDesc>,
    pub salt: [u8; 16],
    pub root_stripe: StripeDesc,
}

/// Erreurs de format.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("format : {0}")]
    Format(&'static str),
    #[error(transparent)]
    Dht(#[from] DhtError),
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// `stripe_id` = SHA-256 de la concaténation des hashes de ses k blocs de
/// données (padding compris).
pub fn stripe_id(data_hashes: &[Id]) -> Id {
    hash_sha256(&data_hashes.concat())
}

/// Distance XOR (big-endian) entre deux identifiants.
pub fn xor_distance(a: &Id, b: &Id) -> Id {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Trie `candidates` par distance XOR croissante à `target`.
pub fn by_xor_distance(candidates: &mut [Id], target: &Id) {
    candidates.sort_by_key(|c| xor_distance(c, target));
}

// ------------------------------------------------------------------ codage

pub(crate) fn stripe_fb<'a>(
    b: &mut FlatBufferBuilder<'a>,
    s: &StripeDesc,
) -> WIPOffset<fbs::Stripe<'a>> {
    let blocks: Vec<_> = s
        .blocks
        .iter()
        .map(|x| {
            let h = b.create_vector(&x.hash);
            fbs::BlockEntry::create(
                b,
                &fbs::BlockEntryArgs {
                    block_hash: Some(h),
                    block_index: x.index,
                    partner_id: x.partner_id,
                    key_version: x.key_version,
                    is_padding: x.is_padding,
                },
            )
        })
        .collect();
    let blocks = b.create_vector(&blocks);
    let id = b.create_vector(&s.stripe_id);
    let salt = s.encryption_salt.map(|v| b.create_vector(&v));
    fbs::Stripe::create(
        b,
        &fbs::StripeArgs {
            stripe_id: Some(id),
            k: s.k,
            m: s.m,
            blocks: Some(blocks),
            encryption_salt: salt,
        },
    )
}

pub(crate) fn partners_fb<'a>(
    b: &mut FlatBufferBuilder<'a>,
    ps: &[PartnerDesc],
) -> WIPOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<fbs::Partner<'a>>>> {
    let v: Vec<_> = ps
        .iter()
        .map(|p| {
            let id = b.create_vector(&p.node_id);
            let ip = b.create_string(&p.ip);
            fbs::Partner::create(
                b,
                &fbs::PartnerArgs {
                    partner_id: p.partner_id,
                    node_id: Some(id),
                    ip: Some(ip),
                    port: p.port,
                },
            )
        })
        .collect();
    b.create_vector(&v)
}

fn index_fb<'a>(b: &mut FlatBufferBuilder<'a>, n: &IndexNodeDesc) -> WIPOffset<fbs::IndexNode<'a>> {
    let entries: Vec<_> = n.entries.iter().map(|s| stripe_fb(b, s)).collect();
    let v = b.create_vector(&entries);
    fbs::IndexNode::create(
        b,
        &fbs::IndexNodeArgs {
            is_leaf: n.is_leaf,
            stripes: n.is_leaf.then_some(v),
            children: (!n.is_leaf).then_some(v),
        },
    )
}

fn id_of(v: Option<flatbuffers::Vector<'_, u8>>) -> Result<Id, CatalogError> {
    v.and_then(|x| x.bytes().try_into().ok())
        .ok_or(CatalogError::Format("identifiant de 32 o"))
}

pub(crate) fn stripe_of(s: fbs::Stripe<'_>) -> Result<StripeDesc, CatalogError> {
    let blocks = s
        .blocks()
        .map(|v| {
            v.iter()
                .map(|x| {
                    Ok(BlockRef {
                        hash: id_of(x.block_hash())?,
                        index: x.block_index(),
                        partner_id: x.partner_id(),
                        key_version: x.key_version(),
                        is_padding: x.is_padding(),
                    })
                })
                .collect::<Result<Vec<_>, CatalogError>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(StripeDesc {
        stripe_id: id_of(s.stripe_id())?,
        k: s.k(),
        m: s.m(),
        blocks,
        encryption_salt: s
            .encryption_salt()
            .filter(|v| !v.is_empty())
            .map(|v| v.bytes().try_into())
            .transpose()
            .map_err(|_| CatalogError::Format("encryption_salt"))?,
    })
}

pub(crate) fn partners_of(
    v: Option<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<fbs::Partner<'_>>>>,
) -> Result<Vec<PartnerDesc>, CatalogError> {
    v.map(|v| {
        v.iter()
            .map(|p| {
                Ok(PartnerDesc {
                    partner_id: p.partner_id(),
                    node_id: id_of(p.node_id())?,
                    ip: p.ip().unwrap_or_default().to_string(),
                    port: p.port(),
                })
            })
            .collect()
    })
    .unwrap_or(Ok(Vec::new()))
}

fn index_of(n: fbs::IndexNode<'_>) -> Result<IndexNodeDesc, CatalogError> {
    let list = if n.is_leaf() {
        n.stripes()
    } else {
        n.children()
    };
    Ok(IndexNodeDesc {
        is_leaf: n.is_leaf(),
        entries: list
            .map(|v| v.iter().map(stripe_of).collect::<Result<Vec<_>, _>>())
            .transpose()?
            .unwrap_or_default(),
    })
}

/// Sérialise un `IndexNode` (nœud enfant de l'arbre).
pub fn encode_index_node(n: &IndexNodeDesc) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let o = index_fb(&mut b, n);
    b.finish_minimal(o);
    b.finished_data().to_vec()
}

pub fn decode_index_node(buf: &[u8]) -> Result<IndexNodeDesc, CatalogError> {
    index_of(
        flatbuffers::root::<fbs::IndexNode>(buf).map_err(|_| CatalogError::Format("IndexNode"))?,
    )
}

/// Sérialise le `DispersalManifest` (nœud racine).
pub fn encode_manifest(m: &ManifestDesc) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let user = b.create_vector(&m.user_id);
    let node = b.create_vector(&m.node_id);
    let partners = partners_fb(&mut b, &m.partners);
    let root = index_fb(&mut b, &m.root);
    let o = fbs::DispersalManifest::create(
        &mut b,
        &fbs::DispersalManifestArgs {
            user_id: Some(user),
            node_id: Some(node),
            partners: Some(partners),
            root: Some(root),
            timestamp: m.timestamp,
        },
    );
    fbs::finish_dispersal_manifest_buffer(&mut b, o);
    b.finished_data().to_vec()
}

pub fn decode_manifest(buf: &[u8]) -> Result<ManifestDesc, CatalogError> {
    let m = fbs::root_as_dispersal_manifest(buf)
        .map_err(|_| CatalogError::Format("DispersalManifest"))?;
    Ok(ManifestDesc {
        user_id: id_of(m.user_id())?,
        node_id: id_of(m.node_id())?,
        partners: partners_of(m.partners())?,
        root: index_of(m.root().ok_or(CatalogError::Format("root"))?)?,
        timestamp: m.timestamp(),
    })
}

/// Sérialise le `DispersalRootPointer`.
pub fn encode_root_pointer(p: &RootPointer) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let h = b.create_vector(&p.root_hash);
    let partners = partners_fb(&mut b, &p.partners);
    let salt = b.create_vector(&p.salt);
    let stripe = stripe_fb(&mut b, &p.root_stripe);
    let o = fbd::DispersalRootPointer::create(
        &mut b,
        &fbd::DispersalRootPointerArgs {
            dispersal_root_hash: Some(h),
            dispersal_root_partners: Some(partners),
            dispersal_root_salt: Some(salt),
            dispersal_root_stripe: Some(stripe),
        },
    );
    b.finish_minimal(o);
    b.finished_data().to_vec()
}

pub fn decode_root_pointer(buf: &[u8]) -> Result<RootPointer, CatalogError> {
    let p = flatbuffers::root::<fbd::DispersalRootPointer>(buf)
        .map_err(|_| CatalogError::Format("DispersalRootPointer"))?;
    Ok(RootPointer {
        root_hash: id_of(p.dispersal_root_hash())?,
        partners: partners_of(p.dispersal_root_partners())?,
        salt: p
            .dispersal_root_salt()
            .and_then(|v| v.bytes().try_into().ok())
            .ok_or(CatalogError::Format("dispersal_root_salt"))?,
        root_stripe: stripe_of(
            p.dispersal_root_stripe()
                .ok_or(CatalogError::Format("dispersal_root_stripe"))?,
        )?,
    })
}

// -------------------------------------------------------------- entrée DHT

/// Entrée DHT DispersalManifest : pointeur chiffré sous `K_attach`, signé
/// par `sig_priv_dispersal = KDF(K_attach, "dispersal-signing")`.
pub fn dispersal_entry_envelope(
    k_attach: &[u8; 32],
    timestamp: u64,
    nonce: &[u8; 12],
    pointer: &RootPointer,
) -> Result<Vec<u8>, CatalogError> {
    let sig_priv = derive_sig_priv_dispersal(k_attach)?;
    let sig_pub = SigningKey::from_bytes(&sig_priv).verifying_key().to_bytes();
    let blob = seal_blob(
        k_attach,
        EntryKind::Dispersal.blob_aad_label(),
        nonce,
        &encode_root_pointer(pointer),
    )?;
    let mut b = FlatBufferBuilder::new();
    let key = b.create_vector(&sig_pub);
    let ct = b.create_vector(&blob);
    let e = fbd::DispersalEntry::create(
        &mut b,
        &fbd::DispersalEntryArgs {
            sig_pub_dispersal: Some(key),
            timestamp,
            ciphertext: Some(ct),
        },
    );
    fbd::finish_dispersal_entry_buffer(&mut b, e);
    let payload = b.finished_data().to_vec();
    let sig = sign(&sig_priv, EntryKind::Dispersal.signature_label(), &payload);
    Ok(build_envelope(&payload, &sig))
}

/// Déchiffre le pointeur d'une enveloppe DispersalManifest (déjà vérifiée
/// par l'adaptateur DHT).
pub fn open_dispersal_entry(
    k_attach: &[u8; 32],
    envelope: &[u8],
) -> Result<RootPointer, CatalogError> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope)
        .map_err(|_| CatalogError::Format("DhtEnvelope"))?;
    let payload = env
        .payload()
        .ok_or(CatalogError::Format("payload"))?
        .bytes();
    let e = fbd::root_as_dispersal_entry(payload)
        .map_err(|_| CatalogError::Format("DispersalEntry"))?;
    let blob = e.ciphertext().ok_or(CatalogError::Format("ciphertext"))?;
    let clear = open_blob(
        k_attach,
        EntryKind::Dispersal.blob_aad_label(),
        blob.bytes(),
    )?;
    decode_root_pointer(&clear)
}
