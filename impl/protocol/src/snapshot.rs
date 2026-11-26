//! Snapshot du NodeManifest — id `deploiement.disaster-recovery`, partie
//! commune, sans I/O. Réf. spec : docs/07-deploiement/disaster-recovery.md
//! § Snapshot.
//!
//! - Contenu : `NodeManifest` (Utilisateurs rattachés, comptes partenaires
//!   avec solde accordé, liste noire).
//! - Chiffrement : `u32be(len) ‖ NodeManifest` réparti sur les k blocs de
//!   données d'un stripe, bloc `i` sous `K_node_snapshot(sel, i)`.
//! - Pointeur : `NodeSnapshotPointer` (hash du bloc 0, partenaires, sel,
//!   stripe) chiffré sous `K_node_self` dans l'entrée Node.

use flatbuffers::FlatBufferBuilder;
use s3m_core::k_block::{open_block, seal_block, BLOCK_PLAINTEXT_LEN};
use s3m_core::k_node_self::{derive_k_node_self, derive_k_node_snapshot};
use s3m_core::version::CURRENT_HEADER;

use crate::dht::{open_blob, EntryKind};
use crate::dispersal::{
    partners_fb, partners_of, stripe_fb, stripe_of, CatalogError, Id, PartnerDesc, StripeDesc,
};
use crate::fb::{dht as fbd, node as fbn};

/// Utilisateur rattaché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapUser {
    pub user_id: Id,
    pub salt: Vec<u8>,
    pub quota_bytes: u64,
    pub attached_at: u64,
    /// Racine courante et son descripteur scellé (`crypto.k-self#k-root`) ;
    /// vides : inconnus.
    pub root: Vec<u8>,
    pub root_seal: Vec<u8>,
    /// 2FA (`securite.incidents-compromissions#2fa`) : secret (vide : aucun),
    /// empreintes des codes de secours (n × 32 o), dernier pas accepté.
    pub twofa_secret: Vec<u8>,
    pub twofa_recovery: Vec<u8>,
    pub twofa_last_step: u64,
    pub pending: Vec<SnapPending>,
}

/// Opération différée sauvegardée (`PendingUserOp`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapPending {
    pub id: u64,
    /// 0 : changement d'identité ; 1 : purge ; 2 : retrait du 2FA.
    pub kind: u8,
    pub new_user_id: Vec<u8>,
    pub new_salt: Vec<u8>,
    pub before: u64,
    pub created_at: u64,
    pub due_at: u64,
}

/// Compte partenaire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapPartner {
    pub node_id: Id,
    pub hosted_for_partner: u64,
    pub hosted_by_partner: u64,
    pub allowance: u64,
}

/// Contenu du snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDesc {
    pub node_id: Id,
    pub users: Vec<SnapUser>,
    pub partners: Vec<SnapPartner>,
    /// `(node_id, date, motif)`.
    pub blacklist: Vec<(Id, u64, String)>,
    pub timestamp: u64,
}

/// `NodeSnapshotPointer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPointer {
    pub root_hash: Id,
    pub partners: Vec<PartnerDesc>,
    pub salt: [u8; 16],
    pub stripe: StripeDesc,
}

fn id_of(v: Option<flatbuffers::Vector<'_, u8>>) -> Result<Id, CatalogError> {
    v.and_then(|x| x.bytes().try_into().ok())
        .ok_or(CatalogError::Format("identifiant de 32 o"))
}

/// Sérialise le `NodeManifest`.
pub fn encode_manifest(s: &SnapshotDesc) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let quotas: Vec<_> = s
        .users
        .iter()
        .map(|u| {
            let id = b.create_vector(&u.user_id);
            fbn::UserQuota::create(
                &mut b,
                &fbn::UserQuotaArgs {
                    user_id: Some(id),
                    quota_bytes: u.quota_bytes,
                },
            )
        })
        .collect();
    let quotas = b.create_vector(&quotas);
    let accounts: Vec<_> = s
        .partners
        .iter()
        .map(|p| {
            let id = b.create_vector(&p.node_id);
            fbn::PartnerAccount::create(
                &mut b,
                &fbn::PartnerAccountArgs {
                    partner_node_id: Some(id),
                    blocks_hosted_for_partner: p.hosted_for_partner,
                    blocks_hosted_by_partner: p.hosted_by_partner,
                    allowance_blocks: p.allowance,
                },
            )
        })
        .collect();
    let accounts = b.create_vector(&accounts);
    let config = fbn::NodeConfig::create(
        &mut b,
        &fbn::NodeConfigArgs {
            user_quotas: Some(quotas),
            partner_accounts: Some(accounts),
            ..Default::default()
        },
    );
    let users: Vec<_> = s
        .users
        .iter()
        .map(|u| {
            let id = b.create_vector(&u.user_id);
            let salt = b.create_vector(&u.salt);
            let root = (!u.root.is_empty()).then(|| b.create_vector(&u.root));
            let seal = (!u.root_seal.is_empty()).then(|| b.create_vector(&u.root_seal));
            let tf = (!u.twofa_secret.is_empty()).then(|| b.create_vector(&u.twofa_secret));
            let tr = (!u.twofa_recovery.is_empty()).then(|| b.create_vector(&u.twofa_recovery));
            let ops: Vec<_> = u
                .pending
                .iter()
                .map(|p| {
                    let nu = (!p.new_user_id.is_empty()).then(|| b.create_vector(&p.new_user_id));
                    let ns = (!p.new_salt.is_empty()).then(|| b.create_vector(&p.new_salt));
                    fbn::PendingUserOp::create(
                        &mut b,
                        &fbn::PendingUserOpArgs {
                            id: p.id,
                            kind: p.kind,
                            new_user_id: nu,
                            new_salt: ns,
                            before: p.before,
                            created_at: p.created_at,
                            due_at: p.due_at,
                        },
                    )
                })
                .collect();
            let ops = (!ops.is_empty()).then(|| b.create_vector(&ops));
            fbn::AttachedUser::create(
                &mut b,
                &fbn::AttachedUserArgs {
                    user_id: Some(id),
                    salt: Some(salt),
                    attached_at: u.attached_at,
                    root,
                    root_seal: seal,
                    twofa_secret: tf,
                    twofa_recovery: tr,
                    twofa_last_step: u.twofa_last_step,
                    pending_ops: ops,
                    ..Default::default()
                },
            )
        })
        .collect();
    let users = b.create_vector(&users);
    let black: Vec<_> = s
        .blacklist
        .iter()
        .map(|(n, at, why)| {
            let id = b.create_vector(n);
            let r = b.create_string(why);
            fbn::BlacklistedPartner::create(
                &mut b,
                &fbn::BlacklistedPartnerArgs {
                    partner_node_id: Some(id),
                    blacklisted_at: *at,
                    reason: Some(r),
                },
            )
        })
        .collect();
    let black = b.create_vector(&black);
    let node = b.create_vector(&s.node_id);
    let m = fbn::NodeManifest::create(
        &mut b,
        &fbn::NodeManifestArgs {
            node_id: Some(node),
            config: Some(config),
            attached_users: Some(users),
            blacklisted_partners: Some(black),
            containers: None,
            timestamp: s.timestamp,
            schema_version: 1,
        },
    );
    fbn::finish_node_manifest_buffer(&mut b, m);
    b.finished_data().to_vec()
}

pub fn decode_manifest(buf: &[u8]) -> Result<SnapshotDesc, CatalogError> {
    let m = fbn::root_as_node_manifest(buf).map_err(|_| CatalogError::Format("NodeManifest"))?;
    let quotas: Vec<(Id, u64)> = m
        .config()
        .and_then(|c| c.user_quotas())
        .map(|v| {
            v.iter()
                .filter_map(|q| Some((id_of(q.user_id()).ok()?, q.quota_bytes())))
                .collect()
        })
        .unwrap_or_default();
    let users = m
        .attached_users()
        .map(|v| {
            v.iter()
                .map(|u| {
                    let user_id = id_of(u.user_id())?;
                    Ok(SnapUser {
                        user_id,
                        salt: u.salt().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                        quota_bytes: quotas
                            .iter()
                            .find(|(i, _)| *i == user_id)
                            .map(|q| q.1)
                            .unwrap_or(0),
                        attached_at: u.attached_at(),
                        root: u.root().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                        root_seal: u.root_seal().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                        twofa_secret: u.twofa_secret().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                        twofa_recovery: u.twofa_recovery().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                        twofa_last_step: u.twofa_last_step(),
                        pending: u
                            .pending_ops()
                            .map(|v| {
                                v.iter()
                                    .map(|p| SnapPending {
                                        id: p.id(),
                                        kind: p.kind(),
                                        new_user_id: p.new_user_id().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                                        new_salt: p.new_salt().map(|s| s.bytes().to_vec()).unwrap_or_default(),
                                        before: p.before(),
                                        created_at: p.created_at(),
                                        due_at: p.due_at(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>, CatalogError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let partners = m
        .config()
        .and_then(|c| c.partner_accounts())
        .map(|v| {
            v.iter()
                .map(|p| {
                    Ok(SnapPartner {
                        node_id: id_of(p.partner_node_id())?,
                        hosted_for_partner: p.blocks_hosted_for_partner(),
                        hosted_by_partner: p.blocks_hosted_by_partner(),
                        allowance: p.allowance_blocks(),
                    })
                })
                .collect::<Result<Vec<_>, CatalogError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let blacklist = m
        .blacklisted_partners()
        .map(|v| {
            v.iter()
                .map(|e| {
                    Ok((
                        id_of(e.partner_node_id())?,
                        e.blacklisted_at(),
                        e.reason().unwrap_or_default().to_string(),
                    ))
                })
                .collect::<Result<Vec<_>, CatalogError>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(SnapshotDesc {
        node_id: id_of(m.node_id())?,
        users,
        partners,
        blacklist,
        timestamp: m.timestamp(),
    })
}

/// Chiffre le manifeste sur `k` blocs de 65 536 o.
pub fn seal_snapshot(
    priv_node: &[u8; 32],
    salt: &[u8; 16],
    k: usize,
    manifest: &[u8],
    nonce: &mut dyn FnMut() -> [u8; 12],
) -> Result<Vec<Vec<u8>>, CatalogError> {
    let mut clear = (manifest.len() as u32).to_be_bytes().to_vec();
    clear.extend_from_slice(manifest);
    if clear.len() > k * BLOCK_PLAINTEXT_LEN {
        return Err(CatalogError::Format(
            "snapshot trop volumineux pour un stripe",
        ));
    }
    clear.resize(k * BLOCK_PLAINTEXT_LEN, 0);
    clear
        .chunks(BLOCK_PLAINTEXT_LEN)
        .enumerate()
        .map(|(i, chunk)| {
            let key = derive_k_node_snapshot(priv_node, salt, i as u32)?;
            Ok(seal_block(&key, &CURRENT_HEADER, &nonce(), chunk)?)
        })
        .collect()
}

/// Déchiffre les k blocs du snapshot ; rend le `NodeManifest` sérialisé.
pub fn open_snapshot(
    priv_node: &[u8; 32],
    salt: &[u8; 16],
    frames: &[Vec<u8>],
) -> Result<Vec<u8>, CatalogError> {
    let mut clear = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let key = derive_k_node_snapshot(priv_node, salt, i as u32)?;
        clear.extend_from_slice(&open_block(&key, &CURRENT_HEADER, f)?);
    }
    let n = u32::from_be_bytes(
        clear
            .get(..4)
            .ok_or(CatalogError::Format("longueur"))?
            .try_into()
            .unwrap(),
    ) as usize;
    clear
        .get(4..4 + n)
        .map(|s| s.to_vec())
        .ok_or(CatalogError::Format("snapshot tronqué"))
}

/// Sérialise le `NodeSnapshotPointer`.
pub fn encode_pointer(p: &SnapshotPointer) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let h = b.create_vector(&p.root_hash);
    let partners = partners_fb(&mut b, &p.partners);
    let salt = b.create_vector(&p.salt);
    let stripe = stripe_fb(&mut b, &p.stripe);
    let o = fbd::NodeSnapshotPointer::create(
        &mut b,
        &fbd::NodeSnapshotPointerArgs {
            node_snapshot_root_hash: Some(h),
            node_snapshot_root_partners: Some(partners),
            node_snapshot_root_salt: Some(salt),
            node_snapshot_root_stripe: Some(stripe),
        },
    );
    b.finish_minimal(o);
    b.finished_data().to_vec()
}

pub fn decode_pointer(buf: &[u8]) -> Result<SnapshotPointer, CatalogError> {
    let p = flatbuffers::root::<fbd::NodeSnapshotPointer>(buf)
        .map_err(|_| CatalogError::Format("NodeSnapshotPointer"))?;
    Ok(SnapshotPointer {
        root_hash: id_of(p.node_snapshot_root_hash())?,
        partners: partners_of(p.node_snapshot_root_partners())?,
        salt: p
            .node_snapshot_root_salt()
            .and_then(|v| v.bytes().try_into().ok())
            .ok_or(CatalogError::Format("node_snapshot_root_salt"))?,
        stripe: stripe_of(
            p.node_snapshot_root_stripe()
                .ok_or(CatalogError::Format("node_snapshot_root_stripe"))?,
        )?,
    })
}

/// Pointeur de snapshot de l'entrée Node (enveloppe déjà vérifiée) ;
/// `Ok(None)` si l'entrée n'en porte pas.
pub fn open_node_entry_pointer(
    priv_node: &[u8; 32],
    envelope: &[u8],
) -> Result<Option<SnapshotPointer>, CatalogError> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope)
        .map_err(|_| CatalogError::Format("DhtEnvelope"))?;
    let e = fbd::root_as_node_entry(
        env.payload()
            .ok_or(CatalogError::Format("payload"))?
            .bytes(),
    )
    .map_err(|_| CatalogError::Format("NodeEntry"))?;
    let Some(blob) = e.snapshot_ciphertext() else {
        return Ok(None);
    };
    let clear = open_blob(
        &derive_k_node_self(priv_node)?,
        EntryKind::Node.blob_aad_label(),
        blob.bytes(),
    )?;
    Ok(Some(decode_pointer(&clear)?))
}
