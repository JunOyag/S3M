//! Rupture de confiance et liste noire — id `securite.blacklist-fraude`,
//! component `node` (Phase 5). Réf. spec : docs/05-securite/blacklist-fraude.md.
//!
//! Sur réponse PoS incorrecte (fraude ou corruption avérée), distincte d'un
//! timeout :
//! - **destruction locale immédiate** de toutes les données hébergées pour
//!   le partenaire P, toutes relations confondues — en bloc, par ses
//!   conteneurs dédiés (`PhysicalStore::remove_owner`) ; **aucun** avis ni
//!   tombstone adressé à P ;
//! - compte de troc avec P remis à zéro ;
//! - **réparation proactive immédiate** de tous les fragments confiés à P ;
//! - inscription **permanente** dans la liste noire locale
//!   (`node.BlacklistedPartner`), jamais diffusée, sérialisée dans le
//!   NodeManifest (restaurable depuis la seed).

use std::collections::BTreeMap;

use flatbuffers::FlatBufferBuilder;
use s3m_protocol::fb::node as fb;

use crate::tombstones::PartnerLedger;
use crate::volatility::Holder;
use crate::{Owner, OwnerType, PhysicalStore, StorageError};

/// Motif d'inscription d'un échec PoS.
pub const REASON_POS_INVALID: &str = "pos_invalid_response";

/// Liste noire locale, permanente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Blacklist {
    entries: BTreeMap<Vec<u8>, (u64, String)>,
}

impl Blacklist {
    /// Inscrit P (idempotent : la première date est conservée).
    pub fn add(&mut self, partner_node_id: &[u8], at: u64, reason: &str) {
        self.entries
            .entry(partner_node_id.to_vec())
            .or_insert((at, reason.to_owned()));
    }

    /// Tout nouveau troc avec un partenaire inscrit est refusé.
    pub fn is_blacklisted(&self, partner_node_id: &[u8]) -> bool {
        self.entries.contains_key(partner_node_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sérialise en vecteur de `node.BlacklistedPartner` (racine minimale,
    /// destinée à être embarquée dans le NodeManifest).
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let items: Vec<_> = self
            .entries
            .iter()
            .map(|(id, (at, reason))| {
                let id = fbb.create_vector(id);
                let r = fbb.create_string(reason);
                fb::BlacklistedPartner::create(
                    &mut fbb,
                    &fb::BlacklistedPartnerArgs {
                        partner_node_id: Some(id),
                        blacklisted_at: *at,
                        reason: Some(r),
                    },
                )
            })
            .collect();
        let v = fbb.create_vector(&items);
        let cfg = fb::NodeManifest::create(
            &mut fbb,
            &fb::NodeManifestArgs {
                blacklisted_partners: Some(v),
                ..Default::default()
            },
        );
        fb::finish_node_manifest_buffer(&mut fbb, cfg);
        fbb.finished_data().to_vec()
    }

    /// Relit la liste depuis un NodeManifest.
    pub fn decode(manifest: &[u8]) -> Option<Self> {
        let m = fb::root_as_node_manifest(manifest).ok()?;
        let mut b = Self::default();
        for e in m.blacklisted_partners().iter().flatten() {
            b.add(
                e.partner_node_id()?.bytes(),
                e.blacklisted_at(),
                e.reason().unwrap_or_default(),
            );
        }
        Some(b)
    }
}

/// Résultat d'une rupture pour fraude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rupture {
    /// Conteneurs de P effacés en bloc (tous ses blocs, tous volumes).
    pub destroyed_containers: usize,
    /// Fragments que P hébergeait pour nous : à réparer immédiatement
    /// (hors cycle quotidien), via `protocols.dispersion-transactionnelle`.
    pub immediate_repair: Vec<usize>,
}

/// Rupture bilatérale immédiate avec P après une réponse PoS incorrecte.
pub fn rupture(
    store: &mut PhysicalStore,
    ledger: &mut PartnerLedger,
    blacklist: &mut Blacklist,
    partner_node_id: &[u8],
    partner_id: u16,
    holders: &[Holder],
    now: u64,
) -> Result<Rupture, StorageError> {
    let owner = Owner::new(OwnerType::Partner, partner_node_id.to_vec())?;
    let destroyed_containers = store.remove_owner(&owner)?;
    *ledger = PartnerLedger::default();
    blacklist.add(partner_node_id, now, REASON_POS_INVALID);
    let immediate_repair = holders
        .iter()
        .filter(|h| h.partner == partner_id)
        .map(|h| h.index)
        .collect();
    Ok(Rupture {
        destroyed_containers,
        immediate_repair,
    })
}
