//! Sauvegarde du snapshot du NodeManifest — id
//! `deploiement.disaster-recovery` (partie node). Réf. spec :
//! docs/07-deploiement/disaster-recovery.md § Snapshot.
//!
//! À chaque cycle, si le contenu (Utilisateurs rattachés, comptes
//! partenaires, liste noire) a changé depuis le dernier snapshot et au plus
//! toutes les `MIN_INTERVAL_S` : chiffrement sur k blocs, dispersion comme
//! un stripe complet, nouveau `NodeSnapshotPointer` (publié par l'entrée
//! DHT Node), purge de l'ancien stripe après le délai de grâce.

use std::sync::Mutex;

use s3m_core::symmetric_suite::hash_sha256;
use s3m_protocol::dispersal::Id;
use s3m_protocol::snapshot::*;

use crate::dispersal_engine::{
    disperse, retire, DispersalState, EngineConfig, Fabric, PartnerTable,
};
use crate::exchange::NodeService;

/// Intervalle minimal entre deux snapshots.
pub const MIN_INTERVAL_S: u64 = 600;

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

/// Contenu courant du snapshot.
pub fn current_desc(
    service: &Mutex<NodeService>,
    state: &DispersalState,
    now: u64,
) -> SnapshotDesc {
    let s = service.lock().unwrap();
    let mut users: Vec<SnapUser> = s
        .users
        .iter()
        .map(|(id, u)| SnapUser {
            user_id: *id,
            salt: u.salt.clone(),
            quota_bytes: u.quota_bytes,
            attached_at: 0,
        })
        .collect();
    users.sort_by_key(|u| u.user_id);
    let mut partners: Vec<SnapPartner> = s
        .partners
        .iter()
        .map(|(id, p)| SnapPartner {
            node_id: *id,
            hosted_for_partner: p.ledger.hosted_for_partner,
            hosted_by_partner: p.ledger.hosted_by_partner,
            allowance: p.quota,
        })
        .collect();
    partners.sort_by_key(|p| p.node_id);
    let blacklist = state
        .upkeep
        .blacklist
        .iter()
        .filter_map(|(n, (at, why))| {
            let id: Id = hex::decode(n).ok()?.try_into().ok()?;
            Some((id, *at, why.clone()))
        })
        .collect();
    SnapshotDesc {
        node_id: s.node_id(),
        users,
        partners,
        blacklist,
        timestamp: now,
    }
}

/// Empreinte du contenu, horodatage exclu. Les soldes de troc varient à
/// chaque dépôt : seuls les solde accordés, la composition et la liste
/// noire déclenchent un nouveau snapshot.
fn digest(d: &SnapshotDesc) -> String {
    let mut d = d.clone();
    d.timestamp = 0;
    for p in &mut d.partners {
        p.hosted_for_partner = 0;
        p.hosted_by_partner = 0;
    }
    hex::encode(hash_sha256(&encode_manifest(&d)))
}

/// Disperse un nouveau snapshot si nécessaire ; rend vrai si le pointeur a
/// changé.
pub async fn run_snapshot(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    fabric: &dyn Fabric,
    cfg: &EngineConfig,
    now: u64,
) -> bool {
    let desc = current_desc(service, state, now);
    if desc.users.is_empty() && desc.partners.is_empty() {
        return false; // jamais un snapshot vide (installation neuve ou restauration ratée)
    }
    let dg = digest(&desc);
    let snap = &state.snapshot;
    if (snap.digest == dg && snap.pointer.is_some())
        || (snap.pointer.is_some() && now < snap.last_at + MIN_INTERVAL_S)
    {
        return false;
    }
    let priv_node = service.lock().unwrap().priv_node();
    let salt = random::<16>();
    let frames = match seal_snapshot(
        &priv_node,
        &salt,
        cfg.k,
        &encode_manifest(&desc),
        &mut random::<12>,
    ) {
        Ok(f) => f,
        Err(e) => {
            state.snapshot.last_error = Some(e.to_string());
            return false;
        }
    };
    let root_hash = hash_sha256(&frames[0]);
    let padding = vec![false; cfg.k];
    let mut retired = Vec::new();
    let rec = match disperse(
        service,
        fabric,
        cfg,
        &frames,
        &padding,
        Some(salt),
        &mut retired,
        now,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            state.snapshot.retired.extend(retired);
            state.snapshot.last_error = Some(e);
            return false;
        }
    };
    let reach = fabric.partners();
    let mut table = PartnerTable::default();
    let stripe = table.desc(&rec, cfg.k, &reach);
    let pointer = SnapshotPointer {
        root_hash,
        partners: table.list,
        salt,
        stripe,
    };
    let snap = &mut state.snapshot;
    if let Some(old) = snap.stripe.replace(rec) {
        retire(&old, &mut snap.retired, now);
    }
    snap.pointer = Some(hex::encode(encode_pointer(&pointer)));
    snap.digest = dg;
    snap.last_at = now;
    snap.last_error = None;
    true
}
