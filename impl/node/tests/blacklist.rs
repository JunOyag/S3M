//! Invariants de `securite.blacklist-fraude` (stockage physique réel).

use std::path::PathBuf;

use s3m_node::blacklist::*;
use s3m_node::tombstones::PartnerLedger;
use s3m_node::volatility::Holder;
use s3m_node::{Owner, OwnerType, PhysicalStore, VolumeConfig};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store() -> (Temp, PhysicalStore) {
    let dir = std::env::temp_dir().join(format!(
        "p2p-blacklist-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vols = vec![VolumeConfig {
        volume_id: 0,
        mount_path: dir.join("vol0"),
        max_capacity_bytes: 64 * 1024 * 1024,
    }];
    let s = PhysicalStore::open(dir.join("node.sqlite"), vols).unwrap();
    (Temp(dir), s)
}

const P: &[u8] = &[0xAA; 32];
const Q: &[u8] = &[0xBB; 32];

/// Fraude de P : destruction de toutes ses données (et d'elles seules),
/// compte remis à zéro, réparation immédiate des fragments qu'il hébergeait,
/// inscription permanente ; aucun avis n'est produit.
#[test]
fn fraud_destroys_all_data_of_the_partner_and_blacklists_it() {
    let (_t, mut s) = store();
    let p = Owner::new(OwnerType::Partner, P.to_vec()).unwrap();
    let q = Owner::new(OwnerType::Partner, Q.to_vec()).unwrap();
    for i in 0..3u8 {
        s.write_block(&p, &[i; 32], &vec![i; 65_536]).unwrap();
    }
    s.write_block(&q, &[9; 32], &vec![9; 65_536]).unwrap();
    let mut ledger = PartnerLedger {
        hosted_for_partner: 5,
        hosted_by_partner: 3,
        last_tombstone_at: 0,
    };
    let mut bl = Blacklist::default();
    let holders = [
        Holder {
            index: 4,
            partner: 7,
            last_seen: 0,
        },
        Holder {
            index: 5,
            partner: 8,
            last_seen: 0,
        },
        Holder {
            index: 9,
            partner: 7,
            last_seen: 0,
        },
    ];
    let r = rupture(&mut s, &mut ledger, &mut bl, P, 7, &holders, 1_000).unwrap();
    assert_eq!(
        r.destroyed_containers, 1,
        "les 3 blocs de P sont dans un seul conteneur dédié"
    );
    for i in 0..3u8 {
        assert!(s.location(&[i; 32]).unwrap().is_none());
    }
    assert_eq!(r.immediate_repair, vec![4, 9]);
    assert_eq!(ledger, PartnerLedger::default());
    assert!(bl.is_blacklisted(P));
    assert!(!bl.is_blacklisted(Q));
    assert!(
        s.location(&[9; 32]).unwrap().is_some(),
        "les données de Q sont intactes"
    );
    assert!(s.location(&[0; 32]).unwrap().is_none());
}

/// Liste noire permanente : idempotente, sérialisée dans le NodeManifest et
/// relue à l'identique (restauration depuis la seed).
#[test]
fn blacklist_is_permanent_and_survives_manifest_roundtrip() {
    let mut bl = Blacklist::default();
    bl.add(P, 100, REASON_POS_INVALID);
    bl.add(P, 200, "autre");
    bl.add(Q, 150, REASON_POS_INVALID);
    assert_eq!(bl.len(), 2);
    let back = Blacklist::decode(&bl.encode()).unwrap();
    assert_eq!(back, bl);
}
