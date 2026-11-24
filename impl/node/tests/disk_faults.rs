//! Défaillances matérielles des volumes signalées à l'opérateur
//! (`securite.integrite-autoreparation#defaillance`).

use std::path::PathBuf;

use s3m_core::symmetric_suite::hash_sha256;
use s3m_node::{FaultKind, Owner, OwnerType, PhysicalStore, VolumeConfig};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp(name: &str) -> Temp {
    let dir = std::env::temp_dir().join(format!("p2p-fault-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Temp(dir)
}

fn open(dir: &std::path::Path) -> PhysicalStore {
    PhysicalStore::open(
        dir.join("node.sqlite"),
        vec![VolumeConfig {
            volume_id: 3,
            mount_path: dir.join("disque").join("vol"),
            max_capacity_bytes: 16 * 1024 * 1024,
        }],
    )
    .unwrap()
}

fn owner() -> Owner {
    Owner::new(OwnerType::AttachedUser, vec![1; 32]).unwrap()
}

/// Disque débranché : le Nœud démarre, l'alerte dit de le rebrancher ou de
/// modifier le point de montage, et rien n'est oublié ; elle disparaît au
/// retour du disque.
#[test]
fn an_unplugged_disk_is_reported_without_forgetting_its_blocks() {
    let t = temp("unplug");
    let b = vec![5u8; 65_536];
    let h = hash_sha256(&b);
    {
        let mut s = open(&t.0);
        s.write_block(&owner(), &h, &b).unwrap();
    }
    std::fs::rename(t.0.join("disque"), t.0.join("ailleurs")).unwrap();
    let s = open(&t.0);
    let f = s.faults();
    assert_eq!(f.len(), 1);
    assert_eq!((f[0].volume_id, f[0].kind), (3, FaultKind::Unreachable));
    assert!(f[0].advice().contains("modifiez le point de montage du volume 3"));
    assert!(s.missing_containers().is_empty(), "rien n'est oublié");
    std::fs::rename(t.0.join("ailleurs"), t.0.join("disque")).unwrap();
    s.check_volumes();
    assert!(s.faults().is_empty());
    assert_eq!(s.read_block(&h).unwrap().unwrap(), b);
}

/// Dossier du volume effacé, disque présent : le Nœud démarre et laisse la
/// maintenance reconstruire, sans alerte matérielle.
#[test]
fn a_deleted_volume_folder_does_not_prevent_startup() {
    let t = temp("deleted");
    let b = vec![6u8; 65_536];
    {
        let mut s = open(&t.0);
        s.write_block(&owner(), &hash_sha256(&b), &b).unwrap();
    }
    std::fs::remove_dir_all(t.0.join("disque").join("vol")).unwrap();
    let s = open(&t.0);
    assert_eq!(s.missing_containers().len(), 1);
    assert!(s.faults().is_empty());
}

/// Bloc altéré relu : alerte « disque défectueux », effacée à la demande
/// de l'opérateur.
#[test]
fn a_corrupted_block_raises_a_replace_the_disk_alert() {
    let t = temp("corrupt");
    let mut s = open(&t.0);
    let b = vec![7u8; 65_536];
    let h = hash_sha256(&b);
    s.write_block(&owner(), &h, &b).unwrap();
    s.note_corrupted(&h);
    s.note_corrupted(&h);
    let f = s.faults();
    assert_eq!((f[0].kind, f[0].count), (FaultKind::Corrupted, 2));
    assert!(f[0].advice().contains("Remplacez le disque défectueux"));
    s.clear_faults(3);
    assert!(s.faults().is_empty());
}
