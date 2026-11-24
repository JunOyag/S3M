//! Entrées de l'annuaire gardées sur disque (`network.dht-directory`) : un
//! redémarrage, même de tout le réseau, ne les perd pas.

use std::time::{Duration, Instant};

use libp2p::kad::store::{MemoryStore, RecordStore};
use libp2p::kad::{Record, RecordKey};
use libp2p::PeerId;
use s3m_node::dht_directory::{load_records, save_records};

#[test]
fn records_survive_a_restart_until_they_expire() {
    let dir = std::env::temp_dir().join(format!("s3m-dht-records-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dht_records.json");
    let now = 1_800_000_000;
    let mut a = MemoryStore::new(PeerId::random());
    let mut keep = Record::new(RecordKey::new(&b"noeud"), vec![1, 2, 3]);
    keep.expires = Some(Instant::now() + Duration::from_secs(1_000));
    let mut old = Record::new(RecordKey::new(&b"vieux"), vec![9]);
    old.expires = Some(Instant::now() + Duration::from_secs(10));
    a.put(keep).unwrap();
    a.put(old).unwrap();
    save_records(&mut a, &path, now);

    // Redémarrage 100 s plus tard : l'entrée échue n'est pas rechargée.
    let mut b = MemoryStore::new(PeerId::random());
    assert_eq!(load_records(&mut b, &path, now + 100), 1);
    let r = b.get(&RecordKey::new(&b"noeud")).unwrap();
    assert_eq!(r.value, vec![1, 2, 3]);
    let left = r.expires.unwrap().saturating_duration_since(Instant::now()).as_secs();
    assert!((890..=900).contains(&left), "{left}");
    assert!(b.get(&RecordKey::new(&b"vieux")).is_none());
    // Fichier absent ou illisible : rien.
    std::fs::write(&path, b"pas du json").unwrap();
    assert_eq!(load_records(&mut MemoryStore::new(PeerId::random()), &path, now), 0);
    let _ = std::fs::remove_dir_all(&dir);
}
