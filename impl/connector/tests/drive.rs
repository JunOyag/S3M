//! Moteur du lecteur monté (`protocols.acces-applicatif`,
//! `protocols.ecriture-differee`) sur un Nœud simulé en mémoire.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p2p_storage_connector::drive::*;
use p2p_storage_connector::fs::BlockHash;

#[derive(Default)]
struct MemNode {
    blocks: Mutex<HashMap<BlockHash, Vec<u8>>>,
    root: Mutex<BlockHash>,
}

impl BlockIo for MemNode {
    fn get(&self, h: &BlockHash) -> Option<Vec<u8>> {
        self.blocks.lock().unwrap().get(h).cloned()
    }
    fn put(&self, h: &BlockHash, frame: Vec<u8>) -> Result<(), String> {
        self.blocks.lock().unwrap().insert(*h, frame);
        Ok(())
    }
    fn commit(&self, base: &BlockHash, new: &BlockHash) -> Result<Option<BlockHash>, String> {
        let mut r = self.root.lock().unwrap();
        if *r != *base {
            return Ok(Some(*r));
        }
        *r = *new;
        Ok(None)
    }
}

fn workspace(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("p2p-drive-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn drive(node: &Arc<MemNode>, ws: &std::path::Path) -> Drive {
    Drive::open(node.clone(), [9; 32], ws.to_path_buf(), Arc::new(|| 1000)).unwrap()
}

fn names(d: &mut Drive, p: &str) -> Vec<String> {
    d.list(p).unwrap().into_iter().map(|(n, _)| n).collect()
}

#[test]
fn files_and_directories_survive_sync_and_are_read_back_from_the_node() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("basic");
    let mut d = drive(&node, &ws);
    assert!(names(&mut d, "/").is_empty());
    d.create("/docs", true).unwrap();
    d.create("/docs/a.txt", false).unwrap();
    d.write("/docs/a.txt", 0, b"bonjour").unwrap();
    d.write("/docs/a.txt", 3, b"SOIR").unwrap();
    assert_eq!(d.read("/docs/a.txt", 0, 100).unwrap(), b"bonSOIR");
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    d.create("/big.bin", false).unwrap();
    d.write("/big.bin", 0, &big).unwrap();
    assert_eq!(d.sync().unwrap(), 3);
    assert_eq!(d.pending(), 0);
    assert_eq!(*node.root.lock().unwrap(), d.root_hash());

    // Relecture par un lecteur rouvert, cache local vidé : tout vient du Nœud.
    drop(d);
    std::fs::remove_dir_all(ws.join("cache")).unwrap();
    let mut d = drive(&node, &ws);
    assert_eq!(names(&mut d, "/"), vec!["big.bin", "docs"]);
    assert_eq!(d.read("/docs/a.txt", 0, 100).unwrap(), b"bonSOIR");
    assert_eq!(
        d.read("/big.bin", 65_000, 1000).unwrap(),
        big[65_000..66_000]
    );
    let m = d.stat("/big.bin").unwrap().unwrap();
    assert_eq!((m.is_dir, m.size), (false, 200_000));
    assert!(d.stat("/docs").unwrap().unwrap().is_dir);
}

#[test]
fn rename_delete_and_nested_edits_are_copy_on_write() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("cow");
    let mut d = drive(&node, &ws);
    d.create("/a", true).unwrap();
    d.create("/a/b", true).unwrap();
    d.create("/a/b/f", false).unwrap();
    d.write("/a/b/f", 0, b"v1").unwrap();
    d.create("/x", false).unwrap();
    d.sync().unwrap();

    // Déplacement d'un répertoire distant non vide, puis modification dedans.
    d.rename("/a", "/z", false).unwrap();
    assert!(d.stat("/a").unwrap().is_none());
    assert_eq!(d.read("/z/b/f", 0, 10).unwrap(), b"v1");
    d.write("/z/b/f", 2, b"+").unwrap();
    assert!(matches!(d.remove("/z/b"), Err(DriveError::NotEmpty)));
    d.remove("/x").unwrap();
    assert!(matches!(d.create("/z", true), Err(DriveError::Exists)));
    d.sync().unwrap();

    std::fs::remove_dir_all(ws.join("cache")).unwrap();
    let mut d = drive(&node, &ws);
    assert_eq!(names(&mut d, "/"), vec!["z"]);
    assert_eq!(d.read("/z/b/f", 0, 10).unwrap(), b"v1+");
    d.set_size("/z/b/f", 1).unwrap();
    d.rename("/z/b/f", "/z/g", false).unwrap();
    assert_eq!(names(&mut d, "/z"), vec!["b", "g"]);
    d.sync().unwrap();
    assert_eq!(d.read("/z/g", 0, 10).unwrap(), b"v");
    assert!(names(&mut d, "/z/b").is_empty());
}

#[test]
fn concurrent_root_change_is_a_conflict_and_keeps_local_changes() {
    let node = Arc::new(MemNode::default());
    let ws = workspace("conflict");
    let mut d = drive(&node, &ws);
    d.create("/f", false).unwrap();
    *node.root.lock().unwrap() = [0xEE; 32];
    assert!(matches!(d.sync(), Err(DriveError::Conflict)));
    assert_eq!(d.conflict, Some([0xEE; 32]));
    assert_eq!(d.pending(), 1);
    // Journal persistant : les modifications survivent à un redémarrage.
    drop(d);
    let mut d = drive(&node, &ws);
    assert_eq!(d.pending(), 1);
    assert_eq!(names(&mut d, "/"), vec!["f"]);
}
