//! Mode dossier (`protocols.acces-applicatif#mode-dossier`), partie commune :
//! enregistrement par blocs, plan de mise à jour des fantômes, temps de calme.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use s3m_connector::drive::*;
use s3m_connector::folder_sync::*;
use s3m_connector::fs::BlockHash;

#[derive(Default)]
struct MemNode {
    blocks: Mutex<HashMap<BlockHash, Vec<u8>>>,
    root: Mutex<BlockHash>,
    puts: Mutex<usize>,
}

impl BlockIo for MemNode {
    fn get(&self, h: &BlockHash) -> Option<Vec<u8>> {
        self.blocks.lock().unwrap().get(h).cloned()
    }
    fn put(&self, h: &BlockHash, frame: Vec<u8>) -> Result<(), String> {
        *self.puts.lock().unwrap() += 1;
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

fn drive(name: &str) -> Drive {
    let ws = std::env::temp_dir().join(format!("p2p-folder-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    Drive::open(Arc::new(MemNode::default()), [9; 32], ws, Arc::new(|| 1000)).unwrap()
}

#[test]
fn local_file_is_stored_block_by_block() {
    let mut d = drive("apply");
    let mut content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    assert!(apply_local_file(&mut d, "/a.bin", &content).unwrap());
    assert_eq!(d.read("/a.bin", 0, content.len()).unwrap(), content);
    assert!(
        !apply_local_file(&mut d, "/a.bin", &content).unwrap(),
        "rien n'a changé"
    );
    // Un octet du 2e bloc, puis raccourci.
    content[70_000] ^= 0xff;
    assert!(apply_local_file(&mut d, "/a.bin", &content).unwrap());
    assert_eq!(d.read("/a.bin", 0, content.len()).unwrap(), content);
    content.truncate(10);
    assert!(apply_local_file(&mut d, "/a.bin", &content).unwrap());
    assert_eq!(d.stat("/a.bin").unwrap().unwrap().size, 10);
    d.create("/dir", true).unwrap();
    assert!(apply_local_file(&mut d, "/dir", b"x").is_err());
}

fn meta(is_dir: bool, size: u64, t: u64) -> Meta {
    Meta {
        is_dir,
        size,
        created_at: t,
        modified_at: t,
    }
}

fn local(name: &str, in_sync: bool, size: u64, t: u64) -> LocalEntry {
    LocalEntry {
        name: name.into(),
        is_dir: false,
        in_sync,
        size,
        modified_at: t,
    }
}

#[test]
fn refresh_plan_never_touches_unsaved_local_changes() {
    let remote = vec![
        ("Nouveau.txt".to_string(), meta(false, 3, 10)),
        ("Change.txt".to_string(), meta(false, 9, 20)),
        ("Pareil.txt".to_string(), meta(false, 5, 10)),
        ("Modifie.txt".to_string(), meta(false, 7, 30)),
        ("docs".to_string(), meta(true, 0, 10)),
    ];
    let local = vec![
        local("change.TXT", true, 5, 10),
        local("Pareil.txt", true, 5, 10),
        local("Modifie.txt", false, 1, 99),
        local("Supprime.txt", true, 1, 10),
        local("Brouillon.txt", false, 1, 10),
        LocalEntry {
            name: "docs".into(),
            is_dir: true,
            in_sync: true,
            size: 0,
            modified_at: 5,
        },
    ];
    let plan = plan_refresh(&remote, &local);
    assert_eq!(plan.create, vec!["Nouveau.txt".to_string()]);
    assert_eq!(plan.remove, vec!["Supprime.txt".to_string()]);
    assert_eq!(plan.update, vec!["change.TXT".to_string()]);
}

#[test]
fn changes_are_read_after_two_quiet_seconds() {
    let mut d = Debounce::default();
    d.touch("a", 0);
    d.touch("b", 500);
    assert!(d.due(1_999).is_empty());
    d.touch("a", 1_500);
    assert_eq!(d.due(2_600), vec!["b".to_string()]);
    assert_eq!(d.due(3_500), vec!["a".to_string()]);
    assert!(d.due(10_000).is_empty());
}
