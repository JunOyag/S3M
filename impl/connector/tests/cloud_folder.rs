//! Mode dossier Windows (`protocols.acces-applicatif#mode-dossier`) : vrai
//! dossier synchronisé Cloud Files dans un répertoire temporaire, sur un
//! Nœud simulé en mémoire.
#![cfg(all(windows, feature = "folder"))]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use s3m_connector::drive::*;
use s3m_connector::fs::BlockHash;

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

fn shell(cmd: &[&str], paths: &[&Path]) -> String {
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .args(cmd)
        .args(paths)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let t = Instant::now();
    while !ok() {
        assert!(
            t.elapsed() < Duration::from_secs(15),
            "délai dépassé : {what}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn folder_shows_placeholders_hydrates_and_records_local_changes() {
    let base = std::env::temp_dir().join(format!("p2p-cloud-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("S3m");
    let node = Arc::new(MemNode::default());
    let mut d = Drive::open(node, [9; 32], base.join("ws"), Arc::new(|| 1_000)).unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    d.create("/docs", true).unwrap();
    d.create("/docs/a.txt", false).unwrap();
    d.write("/docs/a.txt", 0, b"bonjour").unwrap();
    d.create("/b.bin", false).unwrap();
    d.write("/b.bin", 0, &big).unwrap();
    let drive = Arc::new(Mutex::new(d));
    let writes = Arc::new(Mutex::new(Vec::<String>::new()));
    let w = writes.clone();
    let stop = s3m_connector::cloud_folder::start(
        &root,
        drive.clone(),
        Arc::new(move |p, _| w.lock().unwrap().push(p.to_string())),
    )
    .unwrap();

    // Fantômes fournis à l'ouverture, contenu à la lecture.
    let mut names: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["b.bin", "docs"]);
    assert_eq!(
        std::fs::metadata(root.join("b.bin")).unwrap().len(),
        big.len() as u64
    );
    assert_eq!(std::fs::read(root.join("b.bin")).unwrap(), big);
    // Windows ne sollicite pas le fournisseur pour ses propres opérations
    // (ouverture d'un dossier, renommage, suppression) : elles passent par
    // un autre processus, comme l'Explorateur.
    let out = shell(&["dir", "/B"], &[&root.join("docs")]);
    assert_eq!(out.trim(), "a.txt");
    assert_eq!(
        std::fs::read(root.join("docs").join("a.txt")).unwrap(),
        b"bonjour"
    );

    // Fichier créé localement : enregistré après le temps de calme.
    std::fs::write(root.join("nouveau.txt"), b"salut").unwrap();
    let stored = |p: &str| drive.lock().unwrap().stat(p).ok().flatten().is_some();
    wait("enregistrement de nouveau.txt", || stored("/nouveau.txt"));
    assert_eq!(
        drive.lock().unwrap().read("/nouveau.txt", 0, 100).unwrap(),
        b"salut"
    );

    // Fichier existant modifié localement.
    std::fs::write(root.join("docs").join("a.txt"), b"bonsoir !").unwrap();
    wait("modification de a.txt", || {
        drive.lock().unwrap().read("/docs/a.txt", 0, 100).unwrap() == b"bonsoir !"
    });

    // Renommage et suppression.
    shell(
        &["ren"],
        &[&root.join("nouveau.txt"), Path::new("renomme.txt")],
    );
    wait("renommage", || {
        stored("/renomme.txt") && !stored("/nouveau.txt")
    });
    shell(&["del", "/Q"], &[&root.join("b.bin")]);
    wait("suppression", || !stored("/b.bin"));
    assert!(!writes.lock().unwrap().is_empty());

    // Changement distant (nouvelle racine) : fantôme créé dans un dossier ouvert.
    {
        let mut d = drive.lock().unwrap();
        d.create("/docs/distant.txt", false).unwrap();
        d.write("/docs/distant.txt", 0, b"d'ailleurs").unwrap();
        d.sync().unwrap();
    }
    wait("fantôme distant", || {
        root.join("docs").join("distant.txt").exists()
    });
    assert_eq!(
        std::fs::read(root.join("docs").join("distant.txt")).unwrap(),
        b"d'ailleurs"
    );

    // Libération d'espace : fichiers téléchargés et à jour vidés du disque,
    // toujours là, relus à l'ouverture ; rien de récent avec un délai.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let recall = |p: &Path| {
        use std::os::windows::fs::MetadataExt;
        std::fs::metadata(p).unwrap().file_attributes() & 0x0040_0000 != 0
    };
    let distant = root.join("docs").join("distant.txt");
    assert!(!recall(&distant), "téléchargé par la lecture");
    // Dates du fichier = celles de son auteur : le téléchargement récent
    // compte (relevé du dossier synchronisé).
    let recent: std::collections::HashMap<String, u64> = [
        ("/docs/distant.txt".to_string(), now),
        ("/docs/a.txt".to_string(), now),
        ("/renomme.txt".to_string(), now),
    ]
    .into();
    let none = s3m_connector::cloud_folder::free_space(&root, &root, Some(86_400), now, &recent);
    assert!(!recall(&distant), "téléchargé récemment : gardé ({none:?})");
    let freed = s3m_connector::cloud_folder::free_space(&root, &root, None, now, &recent);
    assert!(freed.files >= 1 && freed.bytes >= 10, "{freed:?}");
    assert!(recall(&distant), "contenu retiré du disque");
    assert_eq!(std::fs::read(&distant).unwrap(), b"d'ailleurs");

    // Arrêt sans quitter le processus : fils terminés, dossier déconnecté,
    // lecteur relâché.
    assert!(Arc::strong_count(&drive) > 1);
    stop();
    assert_eq!(
        Arc::strong_count(&drive),
        1,
        "lecteur relâché par le dossier"
    );

    let _ = s3m_connector::cloud_folder::unregister(&root);
    let _ = std::fs::remove_dir_all(&base);
    assert!(!Path::new(&root).join("b.bin").exists());
}
