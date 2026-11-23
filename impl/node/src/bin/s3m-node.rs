//! `s3m-node` — exécutable du Nœud (`deploiement.packaging`).
//!
//! ```text
//! s3m-node init <répertoire>   crée la configuration
//! s3m-node init <répertoire> --identite
//!                              crée aussi une identité neuve (node.seed), sans
//!                              assistant : Nœuds d'essai créés par script
//! s3m-node essais-reconcilier <racine>
//!                              Nœuds d'essai arrêtés de <racine>\node* :
//!                              fragments introuvables chez leur détenteur
//!                              oubliés, listes noires vidées
//! s3m-node blacklist-clear <config.json>
//!                              vide la liste noire (Nœud arrêté)
//! s3m-node <config.json>       démarre le Nœud (premier lancement : identité
//!                              temporaire et assistant, deploiement.appairage-admin)
//! ```

use std::path::{Path, PathBuf};

use s3m_node::daemon::{start_with, Config, VolumeSpec, ASSETS};
use s3m_node::local_http::Switch;

fn init(dir: &Path, identity: bool) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    if dir.join("node.json").exists() {
        return Err(format!("{} existe déjà", dir.join("node.json").display()).into());
    }
    let config = Config {
        seed_file: "node.seed".into(),
        identity_index: 0,
        data_dir: "data".into(),
        volumes: vec![VolumeSpec {
            volume_id: 1,
            mount_path: PathBuf::from("data/volume1"),
            max_capacity_bytes: 100 << 30,
            draining: false,
        }],
        listen: s3m_node::daemon::default_listen(),
        dht_listen: None,
        blocks_listen: None,
        bootstrap: vec![],
        api_port: 8765,
        dispersal: Default::default(),
        upkeep: Default::default(),
        public_ip: None,
        public_port: None,
        partnering: Default::default(),
        partner_policy: Default::default(),
        attach: Default::default(),
        record_user_ips: true,
        upnp: true,
        relay_server: true,
        relay_limits: Default::default(),
        relays: vec![],
        force_relay: false,
        mdns: true,
        remote_admin: true,
        admin_listen: s3m_node::daemon::default_admin_listen(),
        admin_totp_serial: 0,
        source: None,
    };
    std::fs::write(
        dir.join("node.json"),
        serde_json::to_string_pretty(&config)?,
    )?;
    if identity {
        // Identité neuve : la phrase reste dans node.seed (Nœud d'essai).
        let phrase = s3m_node::daemon::generate_mnemonic()?;
        std::fs::write(dir.join("node.seed"), phrase)?;
        println!(
            "Identité neuve écrite dans {}",
            dir.join("node.seed").display()
        );
    } else {
        println!("Au premier démarrage, le Nœud propose une nouvelle identité ou la restauration d'une identité existante.");
    }
    println!("Configuration : {}", dir.join("node.json").display());
    Ok(())
}

/// Variable posée sur le processus relancé par « Redémarrer le Nœud ».
const RESTARTED_ENV: &str = "S3M_NODE_RESTARTED";

async fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let c = Config::load(path)?;
    let switch = Switch::new();
    std::fs::create_dir_all(&c.data_dir)?;
    // Relancé : l'ancien processus libère ses ports en quittant.
    let restarted = std::env::var_os(RESTARTED_ENV).is_some();
    let mut tries = 0;
    let url = loop {
        match switch.serve(c.api_port, ASSETS, Some(&c.data_dir)).await {
            Ok(u) => break u,
            Err(_) if restarted && tries < 60 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("Dashboard : {url}");
    if !c.seed_file.exists() {
        s3m_node::setup::run(&c, &switch).await?;
    }
    let shared = match start_with(c, &switch).await {
        Ok(s) => s,
        Err(e) => {
            // Le tableau de bord reste ouvert pour expliquer l'arrêt.
            eprintln!("erreur : {e}");
            eprintln!("Tableau de bord : {url} (Ctrl+C pour quitter)");
            let _ = tokio::signal::ctrl_c().await;
            return Err(e.into());
        }
    };
    println!("Nœud {} démarré.", shared.peer_id);
    if let Some(a) = &shared.blocks_addr {
        println!("Échange de blocs : {a}");
    }
    let restart = tokio::select! {
        _ = tokio::signal::ctrl_c() => false,
        _ = shared.restart.notified() => true,
    };
    if restart {
        // Laisse partir la réponse au dashboard.
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    }
    let _ = s3m_node::daemon::save(&shared);
    if let Ok(d) =
        tokio::time::timeout(std::time::Duration::from_secs(20), shared.dispersal.lock()).await
    {
        let _ = s3m_node::daemon::save_dispersal(&shared.config, &d);
    }
    if restart {
        relaunch(path)?;
        std::process::exit(0);
    }
    Ok(())
}

/// Relance l'exécutable avec la même configuration (sorties héritées) ;
/// `node.pid` à côté de la configuration (Nœuds d'essai) suit le nouveau
/// processus.
fn relaunch(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let child = std::process::Command::new(std::env::current_exe()?)
        .arg(config)
        .env(RESTARTED_ENV, "1")
        .spawn()?;
    println!("Redémarrage : nouveau processus {}", child.id());
    if let Some(pid) = config.parent().map(|d| d.join("node.pid")) {
        if pid.exists() {
            let _ = std::fs::write(pid, child.id().to_string());
        }
    }
    Ok(())
}

/// Vide la liste noire d'un Nœud arrêté (un Nœud en marche réécrirait son
/// état par-dessus).
fn blacklist_clear(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let c = Config::load(config)?;
    let path = c.data_dir.join("dispersal.json");
    if !path.exists() {
        println!("Liste noire vide (aucun état de dispersion).");
        return Ok(());
    }
    let mut st: s3m_node::dispersal_engine::DispersalState =
        serde_json::from_slice(&std::fs::read(&path)?)?;
    let n = st.clear_blacklist();
    s3m_node::daemon::save_dispersal(&c, &st)?;
    println!("{n} Nœud(s) retiré(s) de la liste noire.");
    Ok(())
}

/// Remise en cohérence des Nœuds d'essai (tous arrêtés, même machine) :
/// chaque fragment que l'un croit chez un autre est vérifié dans le
/// stockage de ce dernier ; introuvable, il est oublié (la réparation le
/// replace). Les listes noires sont ensuite vidées.
fn reconcile(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use s3m_node::dispersal_engine::DispersalState;
    use std::collections::{HashMap, HashSet};
    struct Node {
        name: String,
        config: Config,
        id: String,
    }
    let mut nodes = Vec::new();
    for e in std::fs::read_dir(root)?.flatten() {
        let cfg = e.path().join("node.json");
        if !cfg.exists() {
            continue;
        }
        let config = Config::load(&cfg)?;
        let Ok(phrase) = std::fs::read_to_string(&config.seed_file) else {
            continue;
        };
        let seed = s3m_node::daemon::node_seed_from_mnemonic(&phrase, config.identity_index)?;
        let id = hex::encode(s3m_core::keys::derive_sig_pub_user(&seed));
        nodes.push(Node {
            name: e.file_name().to_string_lossy().into_owned(),
            config,
            id,
        });
    }
    // Fragments réellement hébergés : détenteur → {(hash, propriétaire)}.
    let mut held: HashMap<String, HashSet<(String, String)>> = HashMap::new();
    for n in &nodes {
        let db = n.config.data_dir.join("store.sqlite");
        let mut set = HashSet::new();
        if db.exists() {
            let c = rusqlite::Connection::open_with_flags(
                &db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let mut q = c.prepare(
                "SELECT l.block_hash, c.owner_id FROM block_locations l \
                 JOIN containers c ON c.container_id = l.container_id WHERE c.owner_type = 1",
            )?;
            let rows = q.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for r in rows.flatten() {
                set.insert((hex::encode(r.0), hex::encode(r.1)));
            }
        }
        held.insert(n.id.clone(), set);
    }
    for n in &nodes {
        let path = n.config.data_dir.join("dispersal.json");
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let mut st: DispersalState = serde_json::from_slice(&bytes)?;
        let mut forgotten = 0;
        let stripes = st
            .users
            .values_mut()
            .flat_map(|u| u.stripes.iter_mut().chain(u.index.iter_mut()))
            .chain(st.snapshot.stripe.iter_mut());
        for s in stripes {
            let before = s.parity.len();
            s.parity.retain(|(_, h, p)| match held.get(p) {
                // Détenteur hors des Nœuds d'essai : laissé tel quel.
                None => true,
                Some(set) => set.contains(&(h.clone(), n.id.clone())),
            });
            forgotten += before - s.parity.len();
        }
        let cleared = st.clear_blacklist();
        s3m_node::daemon::save_dispersal(&n.config, &st)?;
        println!(
            "{} : {forgotten} fragment(s) introuvable(s) oublié(s), {cleared} Nœud(s) retiré(s) de la liste noire",
            n.name
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<(), Box<dyn std::error::Error>> = match args.as_slice() {
        [cmd, dir] if cmd == "init" => init(Path::new(dir), false),
        [cmd, dir, flag] if cmd == "init" && flag == "--identite" => init(Path::new(dir), true),
        [cmd, dir] if cmd == "geoip-update" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match s3m_node::geo::update_with_fallback(Path::new(dir), now) {
                Ok(m) => {
                    println!("Géolocalisation : {m}");
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        }
        [cmd, config] if cmd == "blacklist-clear" => blacklist_clear(Path::new(config)),
        [cmd, root] if cmd == "essais-reconcilier" => reconcile(Path::new(root)),
        [config] => run(Path::new(config)).await,
        _ => Err(
            "usage : s3m-node init <répertoire> [--identite] | geoip-update <répertoire de données> | blacklist-clear <config.json> | essais-reconcilier <racine> | <config.json>".into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("erreur : {e}");
        std::process::exit(1);
    }
}
