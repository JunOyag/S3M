//! `s3m-node` — exécutable du Nœud (`deploiement.packaging`).
//!
//! ```text
//! s3m-node init <répertoire>   crée la configuration
//! s3m-node init <répertoire> --identite
//!                              crée aussi une identité neuve (node.seed), sans
//!                              assistant : Nœuds d'essai créés par script
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
        [config] => run(Path::new(config)).await,
        _ => Err(
            "usage : s3m-node init <répertoire> [--identite] | geoip-update <répertoire de données> | blacklist-clear <config.json> | <config.json>".into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("erreur : {e}");
        std::process::exit(1);
    }
}
