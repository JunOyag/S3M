//! `p2p-storage-node` — exécutable du Nœud (`deploiement.packaging`).
//!
//! ```text
//! p2p-storage-node init <répertoire>   crée phrase de récupération + config
//! p2p-storage-node <config.json>       démarre le Nœud
//! ```

use std::path::{Path, PathBuf};

use p2p_storage_node::daemon::{generate_mnemonic, start, Config, VolumeSpec};

fn init(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let seed = dir.join("node.seed");
    if seed.exists() {
        return Err(format!("{} existe déjà", seed.display()).into());
    }
    std::fs::write(&seed, generate_mnemonic()? + "\n")?;
    let config = Config {
        seed_file: "node.seed".into(),
        identity_index: 0,
        data_dir: "data".into(),
        volumes: vec![VolumeSpec {
            volume_id: 1,
            mount_path: PathBuf::from("data/volume1"),
            max_capacity_bytes: 100 << 30,
        }],
        dht_listen: "/ip4/0.0.0.0/tcp/4001".into(),
        blocks_listen: "/ip4/0.0.0.0/tcp/4002".into(),
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
    };
    std::fs::write(
        dir.join("node.json"),
        serde_json::to_string_pretty(&config)?,
    )?;
    println!(
        "Phrase de récupération écrite dans {} — recopiez-la hors de cette machine.",
        seed.display()
    );
    println!("Configuration : {}", dir.join("node.json").display());
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<(), Box<dyn std::error::Error>> = match args.as_slice() {
        [cmd, dir] if cmd == "init" => init(Path::new(dir)),
        [cmd, dir] if cmd == "geoip-update" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match p2p_storage_node::geo::update(Path::new(dir), now) {
                Ok(p) => {
                    println!("Base de géolocalisation : {} ({})", p.display(), p2p_storage_node::geo::ATTRIBUTION);
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        }
        [config] => match Config::load(Path::new(config)) {
            Err(e) => Err(e.into()),
            Ok(c) => match start(c).await {
                Err(e) => Err(e.into()),
                Ok((shared, url)) => {
                    println!("Nœud {} démarré.", shared.peer_id);
                    if let Some(a) = &shared.blocks_addr {
                        println!("Échange de blocs : {a}");
                    }
                    println!("Dashboard : {url}");
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = p2p_storage_node::daemon::save(&shared);
                    Ok(())
                }
            },
        },
        _ => Err(
            "usage : p2p-storage-node init <répertoire> | geoip-update <répertoire de données> | <config.json>".into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("erreur : {e}");
        std::process::exit(1);
    }
}
