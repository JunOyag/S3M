//! `p2p-storage-connector` — exécutable du Connecteur (`deploiement.packaging`).
//!
//! ```text
//! p2p-storage-connector init <répertoire>   phrase de récupération, sel, config
//! p2p-storage-connector <config.json>       démarre le Connecteur
//! ```

use std::path::Path;

use p2p_storage_connector::daemon::*;

fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn init(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let seed = dir.join("user.seed");
    if seed.exists() {
        return Err(format!("{} existe déjà", seed.display()).into());
    }
    let mnemonic = generate_mnemonic()?;
    std::fs::write(&seed, mnemonic.clone() + "\n")?;
    let (_, pub_user) = user_keys(&mnemonic, 0)?;
    let salt = hex::encode(&random32()?[..16]);
    let config = Config {
        seed_file: "user.seed".into(),
        identity_index: 0,
        data_dir: "data".into(),
        node: NodeLink {
            addr: "/ip4/<IP du Nœud>/tcp/4002/p2p/<PeerId du Nœud>".into(),
            node_id: "<node_id du Nœud>".into(),
            salt: salt.clone(),
        },
        api_port: 8766,
        q_max_bytes: DEFAULT_Q_MAX_BYTES,
        watch_interval_s: DEFAULT_WATCH_INTERVAL_S,
        mount_point: Some("P:".into()),
    };
    let cfg = dir.join("connector.json");
    std::fs::write(&cfg, serde_json::to_string_pretty(&config)?)?;
    println!(
        "Phrase de récupération écrite dans {} — recopiez-la hors de cette machine.",
        seed.display()
    );
    println!("À transmettre à l'opérateur du Nœud (action « Rattacher un utilisateur ») :");
    println!("  user_id : {}", hex::encode(pub_user));
    println!("  salt    : {salt}");
    println!(
        "Puis renseignez l'adresse et le node_id du Nœud dans {}.",
        cfg.display()
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<(), Box<dyn std::error::Error>> = match args.as_slice() {
        [cmd, dir] if cmd == "init" => init(Path::new(dir)),
        [config] => match Config::load(Path::new(config)) {
            Err(e) => Err(e.into()),
            Ok(c) => match start(c, std::sync::Arc::new(system_clock)).await {
                Err(e) => Err(e.into()),
                Ok((_shared, url)) => {
                    println!("Connecteur démarré.");
                    println!("Dashboard : {url}");
                    let _ = tokio::signal::ctrl_c().await;
                    Ok(())
                }
            },
        },
        _ => Err(
            "usage : p2p-storage-connector init <répertoire> | p2p-storage-connector <config.json>"
                .into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("erreur : {e}");
        std::process::exit(1);
    }
}
