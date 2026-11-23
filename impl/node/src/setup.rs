//! Premier lancement du Nœud sous identité temporaire — id
//! `deploiement.appairage-admin` § Identité temporaire. Deux choix
//! (nouvelle identité, identité existante), code d'appairage pour la
//! configuration depuis un Connecteur du réseau local ; la phrase de
//! récupération n'est écrite qu'après confirmation.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use s3m_core::symmetric_suite::derive_admin_totp_secret;
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::admin::{self, otpauth_uri, qr_svg, Mode};
use crate::daemon::{generate_mnemonic, node_seed_from_mnemonic, Config};
use crate::local_http::{ActionFn, StatusFn, Switch};

/// Saisie d'une identité existante : phrase de 12 à 24 mots (casse et
/// espaces indifférents). Rend la phrase normalisée.
pub fn parse_recovery(input: &str) -> Result<String, String> {
    let words = input
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    bip39::Mnemonic::parse_normalized(&words)
        .map(|m| m.to_string())
        .map_err(|e| format!("phrase de récupération : {e}"))
}

/// Enrôlement 2FA de l'identité `mnemonic` : `(secret base32, QR SVG)`.
pub fn totp_enrolment(mnemonic: &str, index: u32, serial: u32) -> Result<(String, String), String> {
    let seed = node_seed_from_mnemonic(mnemonic, index).map_err(|e| e.to_string())?;
    let secret = derive_admin_totp_secret(&seed, serial).map_err(|e| e.to_string())?;
    let node_id = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    Ok((
        s3m_core::identity_derivation::base32_encode(&secret),
        qr_svg(&otpauth_uri(&secret, &node_id)),
    ))
}

enum Phase {
    Choose,
    Reveal { mnemonic: String, restored: bool },
    Done,
}

struct State {
    phase: Phase,
    /// Adresses du canal d'administration (`…/p2p/<identité temporaire>`).
    listen: Vec<String>,
    done: Option<oneshot::Sender<()>>,
}

fn status(st: &State, cfg: &Config, code: &str, temp: &str) -> Value {
    match &st.phase {
        Phase::Choose => json!({
            "titre": "S3m Nœud — premier lancement",
            "identité": {
                "état": "temporaire : aucune donnée, aucun partenaire, rien de publié",
                "identifiant temporaire": temp,
                "code d'appairage": code,
                "adresses d'administration": st.listen,
            },
            "configuration depuis un autre ordinateur": "Dans S3m (Connecteur) sur le même réseau local : « Configurer un Nœud », puis saisir le code d'appairage.",
            "actions": [
                { "nom": "new_identity", "titre": "Nouvelle identité", "libellé": "Créer une nouvelle identité", "champs": [] },
                { "nom": "existing_identity", "titre": "Identité existante (restauration)", "libellé": "Restaurer",
                  "champs": ["phrase de récupération"],
                  "aide": { "phrase de récupération": "Les 24 mots du Nœud, séparés par des espaces" } }
            ]
        }),
        Phase::Reveal { mnemonic, restored } => {
            let mut v = json!({ "titre": "S3m Nœud — identité à confirmer" });
            if !restored {
                v["1. phrase de récupération (à noter sur papier, ne pas photographier)"] = json!({
                    "24 mots": mnemonic,
                    "important": "Seule cette phrase permet de reconstruire le Nœud et ses données. Gardez-la hors de cette machine.",
                });
            }
            let (secret, qr) = totp_enrolment(mnemonic, cfg.identity_index, cfg.admin_totp_serial)
                .unwrap_or_default();
            v["2. double authentification (administration à distance)"] = json!({
                "QR code 2FA": qr,
                "clé": secret,
                "aide": "Scannez ce QR code (et lui seul) avec votre application d'authentification.",
            });
            v["actions"] = json!([
                { "nom": "confirm", "libellé": if *restored { "Démarrer et restaurer le Nœud" } else { "J'ai noté ma phrase : démarrer le Nœud" }, "champs": [] },
                { "nom": "back", "libellé": "Revenir au choix", "champs": [] }
            ]);
            v
        }
        Phase::Done => {
            json!({ "titre": "S3m Nœud — démarrage…", "état": "identité enregistrée, démarrage du Nœud" })
        }
    }
}

fn act(st: &mut State, seed_file: &PathBuf, name: &str, v: &Value) -> Result<Value, String> {
    match (name, &st.phase) {
        ("new_identity", Phase::Choose) => {
            let mnemonic = generate_mnemonic().map_err(|e| e.to_string())?;
            st.phase = Phase::Reveal {
                mnemonic,
                restored: false,
            };
            Ok(
                json!({ "ok": true, "message": "Nouvelle identité créée : notez la phrase avant de démarrer" }),
            )
        }
        ("existing_identity", Phase::Choose) => {
            let input = v
                .get("phrase de récupération")
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            let mnemonic = parse_recovery(input)?;
            st.phase = Phase::Reveal {
                mnemonic,
                restored: true,
            };
            Ok(json!({ "ok": true, "message": "Identité reconnue" }))
        }
        ("back", Phase::Reveal { .. }) => {
            st.phase = Phase::Choose;
            Ok(json!({ "ok": true, "message": "Retour au choix" }))
        }
        ("confirm", Phase::Reveal { mnemonic, restored }) => {
            // Identité neuve : aucune sauvegarde à chercher au démarrage.
            let marker = crate::daemon::new_identity_marker(seed_file);
            if *restored {
                let _ = std::fs::remove_file(&marker);
            } else if let Some(dir) = marker.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                std::fs::write(&marker, b"").map_err(|e| e.to_string())?;
            }
            if let Some(dir) = seed_file.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            std::fs::write(seed_file, format!("{mnemonic}\n")).map_err(|e| e.to_string())?;
            st.phase = Phase::Done;
            if let Some(tx) = st.done.take() {
                let _ = tx.send(());
            }
            Ok(json!({ "ok": true, "message": "Identité enregistrée : le Nœud démarre" }))
        }
        _ => Err("action indisponible à cette étape".into()),
    }
}

/// Assistant sous identité temporaire ; rend quand la phrase est écrite.
pub async fn run(config: &Config, switch: &Arc<Switch>) -> Result<(), String> {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let temp = key.public().to_peer_id().to_string();
    let mut r = [0u8; 5];
    getrandom::getrandom(&mut r).map_err(|e| e.to_string())?;
    let code = s3m_protocol::admin::pairing_code(r);
    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(State {
        phase: Phase::Choose,
        listen: Vec::new(),
        done: Some(tx),
    }));
    let st_fn: StatusFn = {
        let (state, cfg, code, temp) = (state.clone(), config.clone(), code.clone(), temp.clone());
        Arc::new(move || status(&state.lock().unwrap(), &cfg, &code, &temp))
    };
    let act_fn: ActionFn = {
        let (state, seed) = (state.clone(), config.seed_file.clone());
        Arc::new(move |n, v| act(&mut state.lock().unwrap(), &seed, n, &v))
    };
    switch.set(st_fn, act_fn, None);
    let server = admin::serve(
        key,
        &config.admin_listen,
        config.mdns,
        Mode::Setup { code: code.clone() },
        switch.status_fn(),
        switch.action_fn(),
        None,
    )
    .await;
    println!("Nœud à configurer (identité temporaire {temp}).");
    println!("Code d'appairage : {code}");
    match &server {
        Ok(s) => {
            let addrs: Vec<String> = s
                .listen
                .lock()
                .unwrap()
                .iter()
                .map(|a| format!("{a}/p2p/{temp}"))
                .collect();
            println!("Configuration à distance : {}", addrs.join(" "));
            state.lock().unwrap().listen = addrs;
        }
        Err(e) => eprintln!("configuration à distance indisponible : {e}"),
    }
    let _ = rx.await;
    // Laisse partir la réponse à « confirm » avant de fermer le canal.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    if let Ok(s) = server {
        s.stop().await;
    }
    Ok(())
}
