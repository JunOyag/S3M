//! Nœud démarré verrouillé (`deploiement.packaging#coffre-local`) : sa
//! phrase est gardée sous une phrase de passe. Le tableau de bord local ne
//! propose que le déverrouillage ; à distance, le canal d'administration
//! écoute sous la clé de déverrouillage (identité distincte, en clair) et
//! n'accepte que la phrase de passe (essais limités).

use std::sync::{Arc, Mutex};

use s3m_protocol::vault::{self, VaultError};
use serde_json::json;
use tokio::sync::oneshot;

use crate::admin::{self, Mode, UnlockFn};
use crate::daemon::Config;
use crate::local_http::{ActionFn, StatusFn, Switch};

/// `PeerId` de déverrouillage à distance de `seed`, s'il existe.
pub fn unlock_peer(seed: &std::path::Path) -> Option<libp2p::PeerId> {
    let k = vault::unlock_key(seed)?;
    let key = libp2p::identity::Keypair::ed25519_from_bytes(k).ok()?;
    Some(key.public().to_peer_id())
}

/// Attend la phrase de passe ; rend quand la phrase du Nœud est lisible.
pub async fn wait(config: &Config, switch: &Arc<Switch>) -> Result<(), String> {
    let (tx, rx) = oneshot::channel::<()>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let seed = config.seed_file.clone();
    let try_unlock: UnlockFn = Arc::new(move |pass: &str| match vault::unlock(&seed, pass) {
        Ok(_) => {
            if let Some(t) = tx.lock().unwrap().take() {
                let _ = t.send(());
            }
            Ok(())
        }
        Err(VaultError::BadPassphrase) => Err(None),
        Err(e) => Err(Some(e.to_string())),
    });
    let peer = unlock_peer(&config.seed_file).map(|p| p.to_string());
    let st_fn: StatusFn = {
        let peer = peer.clone();
        Arc::new(move || {
            json!({
                "titre": "S3m Nœud — verrouillé",
                "nœud verrouillé": {
                    "état": "🔒 en attente de la phrase de passe",
                    "explication": "La phrase de récupération de ce Nœud est chiffrée sous une phrase de passe : il ne démarre qu'une fois celle-ci saisie, ici ou à distance depuis S3m (Connecteur, « Administrer mon Nœud à distance »).",
                    "identifiant de déverrouillage": peer.clone().unwrap_or_else(|| "aucun (déverrouillage local uniquement)".into()),
                },
                "actions": [
                    { "nom": "unlock", "titre": "Déverrouiller", "libellé": "Déverrouiller", "champs": ["phrase de passe"],
                      "types": { "phrase de passe": "secret" } }
                ]
            })
        })
    };
    let act_fn: ActionFn = {
        let try_unlock = try_unlock.clone();
        Arc::new(move |name, v| {
            if name != "unlock" {
                return Err("Nœud verrouillé : saisissez d'abord la phrase de passe".into());
            }
            let pass = v.get("phrase de passe").and_then(|x| x.as_str()).unwrap_or("");
            match try_unlock(pass) {
                Ok(()) => Ok(json!({ "ok": true, "message": "Nœud déverrouillé : il démarre" })),
                Err(None) => Err("phrase de passe incorrecte".into()),
                Err(Some(e)) => Err(e),
            }
        })
    };
    switch.set(st_fn, act_fn, None);
    println!("Nœud verrouillé : phrase de passe attendue (tableau de bord local ou administration à distance).");
    let server = match (config.remote_admin, vault::unlock_key(&config.seed_file)) {
        (true, Some(k)) => {
            let key = libp2p::identity::Keypair::ed25519_from_bytes(k).map_err(|e| e.to_string())?;
            match admin::serve(
                key,
                &config.admin_listen,
                false,
                Mode::Locked { unlock: try_unlock },
                switch.status_fn(),
                switch.action_fn(),
                None,
            )
            .await
            {
                Ok(s) => {
                    println!("Déverrouillage à distance : identifiant {}", peer.unwrap_or_default());
                    Some(s)
                }
                Err(e) => {
                    eprintln!("déverrouillage à distance indisponible : {e}");
                    None
                }
            }
        }
        _ => None,
    };
    let _ = rx.await;
    // Laisse partir la réponse avant de libérer le port d'administration.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    if let Some(s) = server {
        s.stop().await;
    }
    Ok(())
}
