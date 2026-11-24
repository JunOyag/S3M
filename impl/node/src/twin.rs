//! Identité déjà utilisée (`securite.incidents-compromissions#identite-dupliquee`) :
//! avant de rejoindre le réseau, le Nœud écoute les annonces mDNS du réseau
//! local ; si un autre Nœud y annonce déjà sa propre identité, il ne
//! démarre pas sa pile réseau.

use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, mdns, noise, tcp, yamux, Multiaddr, PeerId};

/// Durée d'écoute avant le démarrage.
pub const SCAN: Duration = Duration::from_secs(3);

/// Identifiant réseau (`PeerId`) d'une graine de Nœud.
pub fn peer_id_of(node_seed: [u8; 32]) -> Result<PeerId, String> {
    let secret =
        identity::ed25519::SecretKey::try_from_bytes(node_seed).map_err(|e| e.to_string())?;
    Ok(
        identity::Keypair::from(identity::ed25519::Keypair::from(secret))
            .public()
            .to_peer_id(),
    )
}

/// Adresses annoncées sous `me` parmi les découvertes : avant que ce Nœud
/// ne s'annonce lui-même, toute annonce de `me` vient d'un autre processus.
pub fn twins(found: &[(PeerId, Multiaddr)], me: &PeerId) -> Vec<String> {
    let mut out: Vec<String> = found
        .iter()
        .filter(|(p, _)| p == me)
        .map(|(_, a)| a.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Écoute les annonces mDNS pendant `duration` (identité réseau
/// éphémère) et renvoie les adresses où `me` est déjà annoncé.
pub async fn scan(me: PeerId, duration: Duration) -> Result<Vec<String>, String> {
    isolated(move || listen(me, duration)).await
}

/// Exécute `f` sur un runtime tokio à part, détruit ensuite : libp2p-mdns
/// lance une tâche par interface réseau qu'il n'arrête jamais quand son
/// `Behaviour` est abandonné (aucun `Drop`) ; la destruction du runtime les
/// arrête toutes. Sans cela, chaque recherche en laissait tourner,
/// s'interrogeant les unes les autres (consommation processeur croissante).
async fn isolated<F, Fut, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>>,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let r = rt.block_on(f());
        rt.shutdown_background();
        r
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn listen(me: PeerId, duration: Duration) -> Result<Vec<String>, String> {
    let net = |e: &dyn std::fmt::Display| e.to_string();
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| net(&e))?
        .with_behaviour(|key| {
            mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
        .map_err(|e| net(&e))?
        .build();
    let mut found = Vec::new();
    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(mdns::Event::Discovered(list)) = ev {
                    found.extend(list);
                }
            }
        }
    }
    Ok(twins(&found, &me))
}

/// Message affiché quand l'identité est déjà utilisée.
pub fn message(addrs: &[String]) -> String {
    format!(
        "Cette identité est déjà utilisée par un autre Nœud du réseau local ({}) : \
         ce Nœud ne rejoint pas le réseau, pour ne pas mélanger les données des deux. \
         Arrêtez l'autre Nœud, ou donnez à celui-ci sa propre identité \
         (s3m-node init dans un nouveau répertoire, sans copier le dossier d'un Nœud existant).",
        addrs.join(", ")
    )
}
