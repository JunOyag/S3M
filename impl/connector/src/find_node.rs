//! Recherche du Nœud de rattachement d'une identité reprise
//! (`network.bootstrap` § Chemin d'amorçage à froid, assistant de premier
//! lancement) : entrée User de l'annuaire, sinon identité ou empreinte du
//! Nœud saisie par l'Utilisateur.

use std::path::Path;

use libp2p::{Multiaddr, PeerId};
use s3m_protocol::dispersal::Id;

use crate::daemon::node_candidates;
use crate::dht_directory::{chiavdf_verifier, DhtClient, DhtClientConfig};

/// Nœud retrouvé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    pub node_id: Id,
    pub addr: Multiaddr,
    /// Sel de l'attachement (entrée User), s'il est connu.
    pub salt: Option<Vec<u8>>,
    /// Nom donné au Nœud par l'Utilisateur, sinon son empreinte.
    pub label: String,
}

/// Référence saisie : identité complète (64 caractères hexadécimaux ou
/// PeerId) ou empreinte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRef {
    Id(Id),
    Fingerprint(String),
}

/// Interprète la saisie de l'Utilisateur.
pub fn parse_node_ref(input: &str) -> Result<NodeRef, String> {
    let t = input.trim();
    if t.is_empty() {
        return Err("saisissez l'identité ou l'empreinte de votre Nœud".into());
    }
    if t.len() == 64 {
        if let Some(id) = hex::decode(t).ok().and_then(|b| <Id>::try_from(b).ok()) {
            return Ok(NodeRef::Id(id));
        }
    }
    if let Some(id) = t.parse::<PeerId>().ok().and_then(|p| crate::lan::node_id_of(&p)) {
        return Ok(NodeRef::Id(id));
    }
    Ok(NodeRef::Fingerprint(norm_fp(t)))
}

fn norm_fp(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

/// Identité dont l'empreinte est `fp` parmi `candidates`.
pub fn match_fingerprint(fp: &str, candidates: &[Id]) -> Option<Id> {
    let want = norm_fp(fp);
    candidates
        .iter()
        .find(|id| norm_fp(&s3m_protocol::pseudo::fingerprint(&id[..])) == want)
        .copied()
}

/// Points d'entrée : Nœuds du réseau local et Nœuds vus par les autres
/// identités de ce poste (`dht_peers.json`).
pub fn entry_points(app_dir: &Path, lan: &[String]) -> Vec<Multiaddr> {
    let mut out: Vec<Multiaddr> = lan.iter().filter_map(|a| a.parse().ok()).collect();
    let mut files = vec![app_dir.join("data").join("dht_peers.json")];
    if let Ok(rd) = std::fs::read_dir(app_dir.join("identites")) {
        files.extend(rd.flatten().map(|e| e.path().join("data").join("dht_peers.json")));
    }
    for f in files {
        let Ok(b) = std::fs::read(&f) else { continue };
        let list: Vec<String> = serde_json::from_slice(&b).unwrap_or_default();
        out.extend(list.iter().filter_map(|a| a.parse::<Multiaddr>().ok()));
    }
    out.dedup();
    out
}

/// Client de l'annuaire sur ces points d'entrée.
pub async fn client(entry: Vec<Multiaddr>) -> Result<DhtClient, String> {
    if entry.is_empty() {
        return Err("aucun Nœud connu pour accéder à l'annuaire (aucun sur le réseau local)".into());
    }
    let clock: crate::dht_directory::Clock = std::sync::Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    DhtClient::start(DhtClientConfig {
        bootstrap: entry,
        vdf: chiavdf_verifier(),
        clock,
    })
    .await
    .map_err(|e| e.to_string())
}

/// Adresse de `node_id` d'après son entrée dans l'annuaire, cherchée de
/// proche en proche.
pub async fn node_addr(c: &DhtClient, node_id: &Id) -> Result<Multiaddr, String> {
    let env = c
        .get(node_id.to_vec())
        .await
        .map_err(|e| e.to_string())?
        .ok_or("ce Nœud n'a pas d'entrée dans l'annuaire (éteint depuis longtemps ?)")?;
    node_candidates(node_id, &env)
        .into_iter()
        .next()
        .ok_or_else(|| "entrée du Nœud sans adresse joignable".into())
}

/// Nœud de rattachement le plus récent d'après l'entrée User.
pub async fn home_from_user_entry(
    c: &DhtClient,
    priv_user: &[u8; 32],
    pub_user: &[u8; 32],
) -> Result<Home, String> {
    let plain = crate::publish::read_user_entry(c, priv_user, pub_user)
        .await
        .ok_or("aucune entrée de cette identité dans l'annuaire (plus de 6 mois sans connexion ?)")?;
    let a = plain
        .attachments
        .iter()
        .max_by_key(|a| a.timestamp)
        .ok_or("entrée de l'identité sans rattachement")?;
    let addr = node_addr(c, &a.node_id).await?;
    Ok(Home {
        node_id: a.node_id,
        addr,
        salt: Some(a.salt.clone()),
        label: if a.node_label.is_empty() {
            s3m_protocol::pseudo::fingerprint(&a.node_id[..])
        } else {
            a.node_label.clone()
        },
    })
}

/// Identités des Nœuds connus de l'annuaire (table de routage).
pub async fn known_ids(c: &DhtClient) -> Vec<Id> {
    c.known_peers()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|a| {
            a.iter().find_map(|p| match p {
                libp2p::multiaddr::Protocol::P2p(peer) => crate::lan::node_id_of(&peer),
                _ => None,
            })
        })
        .collect()
}
