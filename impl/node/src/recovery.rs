//! Restauration d'un Nœud depuis sa seule seed — id
//! `deploiement.disaster-recovery` (partie node), étapes 2 à 4. Réf. spec :
//! docs/07-deploiement/disaster-recovery.md.
//!
//! 1. Lecture de sa propre entrée DHT Node, déchiffrement du pointeur de
//!    snapshot (`K_node_self`).
//! 2. Reconstruction du snapshot depuis k fragments chez les partenaires,
//!    déchiffrement (`K_node_snapshot`) : Utilisateurs, partenaires (solde
//!    accordé), liste noire. Adresses des partenaires relues dans leurs
//!    propres entrées DHT Node.
//! 3. Pour chaque Utilisateur : `K_attach` recalculé, entrée
//!    DispersalManifest, parcours de l'arbre d'index, reconstruction de
//!    chaque bloc de données depuis la parité — la copie locale intégrale
//!    est retrouvée, et l'état de dispersion avec elle.
//!
//! La racine courante de chaque Utilisateur n'est pas dans le NodeManifest :
//! sa prochaine validation (`CommitRoot`) est acceptée telle quelle
//! (`NodeService::adopt_next_root`).

use std::collections::HashMap;
use std::sync::Mutex;

use libp2p::multiaddr::Protocol;
use libp2p::{identity, Multiaddr, PeerId};
use p2p_storage_core::erasure::{padding_block, reconstruct_data};
use p2p_storage_core::k_attach::derive_k_attach_as_node;
use p2p_storage_core::k_dispersal::derive_k_dispersal_content;
use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_core::version::CURRENT_HEADER;
use p2p_storage_protocol::dht::dispersal_dht_key;
use p2p_storage_protocol::dispersal::{
    decode_index_node, decode_manifest, encode_root_pointer, open_dispersal_entry, Id, PartnerDesc,
    StripeDesc,
};
use p2p_storage_protocol::exchange::{Body, Request, Response};
use p2p_storage_protocol::fb::dht as fbd;
use p2p_storage_protocol::index::open_index_node;
use p2p_storage_protocol::snapshot::{
    decode_manifest as decode_snapshot, encode_pointer, open_node_entry_pointer, open_snapshot,
};

use crate::chunk_store::Space;
use crate::dht_directory::DhtNode;
use crate::dispersal_engine::{DispersalState, EngineConfig, StripeRec, UserDispersal};
use crate::exchange::{BlockServer, NodeService, PartnerState, UserAccount};

/// Bilan d'une restauration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub users: usize,
    pub partners: usize,
    pub stripes: usize,
    pub blocks: usize,
    pub errors: Vec<String>,
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn peer_of(node_id: &Id) -> Option<PeerId> {
    let pk = identity::ed25519::PublicKey::try_from_bytes(node_id).ok()?;
    Some(identity::PublicKey::from(pk).to_peer_id())
}

/// `ip/port` d'une entrée DHT Node (enveloppe vérifiée).
fn ip_port(envelope: &[u8]) -> Option<(String, u16)> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope).ok()?;
    let e = fbd::root_as_node_entry(env.payload()?.bytes()).ok()?;
    Some((e.ip()?.to_string(), e.port()))
}

/// Adresse d'échange de blocs d'un Nœud : son entrée DHT, sinon la table.
async fn resolve_addr(
    dht: &DhtNode,
    node_id: &Id,
    fallback: Option<&PartnerDesc>,
) -> Option<String> {
    let (ip, port) = match dht
        .get(node_id.to_vec())
        .await
        .ok()
        .flatten()
        .and_then(|e| ip_port(&e))
    {
        Some(x) => x,
        None => fallback.map(|p| (p.ip.clone(), p.port))?,
    };
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let mut a = Multiaddr::empty();
    a.push(match ip {
        std::net::IpAddr::V4(v) => Protocol::Ip4(v),
        std::net::IpAddr::V6(v) => Protocol::Ip6(v),
    });
    a.push(Protocol::Tcp(port));
    a.push(Protocol::P2p(peer_of(node_id)?));
    Some(a.to_string())
}

struct Fetcher<'a> {
    server: &'a BlockServer,
    dht: &'a DhtNode,
    addrs: &'a Mutex<HashMap<Id, String>>,
    coef: usize,
}

impl Fetcher<'_> {
    async fn addr(&self, node: &Id, desc: Option<&PartnerDesc>) -> Option<Multiaddr> {
        if let Some(a) = self.addrs.lock().unwrap().get(node) {
            return a.parse().ok();
        }
        let a = resolve_addr(self.dht, node, desc).await?;
        self.addrs.lock().unwrap().insert(*node, a.clone());
        a.parse().ok()
    }

    /// k blocs de données d'un stripe, depuis la parité (hash vérifié).
    async fn data(&self, s: &StripeDesc, table: &[PartnerDesc]) -> Result<Vec<Vec<u8>>, String> {
        let k = s.k as usize;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; k * (1 + self.coef)];
        let mut have = 0;
        for b in &s.blocks {
            if (b.index as usize) < k && b.is_padding {
                shards[b.index as usize] = Some(padding_block());
                have += 1;
            }
        }
        for b in s.blocks.iter().filter(|b| b.index as usize >= k) {
            if have >= k {
                break;
            }
            let Some(p) = table.iter().find(|p| p.partner_id == b.partner_id) else {
                continue;
            };
            let Some(addr) = self.addr(&p.node_id, Some(p)).await else {
                continue;
            };
            let req = Request {
                credential: None,
                body: Body::FetchFragment {
                    hash: b.hash.to_vec(),
                },
            };
            if let Ok(Response::BlockData(d)) = self.server.request(addr, req).await {
                if hash_sha256(&d) == b.hash && (b.index as usize) < shards.len() {
                    shards[b.index as usize] = Some(d);
                    have += 1;
                }
            }
        }
        reconstruct_data(shards, k, self.coef)
            .map_err(|e| format!("stripe {}… : {e}", &hx(&s.stripe_id)[..12]))
    }
}

/// Enregistrement d'état d'un stripe relu.
fn record(s: &StripeDesc, table: &[PartnerDesc], data: &[Vec<u8>]) -> StripeRec {
    let k = s.k as usize;
    let node_of = |pid: u16| {
        table
            .iter()
            .find(|p| p.partner_id == pid)
            .map(|p| hx(&p.node_id))
            .unwrap_or_default()
    };
    let mut padding = vec![false; k];
    for b in s.blocks.iter().filter(|b| (b.index as usize) < k) {
        padding[b.index as usize] = b.is_padding;
    }
    StripeRec {
        id: hx(&s.stripe_id),
        data: data.iter().map(|d| hx(&hash_sha256(d))).collect(),
        padding,
        parity: s
            .blocks
            .iter()
            .filter(|b| b.index as usize >= k)
            .map(|b| (b.index, hx(&b.hash), node_of(b.partner_id)))
            .collect(),
        salt: s.encryption_salt.map(|x| hx(&x)),
    }
}

/// Restaure le Nœud depuis le réseau (installation vide, seed seule).
pub async fn recover(
    service: &Mutex<NodeService>,
    state: &mut DispersalState,
    server: &BlockServer,
    dht: &DhtNode,
    cfg: &EngineConfig,
    addrs: &Mutex<HashMap<Id, String>>,
    now: u64,
) -> Result<RecoveryReport, String> {
    let (priv_node, pub_node) = {
        let s = service.lock().unwrap();
        (s.priv_node(), s.node_id())
    };
    let env = dht
        .get(pub_node.to_vec())
        .await
        .map_err(|e| e.to_string())?
        .ok_or("aucune entrée Node publiée pour cette seed")?;
    let pointer = open_node_entry_pointer(&priv_node, &env)
        .map_err(|e| e.to_string())?
        .ok_or("l'entrée Node ne porte pas de snapshot")?;
    let f = Fetcher {
        server,
        dht,
        addrs,
        coef: cfg.coef,
    };
    let frames = f.data(&pointer.stripe, &pointer.partners).await?;
    let manifest = decode_snapshot(
        &open_snapshot(&priv_node, &pointer.salt, &frames).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut report = RecoveryReport {
        users: manifest.users.len(),
        partners: manifest.partners.len(),
        ..Default::default()
    };
    {
        let mut s = service.lock().unwrap();
        for p in &manifest.partners {
            s.partners.insert(
                p.node_id,
                PartnerState {
                    allowance: p.allowance,
                    ..Default::default()
                },
            );
        }
        for u in &manifest.users {
            s.users.insert(
                u.user_id,
                UserAccount {
                    salt: u.salt.clone(),
                    quota_bytes: u.quota_bytes,
                    used_bytes: 0,
                    root: [0; 32],
                },
            );
            s.adopt_next_root.insert(u.user_id);
        }
    }
    for (n, at, why) in &manifest.blacklist {
        state.upkeep.blacklist.insert(hx(n), (*at, why.clone()));
    }
    for p in &manifest.partners {
        f.addr(&p.node_id, None).await;
    }
    state.snapshot.pointer = Some(hx(&encode_pointer(&pointer)));
    state.snapshot.stripe = Some(record(&pointer.stripe, &pointer.partners, &frames));
    state.snapshot.last_at = now;

    // Étape 4 : copie locale intégrale de chaque Utilisateur.
    for u in &manifest.users {
        match recover_user(service, &f, &priv_node, u.user_id, &u.salt, now).await {
            Ok((d, blocks)) => {
                report.stripes += d.stripes.len();
                report.blocks += blocks;
                state.users.insert(hx(&u.user_id), d);
            }
            Err(e) => report
                .errors
                .push(format!("{}… : {e}", &hx(&u.user_id)[..16])),
        }
    }
    // Soldes : ce qu'on héberge chez chacun, recompté depuis les catalogues.
    let mut s = service.lock().unwrap();
    let all = state
        .users
        .values()
        .flat_map(|d| d.stripes.iter().chain(d.index.iter()))
        .chain(state.snapshot.stripe.iter());
    for rec in all {
        for (_, _, p) in &rec.parity {
            if let Some(st) = hex::decode(p)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .and_then(|id| s.partners.get_mut(&id))
            {
                st.ledger.hosted_for_partner += 1;
            }
        }
    }
    Ok(report)
}

async fn recover_user(
    service: &Mutex<NodeService>,
    f: &Fetcher<'_>,
    priv_node: &[u8; 32],
    user: Id,
    salt: &[u8],
    now: u64,
) -> Result<(UserDispersal, usize), String> {
    let k_attach = derive_k_attach_as_node(priv_node, &user, salt).map_err(|e| e.to_string())?;
    let kdc = derive_k_dispersal_content(&k_attach).map_err(|e| e.to_string())?;
    let mut d = UserDispersal::default();
    let Some(env) = f
        .dht
        .get(dispersal_dht_key(&k_attach).to_vec())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok((d, 0)); // rien encore dispersé pour cet Utilisateur
    };
    let pointer = open_dispersal_entry(&k_attach, &env).map_err(|e| e.to_string())?;
    let root = f.data(&pointer.root_stripe, &pointer.partners).await?;
    let clear = open_index_node(&kdc, &pointer.salt, &CURRENT_HEADER, &root[0])
        .map_err(|e| e.to_string())?;
    let manifest = decode_manifest(&clear).map_err(|e| e.to_string())?;
    let table = manifest.partners.clone();
    let mut index = vec![record(&pointer.root_stripe, &pointer.partners, &root)];
    let mut level = vec![manifest.root];
    let mut blocks = 0;
    while let Some(node) = level.pop() {
        for s in node.entries {
            let data = f.data(&s, &table).await?;
            if node.is_leaf {
                for (i, b) in data.iter().enumerate() {
                    if s.blocks
                        .iter()
                        .any(|x| x.index as usize == i && x.is_padding)
                    {
                        continue;
                    }
                    let h = hash_sha256(b);
                    let mut sv = service.lock().unwrap();
                    sv.store
                        .put(Space::UserBlock, &user, &h, b)
                        .map_err(|e| e.to_string())?;
                    if let Some(acc) = sv.users.get_mut(&user) {
                        acc.used_bytes += b.len() as u64;
                    }
                    blocks += 1;
                }
                d.stripes.push(record(&s, &table, &data));
            } else {
                let salt = s.encryption_salt.ok_or("stripe d'index sans sel")?;
                let clear = open_index_node(&kdc, &salt, &CURRENT_HEADER, &data[0])
                    .map_err(|e| e.to_string())?;
                index.push(record(&s, &table, &data));
                level.push(decode_index_node(&clear).map_err(|e| e.to_string())?);
            }
        }
    }
    index.rotate_left(1); // racine en dernier
    d.index = index;
    d.pointer = Some(hx(&encode_root_pointer(&pointer)));
    d.published_at = now;
    d.next_republish = now;
    Ok((d, blocks))
}
