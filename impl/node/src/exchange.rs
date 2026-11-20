//! Protocole d'échange de blocs — id `protocols.echange-blocs`, partie
//! `node` : service (règles, état) et transport libp2p requête/réponse.
//! Réf. spec : docs/04-protocols/echange-blocs.md.
//!
//! - [`NodeService`] : traitement d'une requête, sans I/O. Côté Connecteur
//!   (blocs, racine, incidents, autorisations, délégations) et côté
//!   partenaire (dépôt de fragments avec reçu signé, challenges PoS,
//!   récupération, avis de suppression, lecture de secours).
//! - [`BlockServer`] : écoute `/p2p-storage/blocks/1` et émet des requêtes
//!   vers d'autres Nœuds (identité libp2p dérivée de `priv_node`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use p2p_storage_core::k_attach::derive_k_attach_as_node;
use p2p_storage_core::symmetric_suite::hash_sha256;
use p2p_storage_protocol::dht::verify_migration_pointer;
use p2p_storage_protocol::exchange::*;
use p2p_storage_protocol::fb::dht as fbd;
use std::net::IpAddr;
use tokio::sync::{mpsc, oneshot};

use crate::chunk_store::{ChunkStore, MemoryStore, Space, StoreError};
use crate::pos::challenge_response;
use crate::tombstones::{apply_received, PartnerLedger, TombstoneError, TombstoneNotice};

/// Utilisateur rattaché (`node.AttachedUser`), vu du service d'échange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub salt: Vec<u8>,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    /// Racine courante du système de fichiers (`[0; 32]` : vide).
    pub root: Id,
}

/// Partenaire de troc (`node.PartnerAccount`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PartnerState {
    /// Nombre maximal de fragments hébergés pour lui (solde de troc).
    pub allowance: u64,
    pub ledger: PartnerLedger,
    /// Dernier échange (secondes Unix).
    pub last_seen: u64,
}

/// Politique de rattachement automatique (`protocols.partenariat-automatique`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachPolicy {
    pub enabled: bool,
    /// Quota attribué à chaque Utilisateur rattaché automatiquement.
    pub quota_bytes: u64,
    pub max_users: usize,
    /// Somme maximale des quotas attribués automatiquement.
    pub budget_bytes: u64,
}

impl Default for AttachPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            quota_bytes: 10 << 30,
            max_users: 10,
            budget_bytes: 100 << 30,
        }
    }
}

/// Politique d'acceptation des propositions de partenariat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartnerPolicy {
    pub accept: bool,
    pub max_partners: usize,
    /// Solde maximal accordé à un partenaire (fragments).
    pub max_allowance_blocks: u64,
}

impl Default for PartnerPolicy {
    fn default() -> Self {
        Self {
            accept: true,
            max_partners: 32,
            max_allowance_blocks: 100_000,
        }
    }
}

/// Vérificateur VDF synchrone (vrai si la preuve est valide).
pub type VdfCheck =
    std::sync::Arc<dyn Fn(&[u8; 33], &p2p_storage_core::vdf::VdfProof) -> bool + Send + Sync>;

/// État et règles du service d'échange d'un Nœud.
pub struct NodeService {
    priv_node: [u8; 32],
    node_id: Id,
    /// Anciens `node_id` couverts par les autorisations émises (migration).
    pub previous_node_ids: Vec<Id>,
    pub users: HashMap<Id, UserAccount>,
    /// Blocs de données des Utilisateurs et fragments des partenaires.
    pub store: Box<dyn ChunkStore>,
    pub partners: HashMap<Id, PartnerState>,
    /// Pointeurs de migration valides lus dans la DHT : ancien → nouveau.
    pub successors: HashMap<Id, Id>,
    pub incidents: Vec<Id>,
    /// Délégations reçues (lecture chez les partenaires de l'ancien Nœud).
    pub delegations: Vec<Delegation>,
    /// Blocs reçus à disperser : `(pub_user, hash)` (moteur de dispersion).
    pub dispersal_queue: Vec<(Id, Id)>,
    /// Après restauration, la racine courante de ces Utilisateurs est
    /// inconnue : leur prochaine validation est adoptée telle quelle.
    pub adopt_next_root: std::collections::HashSet<Id>,
    pub attach_policy: AttachPolicy,
    pub partner_policy: PartnerPolicy,
    /// Vérification des preuves VDF (rattachement et partenariat
    /// automatiques) ; `None` : ces demandes sont refusées.
    pub vdf: Option<VdfCheck>,
    /// Miroir de la liste noire (`upkeep`), pour refuser les propositions.
    pub blacklisted: std::collections::HashSet<Id>,
    /// Utilisateurs rattachés automatiquement.
    pub auto_attached: std::collections::HashSet<Id>,
    /// Identités VDF déjà utilisées pour un rattachement automatique.
    pub used_attach_identities: std::collections::HashSet<Id>,
    /// Partenariats acceptés à traiter par le démon : `(node_id, adresses)`.
    pub new_partners: Vec<(Id, Vec<String>)>,
    /// Dernière adresse IP vue par Utilisateur (carte du dashboard).
    pub last_user_ip: HashMap<Id, String>,
    pub record_user_ips: bool,
    limiter: RescueLimiter,
}

fn store_refusal(e: StoreError) -> Refusal {
    match e {
        StoreError::BadSize => Refusal::Malformed,
        StoreError::Conflict => Refusal::Unauthorized,
        StoreError::Storage(_) => Refusal::QuotaExceeded,
    }
}

fn id32(v: &[u8]) -> Result<Id, Refusal> {
    v.try_into().map_err(|_| Refusal::Malformed)
}

impl NodeService {
    /// Service en mémoire (tests).
    pub fn new(priv_node: [u8; 32]) -> Self {
        Self::with_store(priv_node, Box::<MemoryStore>::default())
    }

    pub fn with_store(priv_node: [u8; 32], store: Box<dyn ChunkStore>) -> Self {
        let node_id = ed25519_dalek::SigningKey::from_bytes(&priv_node)
            .verifying_key()
            .to_bytes();
        Self {
            priv_node,
            node_id,
            previous_node_ids: Vec::new(),
            users: HashMap::new(),
            store,
            partners: HashMap::new(),
            successors: HashMap::new(),
            incidents: Vec::new(),
            delegations: Vec::new(),
            dispersal_queue: Vec::new(),
            adopt_next_root: Default::default(),
            attach_policy: AttachPolicy::default(),
            partner_policy: PartnerPolicy::default(),
            vdf: None,
            blacklisted: Default::default(),
            auto_attached: Default::default(),
            used_attach_identities: Default::default(),
            new_partners: Vec::new(),
            last_user_ip: HashMap::new(),
            record_user_ips: true,
            limiter: RescueLimiter::default(),
        }
    }

    pub fn node_id(&self) -> Id {
        self.node_id
    }

    /// Graine `priv_node` (signatures du moteur de dispersion).
    pub fn priv_node(&self) -> [u8; 32] {
        self.priv_node
    }

    /// Traite une requête. `from` / `local` : octets des `PeerId` de la
    /// connexion ; `from_node` : `pub_node` du demandeur s'il est un Nœud.
    pub fn handle(
        &mut self,
        from: &[u8],
        from_node: Option<Id>,
        local: &[u8],
        req: Request,
        now: u64,
    ) -> Response {
        self.dispatch(from, from_node, local, req, now)
            .unwrap_or_else(Response::Failure)
    }

    fn user(&self, cred: Option<&Credential>, from: &[u8], local: &[u8]) -> Result<Id, Refusal> {
        let Some(Credential::User { user_id, proof }) = cred else {
            return Err(Refusal::Unauthorized);
        };
        let pub_user = id32(user_id)?;
        let acc = self.users.get(&pub_user).ok_or(Refusal::Unauthorized)?;
        let k = derive_k_attach_as_node(&self.priv_node, &pub_user, &acc.salt)
            .map_err(|_| Refusal::Unauthorized)?;
        if !verify_connector_proof(&k, from, local, proof) {
            return Err(Refusal::Unauthorized);
        }
        Ok(pub_user)
    }

    fn partner(&mut self, from_node: Option<Id>, now: u64) -> Result<Id, Refusal> {
        let p = from_node.ok_or(Refusal::Unauthorized)?;
        let st = self.partners.get_mut(&p).ok_or(Refusal::Unauthorized)?;
        st.last_seen = now;
        Ok(p)
    }

    fn dispatch(
        &mut self,
        from: &[u8],
        from_node: Option<Id>,
        local: &[u8],
        req: Request,
        now: u64,
    ) -> Result<Response, Refusal> {
        let cred = req.credential.as_ref();
        match req.body {
            Body::GetBlock { hash } => {
                let u = self.user(cred, from, local)?;
                match self.store.get(Space::UserBlock, &id32(&hash)?) {
                    Some((o, d)) if o == u => Ok(Response::BlockData(d)),
                    _ => Err(Refusal::NotFound),
                }
            }
            Body::PutBlock { data } => {
                let u = self.user(cred, from, local)?;
                let hash = hash_sha256(&data);
                if !self.store.contains(&hash) {
                    let acc = self.users.get(&u).ok_or(Refusal::Unauthorized)?;
                    let used = acc.used_bytes + data.len() as u64;
                    if used > acc.quota_bytes {
                        return Err(Refusal::QuotaExceeded);
                    }
                    self.store
                        .put(Space::UserBlock, &u, &hash, &data)
                        .map_err(store_refusal)?;
                    if let Some(acc) = self.users.get_mut(&u) {
                        acc.used_bytes = used;
                    }
                    self.dispersal_queue.push((u, hash));
                } else if self.store.get(Space::UserBlock, &hash).map(|(o, _)| o) != Some(u) {
                    return Err(Refusal::Unauthorized);
                }
                Ok(Response::Stored(hash.to_vec()))
            }
            Body::CommitRoot {
                base_root,
                new_root,
            } => {
                let u = self.user(cred, from, local)?;
                let (base, new) = (id32(&base_root)?, id32(&new_root)?);
                let adopt = self.adopt_next_root.remove(&u);
                let acc = self.users.get_mut(&u).ok_or(Refusal::Unauthorized)?;
                let committed = adopt || acc.root == base;
                if committed {
                    acc.root = new;
                }
                Ok(Response::RootState {
                    committed,
                    current_root: acc.root.to_vec(),
                })
            }
            Body::ReportIncident { hash } => {
                self.user(cred, from, local)?;
                self.incidents.push(id32(&hash)?);
                Ok(Response::Ack { freed: 0 })
            }
            Body::RenewGrant { grant_pub } => {
                self.user(cred, from, local)?;
                Ok(Response::GrantIssued(issue_grant(
                    &self.priv_node,
                    &id32(&grant_pub)?,
                    now,
                    &self.previous_node_ids,
                )))
            }
            Body::Delegate(d) => {
                self.user(cred, from, local)?;
                open_delegation(&d, now)?;
                if d.delegate_node_id != self.node_id {
                    return Err(Refusal::Unauthorized);
                }
                self.delegations.push(d);
                Ok(Response::Ack { freed: 0 })
            }
            Body::StoreFragment { data } => {
                let p = self.partner(from_node, now)?;
                let hash = hash_sha256(&data);
                if !self.store.contains(&hash) {
                    let st = self.partners.get(&p).ok_or(Refusal::Unauthorized)?;
                    if st.ledger.hosted_by_partner >= st.allowance {
                        return Err(Refusal::QuotaExceeded);
                    }
                    self.store
                        .put(Space::Fragment, &p, &hash, &data)
                        .map_err(store_refusal)?;
                    if let Some(st) = self.partners.get_mut(&p) {
                        st.ledger.hosted_by_partner += 1;
                    }
                } else if self.store.get(Space::Fragment, &hash).map(|(o, _)| o) != Some(p) {
                    return Err(Refusal::Unauthorized);
                }
                Ok(Response::FragmentReceipt {
                    hash: hash.to_vec(),
                    signature: sign_receipt(&self.priv_node, &hash, &p),
                })
            }
            Body::Challenge { hash, nonce } => {
                let p = self.partner(from_node, now)?;
                let f = self.owned_fragment(&hash, &p)?;
                let nonce: [u8; 32] = nonce.try_into().map_err(|_| Refusal::Malformed)?;
                Ok(Response::ChallengeResponse(
                    challenge_response(&f, &nonce).to_vec(),
                ))
            }
            Body::FetchFragment { hash } => {
                if cred.is_none() {
                    let p = self.partner(from_node, now)?;
                    return Ok(Response::BlockData(self.owned_fragment(&hash, &p)?));
                }
                // Secours : identifiant contrôlé avant tout accès disque.
                let grant = authorize_rescue(cred, from, from_node.as_ref(), local, now)?;
                if !self.limiter.allow(&grant.grant_pub, now) {
                    return Err(Refusal::RateLimited);
                }
                let (owner, data) = self
                    .store
                    .get(Space::Fragment, &id32(&hash)?)
                    .ok_or(Refusal::NotFound)?;
                let successors = &self.successors;
                if !covers(&grant, &owner, &|o| successors.get(o).copied()) {
                    return Err(Refusal::Unauthorized);
                }
                Ok(Response::BlockData(data))
            }
            Body::Tombstone {
                timestamp,
                hashes,
                signature,
            } => {
                let p = self.partner(from_node, now)?;
                if !hashes.len().is_multiple_of(32) {
                    return Err(Refusal::Malformed);
                }
                let notice = TombstoneNotice {
                    timestamp,
                    block_hashes: hashes.chunks(32).map(|c| c.try_into().unwrap()).collect(),
                    signature: signature.try_into().map_err(|_| Refusal::Malformed)?,
                };
                let store = &mut self.store;
                let st = self.partners.get_mut(&p).ok_or(Refusal::Unauthorized)?;
                let freed = apply_received(&mut st.ledger, &p, &notice, &mut |h| {
                    store.remove(Space::Fragment, &p, h)
                })
                .map_err(|e| match e {
                    TombstoneError::Replay => Refusal::Replayed,
                    TombstoneError::Signature(_) => Refusal::Unauthorized,
                })?;
                Ok(Response::Ack { freed })
            }
            Body::Probe { nonce } => Ok(Response::ProbeReply {
                nonce,
                accepting_partners: self.partner_policy.accept
                    && self.partners.len() < self.partner_policy.max_partners,
            }),
            Body::ProposePartnership {
                allowance_blocks,
                node_entry,
            } => Ok(Response::PartnershipAnswer {
                granted_blocks: self.propose(from_node, allowance_blocks, &node_entry, now),
            }),
            Body::Attach {
                salt,
                sig_pub_user,
                vdf_y,
                vdf_pi,
                signature,
            } => {
                let Some(Credential::User { user_id, proof }) = cred else {
                    return Err(Refusal::Unauthorized);
                };
                let pub_user = id32(user_id)?;
                if self.users.contains_key(&pub_user) {
                    // Déjà rattaché : réponse idempotente si l'identifiant est bon.
                    self.user(cred, from, local)?;
                    return Ok(Response::Attached {
                        quota_bytes: self.users[&pub_user].quota_bytes,
                    });
                }
                let p = self.attach_policy;
                if !p.enabled || salt.len() != 16 {
                    return Err(Refusal::Unauthorized);
                }
                let k = derive_k_attach_as_node(&self.priv_node, &pub_user, &salt)
                    .map_err(|_| Refusal::Unauthorized)?;
                if !verify_connector_proof(&k, from, local, proof) {
                    return Err(Refusal::Unauthorized);
                }
                let sig_pub = id32(&sig_pub_user)?;
                if self.used_attach_identities.contains(&sig_pub)
                    || !verify_attach_signature(&sig_pub, &pub_user, &self.node_id, &signature)
                {
                    return Err(Refusal::Unauthorized);
                }
                let identity = p2p_storage_core::vdf::tagged_identity(0, &sig_pub)
                    .map_err(|_| Refusal::Unauthorized)?;
                let proof = p2p_storage_core::vdf::VdfProof {
                    y: vdf_y,
                    pi: vdf_pi,
                };
                if !self.vdf.as_ref().is_some_and(|v| v(&identity, &proof)) {
                    return Err(Refusal::Unauthorized);
                }
                let used: u64 = self
                    .auto_attached
                    .iter()
                    .filter_map(|u| self.users.get(u))
                    .map(|u| u.quota_bytes)
                    .sum();
                if self.auto_attached.len() >= p.max_users || used + p.quota_bytes > p.budget_bytes
                {
                    return Err(Refusal::QuotaExceeded);
                }
                self.users.insert(
                    pub_user,
                    UserAccount {
                        salt,
                        quota_bytes: p.quota_bytes,
                        used_bytes: 0,
                        root: [0; 32],
                    },
                );
                self.auto_attached.insert(pub_user);
                self.used_attach_identities.insert(sig_pub);
                Ok(Response::Attached {
                    quota_bytes: p.quota_bytes,
                })
            }
        }
    }

    /// Proposition de partenariat : solde accordé (0 = refus).
    fn propose(&mut self, from_node: Option<Id>, requested: u64, entry: &[u8], now: u64) -> u64 {
        let Some(p) = from_node else { return 0 };
        if self.blacklisted.contains(&p) {
            return 0;
        }
        if let Some(st) = self.partners.get(&p) {
            return st.allowance;
        }
        let pol = self.partner_policy;
        if !pol.accept || self.partners.len() >= pol.max_partners {
            return 0;
        }
        let Some(vdf) = self.vdf.clone() else {
            return 0;
        };
        let check = |id: &[u8; 33], proof: &p2p_storage_core::vdf::VdfProof| Ok(vdf(id, proof));
        if p2p_storage_protocol::dht::accept_record(&p, entry, None, now, &check).is_err() {
            return 0;
        }
        let addrs = entry_multiaddrs(&p, entry);
        if addrs.is_empty() {
            return 0;
        }
        let granted = requested.min(pol.max_allowance_blocks);
        if granted == 0 {
            return 0;
        }
        self.partners.insert(
            p,
            PartnerState {
                allowance: granted,
                last_seen: now,
                ..Default::default()
            },
        );
        self.new_partners.push((p, addrs));
        granted
    }

    fn owned_fragment(&self, hash: &[u8], owner: &Id) -> Result<Vec<u8>, Refusal> {
        match self.store.get(Space::Fragment, &id32(hash)?) {
            Some((o, d)) if o == *owner => Ok(d),
            _ => Err(Refusal::NotFound),
        }
    }

    /// Purge les fragments des Nœuds silencieux depuis au moins
    /// `SILENT_NODE_RETENTION_SECONDS` ; rend le nombre de Nœuds purgés.
    pub fn purge_silent_partners(&mut self, now: u64) -> usize {
        let silent: Vec<Id> = self
            .partners
            .iter()
            .filter(|(_, s)| s.last_seen + SILENT_NODE_RETENTION_SECONDS <= now)
            .map(|(id, _)| *id)
            .collect();
        let owners = self.store.owners(Space::Fragment);
        let mut purged = 0;
        for p in silent.iter().filter(|p| owners.contains(p)) {
            self.store.remove_owner(Space::Fragment, p);
            if let Some(st) = self.partners.get_mut(p) {
                st.ledger.hosted_by_partner = 0;
            }
            purged += 1;
        }
        purged
    }
}

/// Multiaddrs d'échange de blocs d'un Nœud depuis son entrée DHT : adresse
/// TCP directe d'abord, puis les adresses publiées (QUIC, relais).
pub fn entry_multiaddrs(node_id: &Id, envelope: &[u8]) -> Vec<String> {
    let Some((addrs, direct)) = p2p_storage_protocol::entries::node_entry_addrs(envelope) else {
        return Vec::new();
    };
    let mut out: Vec<String> = direct
        .and_then(|(ip, port)| crate::partnering::multiaddr(node_id, &ip, port))
        .into_iter()
        .collect();
    for a in addrs {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// `ip/port` d'une entrée DHT Node.
pub fn entry_addr(envelope: &[u8]) -> Option<(String, u16)> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope).ok()?;
    let e = fbd::root_as_node_entry(env.payload()?.bytes()).ok()?;
    Some((e.ip()?.to_string(), e.port()))
}

/// Successeur annoncé par l'entrée DHT Node (enveloppe déjà validée par
/// l'adaptateur DHT) de `node_id`, si son `migration_pointer` est valide.
pub fn successor_from_node_entry(envelope: &[u8], node_id: &Id) -> Option<Id> {
    let env = flatbuffers::root::<fbd::DhtEnvelope>(envelope).ok()?;
    let e = fbd::root_as_node_entry(env.payload()?.bytes()).ok()?;
    let p = e.migration_pointer()?;
    let rec = e.pub_node_recovery()?;
    verify_migration_pointer(p, rec.bytes(), node_id, None)
        .ok()?
        .try_into()
        .ok()
}

/// Rafraîchit [`NodeService::successors`] depuis la DHT pour tous les Nœuds
/// propriétaires de fragments hébergés.
pub async fn refresh_successors(
    service: &Mutex<NodeService>,
    dht: &crate::dht_directory::DhtNode,
) -> Result<(), crate::dht_directory::DhtNodeError> {
    let owners: Vec<Id> = {
        let s = service.lock().unwrap();
        s.store.owners(Space::Fragment)
    };
    for owner in owners {
        let next = dht
            .get(owner.to_vec())
            .await?
            .and_then(|env| successor_from_node_entry(&env, &owner));
        let mut s = service.lock().unwrap();
        match next {
            Some(n) => s.successors.insert(owner, n),
            None => s.successors.remove(&owner),
        };
    }
    Ok(())
}

// ---------------------------------------------------------------- transport

/// `pub_node` d'un `PeerId` Ed25519 (Nœud), sinon `None` (Connecteur
/// éphémère compris : il n'est pas partenaire).
pub fn node_id_of(peer: &PeerId) -> Option<Id> {
    let mh = peer.as_ref();
    if mh.code() != 0 {
        return None;
    }
    identity::PublicKey::try_decode_protobuf(mh.digest())
        .ok()?
        .try_into_ed25519()
        .ok()
        .map(|k| k.to_bytes())
}

/// Trame préfixée `u32be` ; au-delà de `MAX_MESSAGE_BYTES`, le corps n'est
/// pas lu.
#[derive(Debug, Clone)]
pub enum Frame {
    Data(Vec<u8>),
    TooLarge,
}

/// Codec `/p2p-storage/blocks/1`.
#[derive(Debug, Clone, Default)]
pub struct FrameCodec;

async fn read_frame<T: futures::AsyncRead + Unpin + Send>(io: &mut T) -> std::io::Result<Frame> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MESSAGE_BYTES {
        return Ok(Frame::TooLarge);
    }
    let mut buf = vec![0u8; n];
    io.read_exact(&mut buf).await?;
    Ok(Frame::Data(buf))
}

async fn write_frame<T: futures::AsyncWrite + Unpin + Send>(
    io: &mut T,
    f: Frame,
) -> std::io::Result<()> {
    let Frame::Data(d) = f else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    io.write_all(&(d.len() as u32).to_be_bytes()).await?;
    io.write_all(&d).await?;
    io.close().await
}

#[async_trait::async_trait]
impl request_response::Codec for FrameCodec {
    type Protocol = StreamProtocol;
    type Request = Frame;
    type Response = Frame;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Frame>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Frame>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        f: Frame,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_frame(io, f).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        f: Frame,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_frame(io, f).await
    }
}

/// Erreurs de transport.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("réseau : {0}")]
    Network(String),
    #[error("adresse sans /p2p/<PeerId>")]
    NoPeerId,
    #[error("réponse refusée : {0}")]
    Refused(#[from] Refusal),
    #[error("service arrêté")]
    Stopped,
}

pub(crate) type Reply = oneshot::Sender<Result<Response, ExchangeError>>;

pub(crate) enum Cmd {
    ListenAddr(oneshot::Sender<Option<Multiaddr>>),
    Request(Box<(Multiaddr, Request, Reply)>),
}

type Behaviour = request_response::Behaviour<FrameCodec>;

/// Construit un swarm d'échange de blocs (partagé avec le Connecteur par
/// copie de ce motif : identité fournie, TCP + Noise + Yamux).
fn build_swarm(keypair: identity::Keypair) -> Result<Swarm<Behaviour>, ExchangeError> {
    let net = |e: &dyn std::fmt::Display| ExchangeError::Network(e.to_string());
    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| net(&e))?
        .with_behaviour(|_| {
            request_response::Behaviour::new(
                [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
            )
        })
        .map_err(|e| net(&e))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

/// Serveur d'échange de blocs d'un Nœud (et client vers ses partenaires).
pub struct BlockServer {
    peer_id: PeerId,
    tx: mpsc::Sender<Cmd>,
}

impl BlockServer {
    /// Démarre l'écoute sur `listen` avec l'identité `priv_node` du service.
    pub async fn start(
        node_seed: [u8; 32],
        listen: Multiaddr,
        service: Arc<Mutex<NodeService>>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, ExchangeError> {
        let net = |e: &dyn std::fmt::Display| ExchangeError::Network(e.to_string());
        let secret =
            identity::ed25519::SecretKey::try_from_bytes(node_seed).map_err(|e| net(&e))?;
        let keypair = identity::Keypair::from(identity::ed25519::Keypair::from(secret));
        let peer_id = keypair.public().to_peer_id();
        let mut swarm = build_swarm(keypair)?;
        swarm.listen_on(listen).map_err(|e| net(&e))?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(run(swarm, rx, Some(service), clock));
        Ok(Self { peer_id, tx })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Poignée sur une boucle réseau existante (`crate::net`).
    pub(crate) fn from_parts(peer_id: PeerId, tx: mpsc::Sender<Cmd>) -> Self {
        Self { peer_id, tx }
    }

    /// Première adresse d'écoute, suffixée de `/p2p/<PeerId>`.
    pub async fn listen_addr(&self) -> Option<Multiaddr> {
        listen_addr(&self.tx, self.peer_id).await
    }

    /// Envoie une requête à un pair (`addr` suffixée de `/p2p/<PeerId>`).
    pub async fn request(&self, addr: Multiaddr, req: Request) -> Result<Response, ExchangeError> {
        request(&self.tx, addr, req).await
    }
}

async fn listen_addr(tx: &mpsc::Sender<Cmd>, peer_id: PeerId) -> Option<Multiaddr> {
    for _ in 0..50 {
        let (r, rx) = oneshot::channel();
        tx.send(Cmd::ListenAddr(r)).await.ok()?;
        if let Some(a) = rx.await.ok()? {
            return Some(a.with(Protocol::P2p(peer_id)));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

async fn request(
    tx: &mpsc::Sender<Cmd>,
    addr: Multiaddr,
    req: Request,
) -> Result<Response, ExchangeError> {
    let (r, rx) = oneshot::channel();
    tx.send(Cmd::Request(Box::new((addr, req, r))))
        .await
        .map_err(|_| ExchangeError::Stopped)?;
    rx.await.map_err(|_| ExchangeError::Stopped)?
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(p)) => Some(p),
        _ => None,
    }
}

fn decode_frame(f: Frame) -> Result<Response, ExchangeError> {
    match f {
        Frame::TooLarge => Err(Refusal::TooLarge.into()),
        Frame::Data(d) => Ok(decode_response(&d)?),
    }
}

/// Opérations du swarm nécessaires à l'échange de blocs (swarm dédié, ou
/// swarm unique du Nœud : `crate::net`).
pub(crate) trait RrHost {
    fn rr(&mut self) -> &mut request_response::Behaviour<FrameCodec>;
    fn connected(&self, peer: &PeerId) -> bool;
    fn dial_addr(&mut self, addr: Multiaddr) -> Result<(), String>;
    fn listen_addr(&self) -> Option<Multiaddr>;
}

impl RrHost for Swarm<Behaviour> {
    fn rr(&mut self) -> &mut request_response::Behaviour<FrameCodec> {
        self.behaviour_mut()
    }
    fn connected(&self, peer: &PeerId) -> bool {
        self.is_connected(peer)
    }
    fn dial_addr(&mut self, addr: Multiaddr) -> Result<(), String> {
        self.dial(addr).map_err(|e| e.to_string())
    }
    fn listen_addr(&self) -> Option<Multiaddr> {
        self.listeners().next().cloned()
    }
}

/// Machine d'état de l'échange de blocs, indépendante du swarm.
pub(crate) struct ExchangeLoop {
    local: PeerId,
    service: Option<Arc<Mutex<NodeService>>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    waiting: HashMap<PeerId, Vec<(Vec<u8>, Reply)>>,
    inflight: HashMap<OutboundRequestId, Reply>,
    peer_ips: HashMap<PeerId, IpAddr>,
}

impl ExchangeLoop {
    pub(crate) fn new(
        local: PeerId,
        service: Option<Arc<Mutex<NodeService>>>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            local,
            service,
            clock,
            waiting: HashMap::new(),
            inflight: HashMap::new(),
            peer_ips: HashMap::new(),
        }
    }

    pub(crate) fn on_cmd(&mut self, sw: &mut dyn RrHost, cmd: Cmd) {
        match cmd {
            Cmd::ListenAddr(r) => {
                let _ = r.send(sw.listen_addr());
            }
            Cmd::Request(b) => {
                let (addr, req, reply) = *b;
                let Some(peer) = peer_of(&addr) else {
                    let _ = reply.send(Err(ExchangeError::NoPeerId));
                    return;
                };
                let bytes = encode_request(&req);
                if bytes.len() > MAX_MESSAGE_BYTES {
                    let _ = reply.send(Err(Refusal::TooLarge.into()));
                    return;
                }
                if sw.connected(&peer) {
                    let id = sw.rr().send_request(&peer, Frame::Data(bytes));
                    self.inflight.insert(id, reply);
                } else {
                    let first = !self.waiting.contains_key(&peer);
                    self.waiting.entry(peer).or_default().push((bytes, reply));
                    if first {
                        if let Err(e) = sw.dial_addr(addr) {
                            for (_, r) in self.waiting.remove(&peer).unwrap_or_default() {
                                let _ = r.send(Err(ExchangeError::Network(e.clone())));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Connexion établie : adresse IP du pair (hors relais), requêtes en attente.
    pub(crate) fn on_connected(&mut self, sw: &mut dyn RrHost, peer: PeerId, remote: &Multiaddr) {
        if !remote.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
            for p in remote.iter() {
                match p {
                    Protocol::Ip4(v) => {
                        self.peer_ips.insert(peer, IpAddr::V4(v));
                    }
                    Protocol::Ip6(v) => {
                        self.peer_ips.insert(peer, IpAddr::V6(v));
                    }
                    _ => {}
                }
            }
        }
        for (bytes, r) in self.waiting.remove(&peer).unwrap_or_default() {
            let id = sw.rr().send_request(&peer, Frame::Data(bytes));
            self.inflight.insert(id, r);
        }
    }

    pub(crate) fn on_dial_error(&mut self, peer: PeerId, error: String) {
        for (_, r) in self.waiting.remove(&peer).unwrap_or_default() {
            let _ = r.send(Err(ExchangeError::Network(error.clone())));
        }
    }

    pub(crate) fn on_event(
        &mut self,
        sw: &mut dyn RrHost,
        ev: request_response::Event<Frame, Frame>,
    ) {
        match ev {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let resp = match (&self.service, request) {
                        (None, _) => Response::Failure(Refusal::Unauthorized),
                        (Some(_), Frame::TooLarge) => Response::Failure(Refusal::TooLarge),
                        (Some(s), Frame::Data(d)) => match decode_request(&d) {
                            Err(e) => Response::Failure(e),
                            Ok(req) => {
                                let user = match &req.credential {
                                    Some(Credential::User { user_id, .. }) => {
                                        <[u8; 32]>::try_from(user_id.as_slice()).ok()
                                    }
                                    _ => None,
                                };
                                let mut sv = s.lock().unwrap();
                                let r = sv.handle(
                                    &peer.to_bytes(),
                                    node_id_of(&peer),
                                    &self.local.to_bytes(),
                                    req,
                                    (self.clock)(),
                                );
                                if let (Some(u), Some(ip), false) = (
                                    user,
                                    self.peer_ips.get(&peer),
                                    matches!(r, Response::Failure(_)),
                                ) {
                                    if sv.record_user_ips && sv.users.contains_key(&u) {
                                        sv.last_user_ip.insert(u, ip.to_string());
                                    }
                                }
                                r
                            }
                        },
                    };
                    let _ = sw
                        .rr()
                        .send_response(channel, Frame::Data(encode_response(&resp)));
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(r) = self.inflight.remove(&request_id) {
                        let _ = r.send(decode_frame(response));
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(r) = self.inflight.remove(&request_id) {
                    let _ = r.send(Err(ExchangeError::Network(error.to_string())));
                }
            }
            _ => {}
        }
    }
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Cmd>,
    service: Option<Arc<Mutex<NodeService>>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) {
    let mut el = ExchangeLoop::new(*swarm.local_peer_id(), service, clock);
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => return,
                Some(c) => el.on_cmd(&mut swarm, c),
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    el.on_connected(&mut swarm, peer_id, endpoint.get_remote_address());
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(p), error, .. } => {
                    el.on_dial_error(p, error.to_string());
                }
                SwarmEvent::Behaviour(ev) => el.on_event(&mut swarm, ev),
                _ => {}
            }
        }
    }
}
