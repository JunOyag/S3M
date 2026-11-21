//! Protocole d'échange de blocs — id `protocols.echange-blocs`, partie
//! commune Nœud/Connecteur, sans I/O. Réf. spec :
//! docs/04-protocols/echange-blocs.md.
//!
//! - Modèle Rust des requêtes/réponses et leur codage FlatBuffers
//!   (`BlockRequest` « BREQ », `BlockResponse` « BRSP »).
//! - Preuve Connecteur → Nœud : `KDF(K_attach, "connector-auth", —,
//!   peer_connecteur, peer_noeud)`.
//! - Autorisation de secours (`RescueGrant`) : émission, vérification,
//!   preuve de session, délégation, règle de couverture (révocation par
//!   pointeur de migration).
//! - Reçu de fragment, limiteur de débit de secours.

use std::collections::HashMap;

use flatbuffers::{FlatBufferBuilder, UnionWIPOffset, WIPOffset};
use s3m_core::labels::CONNECTOR_AUTH;
use s3m_core::symmetric_suite::{canonical_encode, kdf};

use crate::dht::{sign, verify_signature};
use crate::fb::exchange as fb;

/// Nom du protocole libp2p requête/réponse.
pub const PROTOCOL: &str = "/s3m/blocks/1";
/// Taille maximale d'un message (requête ou réponse), préfixe exclu.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;
/// Version courante des messages.
pub const VERSION: u16 = 1;
/// Durée de validité d'une autorisation de secours (6 mois).
pub const GRANT_TTL_SECONDS: u64 = 15_552_000;
/// Conservation minimale des fragments d'un Nœud silencieux (6 mois).
pub const SILENT_NODE_RETENTION_SECONDS: u64 = 15_552_000;
/// Débit de secours : jetons par seconde et par `grant_pub`.
pub const RESCUE_RATE_PER_SECOND: u64 = 64;
/// Débit de secours : rafale maximale.
pub const RESCUE_BURST: u64 = 256;

pub const SIG_LABEL_RESCUE_GRANT: &str = "s3m/sig/rescue-grant/v1";
pub const SIG_LABEL_RESCUE_SESSION: &str = "s3m/sig/rescue-session/v1";
pub const SIG_LABEL_RESCUE_DELEGATION: &str = "s3m/sig/rescue-delegation/v1";
pub const SIG_LABEL_FRAGMENT_RECEIPT: &str = "s3m/sig/fragment-receipt/v1";
pub const SIG_LABEL_ATTACH: &str = "s3m/sig/attach/v1";
pub const SIG_LABEL_EMERGENCY_DEPOSIT: &str = "s3m/sig/emergency-deposit/v1";
pub const SIG_LABEL_EMERGENCY_RELEASE: &str = "s3m/sig/emergency-release/v1";
/// Nombre maximal de hashes d'un `EmergencyRelease`.
pub const MAX_RELEASE_HASHES: usize = 1024;

/// Identifiant de 32 o (`pub_node`, `pub_user`, `grant_pub`, hash).
pub type Id = [u8; 32];

/// Refus (`ErrorCode` du schéma).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("introuvable")]
    NotFound,
    #[error("non autorisé")]
    Unauthorized,
    #[error("quota dépassé")]
    QuotaExceeded,
    #[error("message trop volumineux")]
    TooLarge,
    #[error("message mal formé")]
    Malformed,
    #[error("débit de secours dépassé")]
    RateLimited,
    #[error("avis rejoué")]
    Replayed,
}

impl Refusal {
    fn to_fb(self) -> fb::ErrorCode {
        match self {
            Self::NotFound => fb::ErrorCode::NotFound,
            Self::Unauthorized => fb::ErrorCode::Unauthorized,
            Self::QuotaExceeded => fb::ErrorCode::QuotaExceeded,
            Self::TooLarge => fb::ErrorCode::TooLarge,
            Self::Malformed => fb::ErrorCode::Malformed,
            Self::RateLimited => fb::ErrorCode::RateLimited,
            Self::Replayed => fb::ErrorCode::Replayed,
        }
    }

    fn from_fb(c: fb::ErrorCode) -> Result<Self, Refusal> {
        Ok(match c {
            fb::ErrorCode::NotFound => Self::NotFound,
            fb::ErrorCode::Unauthorized => Self::Unauthorized,
            fb::ErrorCode::QuotaExceeded => Self::QuotaExceeded,
            fb::ErrorCode::TooLarge => Self::TooLarge,
            fb::ErrorCode::Malformed => Self::Malformed,
            fb::ErrorCode::RateLimited => Self::RateLimited,
            fb::ErrorCode::Replayed => Self::Replayed,
            _ => return Err(Refusal::Malformed),
        })
    }
}

/// `SignedRescueGrant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGrant {
    pub grant: Vec<u8>,
    pub signature: Vec<u8>,
}

/// `DelegatedCredential` (aussi corps de `Delegate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub grant: SignedGrant,
    pub delegate_node_id: Vec<u8>,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

/// Union `Credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    User {
        user_id: Vec<u8>,
        proof: Vec<u8>,
    },
    Rescue {
        grant: SignedGrant,
        proof: Vec<u8>,
    },
    Delegated(Delegation),
    /// Dépôt d'urgence (`protocols.espace-secours`).
    Emergency {
        sig_pub_user: Vec<u8>,
        vdf_y: Vec<u8>,
        vdf_pi: Vec<u8>,
        emergency_pub: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// Union `RequestBody`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    GetBlock {
        hash: Vec<u8>,
    },
    PutBlock {
        data: Vec<u8>,
    },
    CommitRoot {
        base_root: Vec<u8>,
        new_root: Vec<u8>,
    },
    ReportIncident {
        hash: Vec<u8>,
    },
    RenewGrant {
        grant_pub: Vec<u8>,
    },
    Delegate(Delegation),
    StoreFragment {
        data: Vec<u8>,
    },
    Challenge {
        hash: Vec<u8>,
        nonce: Vec<u8>,
    },
    FetchFragment {
        hash: Vec<u8>,
    },
    Tombstone {
        timestamp: u64,
        hashes: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Import d'un volume (`protocols.gestion-volumes`) : SHA-256 concaténés.
    OwnershipQuery {
        hashes: Vec<u8>,
    },
    /// Mesure de disponibilité/vitesse (`protocols.partenariat-automatique`).
    Probe {
        nonce: Vec<u8>,
    },
    /// Proposition de partenariat, avec l'entrée DHT Node du demandeur.
    ProposePartnership {
        allowance_blocks: u64,
        node_entry: Vec<u8>,
    },
    /// Rattachement automatique d'un Utilisateur.
    Attach {
        salt: Vec<u8>,
        sig_pub_user: Vec<u8>,
        vdf_y: Vec<u8>,
        vdf_pi: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Dépôt d'un bloc chez un partenaire de secours.
    EmergencyPut {
        data: Vec<u8>,
    },
    /// Relecture d'un bloc déposé sous `emergency_pub`.
    EmergencyGet {
        emergency_pub: Vec<u8>,
        hash: Vec<u8>,
    },
    /// Libération signée par `sig_priv_emergency`.
    EmergencyRelease {
        emergency_pub: Vec<u8>,
        timestamp: u64,
        hashes: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// `BlockRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub credential: Option<Credential>,
    pub body: Body,
}

/// Union `ResponseBody`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Failure(Refusal),
    BlockData(Vec<u8>),
    Stored(Vec<u8>),
    RootState {
        committed: bool,
        current_root: Vec<u8>,
        /// Quota et occupation de l'Utilisateur (0 : non communiqué).
        quota_bytes: u64,
        used_bytes: u64,
    },
    FragmentReceipt {
        hash: Vec<u8>,
        signature: Vec<u8>,
    },
    ChallengeResponse(Vec<u8>),
    Ack {
        freed: u64,
    },
    GrantIssued(SignedGrant),
    ProbeReply {
        nonce: Vec<u8>,
        accepting_partners: bool,
    },
    /// 0 : refusé.
    PartnershipAnswer {
        granted_blocks: u64,
    },
    Attached {
        quota_bytes: u64,
    },
    /// Un bit par hash demandé (bit `i % 8` de l'octet `i / 8`).
    OwnershipAnswer {
        owned: Vec<u8>,
    },
}

// ------------------------------------------------------------------ codage

fn signed_grant_fb<'a>(
    b: &mut FlatBufferBuilder<'a>,
    g: &SignedGrant,
) -> WIPOffset<fb::SignedRescueGrant<'a>> {
    let grant = b.create_vector(&g.grant);
    let signature = b.create_vector(&g.signature);
    fb::SignedRescueGrant::create(
        b,
        &fb::SignedRescueGrantArgs {
            grant: Some(grant),
            signature: Some(signature),
        },
    )
}

fn delegation_fb<'a>(
    b: &mut FlatBufferBuilder<'a>,
    d: &Delegation,
) -> WIPOffset<fb::DelegatedCredential<'a>> {
    let grant = signed_grant_fb(b, &d.grant);
    let delegate = b.create_vector(&d.delegate_node_id);
    let signature = b.create_vector(&d.signature);
    fb::DelegatedCredential::create(
        b,
        &fb::DelegatedCredentialArgs {
            grant: Some(grant),
            delegate_node_id: Some(delegate),
            expires_at: d.expires_at,
            signature: Some(signature),
        },
    )
}

/// Encode une requête.
pub fn encode_request(r: &Request) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let (ct, cred): (fb::Credential, Option<WIPOffset<UnionWIPOffset>>) = match &r.credential {
        None => (fb::Credential::NONE, None),
        Some(Credential::User { user_id, proof }) => {
            let u = b.create_vector(user_id);
            let p = b.create_vector(proof);
            let o = fb::UserCredential::create(
                &mut b,
                &fb::UserCredentialArgs {
                    user_id: Some(u),
                    proof: Some(p),
                },
            );
            (fb::Credential::UserCredential, Some(o.as_union_value()))
        }
        Some(Credential::Rescue { grant, proof }) => {
            let g = signed_grant_fb(&mut b, grant);
            let p = b.create_vector(proof);
            let o = fb::RescueCredential::create(
                &mut b,
                &fb::RescueCredentialArgs {
                    grant: Some(g),
                    proof: Some(p),
                },
            );
            (fb::Credential::RescueCredential, Some(o.as_union_value()))
        }
        Some(Credential::Delegated(d)) => {
            let o = delegation_fb(&mut b, d);
            (
                fb::Credential::DelegatedCredential,
                Some(o.as_union_value()),
            )
        }
        Some(Credential::Emergency {
            sig_pub_user,
            vdf_y,
            vdf_pi,
            emergency_pub,
            signature,
        }) => {
            let k = b.create_vector(sig_pub_user);
            let y = b.create_vector(vdf_y);
            let pi = b.create_vector(vdf_pi);
            let e = b.create_vector(emergency_pub);
            let sg = b.create_vector(signature);
            let o = fb::EmergencyCredential::create(
                &mut b,
                &fb::EmergencyCredentialArgs {
                    sig_pub_user: Some(k),
                    vdf_y: Some(y),
                    vdf_pi: Some(pi),
                    emergency_pub: Some(e),
                    signature: Some(sg),
                },
            );
            (
                fb::Credential::EmergencyCredential,
                Some(o.as_union_value()),
            )
        }
    };
    let (bt, body) = match &r.body {
        Body::GetBlock { hash } => {
            let h = b.create_vector(hash);
            let o = fb::GetBlock::create(&mut b, &fb::GetBlockArgs { hash: Some(h) });
            (fb::RequestBody::GetBlock, o.as_union_value())
        }
        Body::PutBlock { data } => {
            let d = b.create_vector(data);
            let o = fb::PutBlock::create(&mut b, &fb::PutBlockArgs { data: Some(d) });
            (fb::RequestBody::PutBlock, o.as_union_value())
        }
        Body::CommitRoot {
            base_root,
            new_root,
        } => {
            let x = b.create_vector(base_root);
            let y = b.create_vector(new_root);
            let o = fb::CommitRoot::create(
                &mut b,
                &fb::CommitRootArgs {
                    base_root: Some(x),
                    new_root: Some(y),
                },
            );
            (fb::RequestBody::CommitRoot, o.as_union_value())
        }
        Body::ReportIncident { hash } => {
            let h = b.create_vector(hash);
            let o = fb::ReportIncident::create(&mut b, &fb::ReportIncidentArgs { hash: Some(h) });
            (fb::RequestBody::ReportIncident, o.as_union_value())
        }
        Body::RenewGrant { grant_pub } => {
            let g = b.create_vector(grant_pub);
            let o = fb::RenewGrant::create(&mut b, &fb::RenewGrantArgs { grant_pub: Some(g) });
            (fb::RequestBody::RenewGrant, o.as_union_value())
        }
        Body::Delegate(d) => {
            let c = delegation_fb(&mut b, d);
            let o = fb::Delegate::create(
                &mut b,
                &fb::DelegateArgs {
                    credential: Some(c),
                },
            );
            (fb::RequestBody::Delegate, o.as_union_value())
        }
        Body::StoreFragment { data } => {
            let d = b.create_vector(data);
            let o = fb::StoreFragment::create(&mut b, &fb::StoreFragmentArgs { data: Some(d) });
            (fb::RequestBody::StoreFragment, o.as_union_value())
        }
        Body::Challenge { hash, nonce } => {
            let h = b.create_vector(hash);
            let n = b.create_vector(nonce);
            let o = fb::Challenge::create(
                &mut b,
                &fb::ChallengeArgs {
                    hash: Some(h),
                    nonce: Some(n),
                },
            );
            (fb::RequestBody::Challenge, o.as_union_value())
        }
        Body::FetchFragment { hash } => {
            let h = b.create_vector(hash);
            let o = fb::FetchFragment::create(&mut b, &fb::FetchFragmentArgs { hash: Some(h) });
            (fb::RequestBody::FetchFragment, o.as_union_value())
        }
        Body::Tombstone {
            timestamp,
            hashes,
            signature,
        } => {
            let h = b.create_vector(hashes);
            let s = b.create_vector(signature);
            let o = fb::Tombstone::create(
                &mut b,
                &fb::TombstoneArgs {
                    timestamp: *timestamp,
                    hashes: Some(h),
                    signature: Some(s),
                },
            );
            (fb::RequestBody::Tombstone, o.as_union_value())
        }
        Body::OwnershipQuery { hashes } => {
            let h = b.create_vector(hashes);
            let o = fb::OwnershipQuery::create(&mut b, &fb::OwnershipQueryArgs { hashes: Some(h) });
            (fb::RequestBody::OwnershipQuery, o.as_union_value())
        }
        Body::Probe { nonce } => {
            let n = b.create_vector(nonce);
            let o = fb::Probe::create(&mut b, &fb::ProbeArgs { nonce: Some(n) });
            (fb::RequestBody::Probe, o.as_union_value())
        }
        Body::ProposePartnership {
            allowance_blocks,
            node_entry,
        } => {
            let e = b.create_vector(node_entry);
            let o = fb::ProposePartnership::create(
                &mut b,
                &fb::ProposePartnershipArgs {
                    allowance_blocks: *allowance_blocks,
                    node_entry: Some(e),
                },
            );
            (fb::RequestBody::ProposePartnership, o.as_union_value())
        }
        Body::Attach {
            salt,
            sig_pub_user,
            vdf_y,
            vdf_pi,
            signature,
        } => {
            let s = b.create_vector(salt);
            let k = b.create_vector(sig_pub_user);
            let y = b.create_vector(vdf_y);
            let pi = b.create_vector(vdf_pi);
            let sg = b.create_vector(signature);
            let o = fb::Attach::create(
                &mut b,
                &fb::AttachArgs {
                    salt: Some(s),
                    sig_pub_user: Some(k),
                    vdf_y: Some(y),
                    vdf_pi: Some(pi),
                    signature: Some(sg),
                },
            );
            (fb::RequestBody::Attach, o.as_union_value())
        }
        Body::EmergencyPut { data } => {
            let d = b.create_vector(data);
            let o = fb::EmergencyPut::create(&mut b, &fb::EmergencyPutArgs { data: Some(d) });
            (fb::RequestBody::EmergencyPut, o.as_union_value())
        }
        Body::EmergencyGet {
            emergency_pub,
            hash,
        } => {
            let e = b.create_vector(emergency_pub);
            let h = b.create_vector(hash);
            let o = fb::EmergencyGet::create(
                &mut b,
                &fb::EmergencyGetArgs {
                    emergency_pub: Some(e),
                    hash: Some(h),
                },
            );
            (fb::RequestBody::EmergencyGet, o.as_union_value())
        }
        Body::EmergencyRelease {
            emergency_pub,
            timestamp,
            hashes,
            signature,
        } => {
            let e = b.create_vector(emergency_pub);
            let h = b.create_vector(hashes);
            let sg = b.create_vector(signature);
            let o = fb::EmergencyRelease::create(
                &mut b,
                &fb::EmergencyReleaseArgs {
                    emergency_pub: Some(e),
                    timestamp: *timestamp,
                    hashes: Some(h),
                    signature: Some(sg),
                },
            );
            (fb::RequestBody::EmergencyRelease, o.as_union_value())
        }
    };
    let root = fb::BlockRequest::create(
        &mut b,
        &fb::BlockRequestArgs {
            version: VERSION,
            credential_type: ct,
            credential: cred,
            body_type: bt,
            body: Some(body),
        },
    );
    fb::finish_block_request_buffer(&mut b, root);
    b.finished_data().to_vec()
}

fn bytes(v: Option<flatbuffers::Vector<'_, u8>>) -> Vec<u8> {
    v.map(|x| x.bytes().to_vec()).unwrap_or_default()
}

fn signed_grant_of(g: Option<fb::SignedRescueGrant<'_>>) -> Result<SignedGrant, Refusal> {
    let g = g.ok_or(Refusal::Malformed)?;
    Ok(SignedGrant {
        grant: bytes(g.grant()),
        signature: bytes(g.signature()),
    })
}

fn delegation_of(d: Option<fb::DelegatedCredential<'_>>) -> Result<Delegation, Refusal> {
    let d = d.ok_or(Refusal::Malformed)?;
    Ok(Delegation {
        grant: signed_grant_of(d.grant())?,
        delegate_node_id: bytes(d.delegate_node_id()),
        expires_at: d.expires_at(),
        signature: bytes(d.signature()),
    })
}

/// Décode une requête (taille, identifiant de fichier, version).
pub fn decode_request(buf: &[u8]) -> Result<Request, Refusal> {
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(Refusal::TooLarge);
    }
    if !fb::block_request_buffer_has_identifier(buf) {
        return Err(Refusal::Malformed);
    }
    let r = fb::root_as_block_request(buf).map_err(|_| Refusal::Malformed)?;
    if r.version() != VERSION {
        return Err(Refusal::Malformed);
    }
    let credential = match r.credential_type() {
        fb::Credential::NONE => None,
        fb::Credential::UserCredential => {
            let c = r
                .credential_as_user_credential()
                .ok_or(Refusal::Malformed)?;
            Some(Credential::User {
                user_id: bytes(c.user_id()),
                proof: bytes(c.proof()),
            })
        }
        fb::Credential::RescueCredential => {
            let c = r
                .credential_as_rescue_credential()
                .ok_or(Refusal::Malformed)?;
            Some(Credential::Rescue {
                grant: signed_grant_of(c.grant())?,
                proof: bytes(c.proof()),
            })
        }
        fb::Credential::DelegatedCredential => Some(Credential::Delegated(delegation_of(
            r.credential_as_delegated_credential(),
        )?)),
        fb::Credential::EmergencyCredential => {
            let c = r
                .credential_as_emergency_credential()
                .ok_or(Refusal::Malformed)?;
            Some(Credential::Emergency {
                sig_pub_user: bytes(c.sig_pub_user()),
                vdf_y: bytes(c.vdf_y()),
                vdf_pi: bytes(c.vdf_pi()),
                emergency_pub: bytes(c.emergency_pub()),
                signature: bytes(c.signature()),
            })
        }
        _ => return Err(Refusal::Malformed),
    };
    let m = Refusal::Malformed;
    let body = match r.body_type() {
        fb::RequestBody::GetBlock => Body::GetBlock {
            hash: bytes(r.body_as_get_block().ok_or(m)?.hash()),
        },
        fb::RequestBody::PutBlock => Body::PutBlock {
            data: bytes(r.body_as_put_block().ok_or(m)?.data()),
        },
        fb::RequestBody::CommitRoot => {
            let c = r.body_as_commit_root().ok_or(m)?;
            Body::CommitRoot {
                base_root: bytes(c.base_root()),
                new_root: bytes(c.new_root()),
            }
        }
        fb::RequestBody::ReportIncident => Body::ReportIncident {
            hash: bytes(r.body_as_report_incident().ok_or(m)?.hash()),
        },
        fb::RequestBody::RenewGrant => Body::RenewGrant {
            grant_pub: bytes(r.body_as_renew_grant().ok_or(m)?.grant_pub()),
        },
        fb::RequestBody::Delegate => {
            Body::Delegate(delegation_of(r.body_as_delegate().ok_or(m)?.credential())?)
        }
        fb::RequestBody::StoreFragment => Body::StoreFragment {
            data: bytes(r.body_as_store_fragment().ok_or(m)?.data()),
        },
        fb::RequestBody::Challenge => {
            let c = r.body_as_challenge().ok_or(m)?;
            Body::Challenge {
                hash: bytes(c.hash()),
                nonce: bytes(c.nonce()),
            }
        }
        fb::RequestBody::FetchFragment => Body::FetchFragment {
            hash: bytes(r.body_as_fetch_fragment().ok_or(m)?.hash()),
        },
        fb::RequestBody::Tombstone => {
            let t = r.body_as_tombstone().ok_or(m)?;
            Body::Tombstone {
                timestamp: t.timestamp(),
                hashes: bytes(t.hashes()),
                signature: bytes(t.signature()),
            }
        }
        fb::RequestBody::OwnershipQuery => Body::OwnershipQuery {
            hashes: bytes(r.body_as_ownership_query().ok_or(m)?.hashes()),
        },
        fb::RequestBody::Probe => Body::Probe {
            nonce: bytes(r.body_as_probe().ok_or(m)?.nonce()),
        },
        fb::RequestBody::ProposePartnership => {
            let x = r.body_as_propose_partnership().ok_or(m)?;
            Body::ProposePartnership {
                allowance_blocks: x.allowance_blocks(),
                node_entry: bytes(x.node_entry()),
            }
        }
        fb::RequestBody::Attach => {
            let x = r.body_as_attach().ok_or(m)?;
            Body::Attach {
                salt: bytes(x.salt()),
                sig_pub_user: bytes(x.sig_pub_user()),
                vdf_y: bytes(x.vdf_y()),
                vdf_pi: bytes(x.vdf_pi()),
                signature: bytes(x.signature()),
            }
        }
        fb::RequestBody::EmergencyPut => Body::EmergencyPut {
            data: bytes(r.body_as_emergency_put().ok_or(m)?.data()),
        },
        fb::RequestBody::EmergencyGet => {
            let x = r.body_as_emergency_get().ok_or(m)?;
            Body::EmergencyGet {
                emergency_pub: bytes(x.emergency_pub()),
                hash: bytes(x.hash()),
            }
        }
        fb::RequestBody::EmergencyRelease => {
            let x = r.body_as_emergency_release().ok_or(m)?;
            Body::EmergencyRelease {
                emergency_pub: bytes(x.emergency_pub()),
                timestamp: x.timestamp(),
                hashes: bytes(x.hashes()),
                signature: bytes(x.signature()),
            }
        }
        _ => return Err(m),
    };
    Ok(Request { credential, body })
}

/// Encode une réponse.
pub fn encode_response(r: &Response) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let (t, o) = match r {
        Response::Failure(code) => {
            let o = fb::Failure::create(&mut b, &fb::FailureArgs { code: code.to_fb() });
            (fb::ResponseBody::Failure, o.as_union_value())
        }
        Response::BlockData(data) => {
            let d = b.create_vector(data);
            let o = fb::BlockData::create(&mut b, &fb::BlockDataArgs { data: Some(d) });
            (fb::ResponseBody::BlockData, o.as_union_value())
        }
        Response::Stored(hash) => {
            let h = b.create_vector(hash);
            let o = fb::Stored::create(&mut b, &fb::StoredArgs { hash: Some(h) });
            (fb::ResponseBody::Stored, o.as_union_value())
        }
        Response::RootState {
            committed,
            current_root,
            quota_bytes,
            used_bytes,
        } => {
            let c = b.create_vector(current_root);
            let o = fb::RootState::create(
                &mut b,
                &fb::RootStateArgs {
                    committed: *committed,
                    current_root: Some(c),
                    quota_bytes: *quota_bytes,
                    used_bytes: *used_bytes,
                },
            );
            (fb::ResponseBody::RootState, o.as_union_value())
        }
        Response::FragmentReceipt { hash, signature } => {
            let h = b.create_vector(hash);
            let s = b.create_vector(signature);
            let o = fb::FragmentReceipt::create(
                &mut b,
                &fb::FragmentReceiptArgs {
                    hash: Some(h),
                    signature: Some(s),
                },
            );
            (fb::ResponseBody::FragmentReceipt, o.as_union_value())
        }
        Response::ChallengeResponse(digest) => {
            let d = b.create_vector(digest);
            let o = fb::ChallengeResponse::create(
                &mut b,
                &fb::ChallengeResponseArgs { digest: Some(d) },
            );
            (fb::ResponseBody::ChallengeResponse, o.as_union_value())
        }
        Response::Ack { freed } => {
            let o = fb::Ack::create(&mut b, &fb::AckArgs { freed: *freed });
            (fb::ResponseBody::Ack, o.as_union_value())
        }
        Response::GrantIssued(g) => {
            let g = signed_grant_fb(&mut b, g);
            let o = fb::GrantIssued::create(&mut b, &fb::GrantIssuedArgs { grant: Some(g) });
            (fb::ResponseBody::GrantIssued, o.as_union_value())
        }
        Response::ProbeReply {
            nonce,
            accepting_partners,
        } => {
            let n = b.create_vector(nonce);
            let o = fb::ProbeReply::create(
                &mut b,
                &fb::ProbeReplyArgs {
                    nonce: Some(n),
                    accepting_partners: *accepting_partners,
                },
            );
            (fb::ResponseBody::ProbeReply, o.as_union_value())
        }
        Response::OwnershipAnswer { owned } => {
            let v = b.create_vector(owned);
            let o =
                fb::OwnershipAnswer::create(&mut b, &fb::OwnershipAnswerArgs { owned: Some(v) });
            (fb::ResponseBody::OwnershipAnswer, o.as_union_value())
        }
        Response::PartnershipAnswer { granted_blocks } => {
            let o = fb::PartnershipAnswer::create(
                &mut b,
                &fb::PartnershipAnswerArgs {
                    granted_blocks: *granted_blocks,
                },
            );
            (fb::ResponseBody::PartnershipAnswer, o.as_union_value())
        }
        Response::Attached { quota_bytes } => {
            let o = fb::Attached::create(
                &mut b,
                &fb::AttachedArgs {
                    quota_bytes: *quota_bytes,
                },
            );
            (fb::ResponseBody::Attached, o.as_union_value())
        }
    };
    let root = fb::BlockResponse::create(
        &mut b,
        &fb::BlockResponseArgs {
            version: VERSION,
            body_type: t,
            body: Some(o),
        },
    );
    fb::finish_block_response_buffer(&mut b, root);
    b.finished_data().to_vec()
}

/// Décode une réponse.
pub fn decode_response(buf: &[u8]) -> Result<Response, Refusal> {
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(Refusal::TooLarge);
    }
    if !fb::block_response_buffer_has_identifier(buf) {
        return Err(Refusal::Malformed);
    }
    let r = fb::root_as_block_response(buf).map_err(|_| Refusal::Malformed)?;
    if r.version() != VERSION {
        return Err(Refusal::Malformed);
    }
    let m = Refusal::Malformed;
    Ok(match r.body_type() {
        fb::ResponseBody::Failure => {
            Response::Failure(Refusal::from_fb(r.body_as_failure().ok_or(m)?.code())?)
        }
        fb::ResponseBody::BlockData => {
            Response::BlockData(bytes(r.body_as_block_data().ok_or(m)?.data()))
        }
        fb::ResponseBody::Stored => Response::Stored(bytes(r.body_as_stored().ok_or(m)?.hash())),
        fb::ResponseBody::RootState => {
            let s = r.body_as_root_state().ok_or(m)?;
            Response::RootState {
                committed: s.committed(),
                current_root: bytes(s.current_root()),
                quota_bytes: s.quota_bytes(),
                used_bytes: s.used_bytes(),
            }
        }
        fb::ResponseBody::FragmentReceipt => {
            let s = r.body_as_fragment_receipt().ok_or(m)?;
            Response::FragmentReceipt {
                hash: bytes(s.hash()),
                signature: bytes(s.signature()),
            }
        }
        fb::ResponseBody::ChallengeResponse => {
            Response::ChallengeResponse(bytes(r.body_as_challenge_response().ok_or(m)?.digest()))
        }
        fb::ResponseBody::Ack => Response::Ack {
            freed: r.body_as_ack().ok_or(m)?.freed(),
        },
        fb::ResponseBody::ProbeReply => {
            let x = r.body_as_probe_reply().ok_or(m)?;
            Response::ProbeReply {
                nonce: bytes(x.nonce()),
                accepting_partners: x.accepting_partners(),
            }
        }
        fb::ResponseBody::PartnershipAnswer => Response::PartnershipAnswer {
            granted_blocks: r.body_as_partnership_answer().ok_or(m)?.granted_blocks(),
        },
        fb::ResponseBody::OwnershipAnswer => Response::OwnershipAnswer {
            owned: bytes(r.body_as_ownership_answer().ok_or(m)?.owned()),
        },
        fb::ResponseBody::Attached => Response::Attached {
            quota_bytes: r.body_as_attached().ok_or(m)?.quota_bytes(),
        },
        fb::ResponseBody::GrantIssued => {
            Response::GrantIssued(signed_grant_of(r.body_as_grant_issued().ok_or(m)?.grant())?)
        }
        _ => return Err(m),
    })
}

// --------------------------------------------------------- authentification

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn id(v: &[u8]) -> Result<Id, Refusal> {
    v.try_into().map_err(|_| Refusal::Malformed)
}

fn pub_of(seed: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Preuve Connecteur → Nœud, liée aux deux `PeerId` de la connexion.
pub fn connector_proof(k_attach: &[u8; 32], connector_peer: &[u8], node_peer: &[u8]) -> Id {
    kdf(k_attach, CONNECTOR_AUTH, &[], &[connector_peer, node_peer])
        .expect("HKDF-SHA256 : 32 o toujours dérivables")
}

/// Vérifie la preuve à temps constant.
pub fn verify_connector_proof(
    k_attach: &[u8; 32],
    connector_peer: &[u8],
    node_peer: &[u8],
    proof: &[u8],
) -> bool {
    ct_eq(&connector_proof(k_attach, connector_peer, node_peer), proof)
}

/// Contenu d'une `RescueGrant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub issuer_node_id: Id,
    pub grant_pub: Id,
    pub expires_at: u64,
    pub covered_node_ids: Vec<Id>,
}

/// Le Nœud (`priv_node`) délivre une autorisation à `grant_pub`, valable
/// `GRANT_TTL_SECONDS`, couvrant ses anciens `node_id` (`covered`).
pub fn issue_grant(priv_node: &[u8; 32], grant_pub: &Id, now: u64, covered: &[Id]) -> SignedGrant {
    let mut b = FlatBufferBuilder::new();
    let issuer = b.create_vector(&pub_of(priv_node));
    let gp = b.create_vector(grant_pub);
    let cov = b.create_vector(&covered.concat());
    let g = fb::RescueGrant::create(
        &mut b,
        &fb::RescueGrantArgs {
            issuer_node_id: Some(issuer),
            grant_pub: Some(gp),
            expires_at: now + GRANT_TTL_SECONDS,
            covered_node_ids: Some(cov),
        },
    );
    b.finish_minimal(g);
    let grant = b.finished_data().to_vec();
    let signature = sign(priv_node, SIG_LABEL_RESCUE_GRANT, &grant).to_vec();
    SignedGrant { grant, signature }
}

/// Vérifie la signature de l'émetteur et l'expiration.
pub fn open_grant(sg: &SignedGrant, now: u64) -> Result<Grant, Refusal> {
    let g = flatbuffers::root::<fb::RescueGrant>(&sg.grant).map_err(|_| Refusal::Malformed)?;
    let issuer = id(&bytes(g.issuer_node_id()))?;
    verify_signature(&issuer, SIG_LABEL_RESCUE_GRANT, &sg.grant, &sg.signature)
        .map_err(|_| Refusal::Unauthorized)?;
    if now >= g.expires_at() {
        return Err(Refusal::Unauthorized);
    }
    let cov = bytes(g.covered_node_ids());
    if !cov.len().is_multiple_of(32) {
        return Err(Refusal::Malformed);
    }
    Ok(Grant {
        issuer_node_id: issuer,
        grant_pub: id(&bytes(g.grant_pub()))?,
        expires_at: g.expires_at(),
        covered_node_ids: cov.chunks(32).map(|c| c.try_into().unwrap()).collect(),
    })
}

/// Preuve de session de secours : signature de `grant_priv` liée aux deux
/// `PeerId` de la connexion.
pub fn rescue_session_proof(
    grant_priv: &[u8; 32],
    requester_peer: &[u8],
    partner_peer: &[u8],
) -> Vec<u8> {
    sign(
        grant_priv,
        SIG_LABEL_RESCUE_SESSION,
        &canonical_encode(&[requester_peer, partner_peer]),
    )
    .to_vec()
}

fn delegation_payload(delegate: &[u8], expires_at: u64) -> Vec<u8> {
    let mut p = delegate.to_vec();
    p.extend_from_slice(&expires_at.to_be_bytes());
    p
}

/// Le Connecteur délègue son autorisation au nouveau Nœud `delegate_node_id`.
pub fn delegate(
    grant_priv: &[u8; 32],
    grant: SignedGrant,
    delegate_node_id: &Id,
    expires_at: u64,
) -> Delegation {
    let signature = sign(
        grant_priv,
        SIG_LABEL_RESCUE_DELEGATION,
        &delegation_payload(delegate_node_id, expires_at),
    )
    .to_vec();
    Delegation {
        grant,
        delegate_node_id: delegate_node_id.to_vec(),
        expires_at,
        signature,
    }
}

/// Vérifie une délégation (sans contrôle du demandeur) ; rend l'autorisation.
pub fn open_delegation(d: &Delegation, now: u64) -> Result<Grant, Refusal> {
    let g = open_grant(&d.grant, now)?;
    if d.expires_at > g.expires_at || now >= d.expires_at {
        return Err(Refusal::Unauthorized);
    }
    verify_signature(
        &g.grant_pub,
        SIG_LABEL_RESCUE_DELEGATION,
        &delegation_payload(&d.delegate_node_id, d.expires_at),
        &d.signature,
    )
    .map_err(|_| Refusal::Unauthorized)?;
    Ok(g)
}

/// Contrôle d'un identifiant de secours présenté à un partenaire, **avant
/// tout accès disque** : rend l'autorisation (la couverture du propriétaire
/// du fragment se contrôle ensuite avec [`covers`]).
///
/// `requester_node_id` : `pub_node` du demandeur s'il est un Nœud.
pub fn authorize_rescue(
    credential: Option<&Credential>,
    requester_peer: &[u8],
    requester_node_id: Option<&Id>,
    partner_peer: &[u8],
    now: u64,
) -> Result<Grant, Refusal> {
    match credential {
        Some(Credential::Rescue { grant, proof }) => {
            let g = open_grant(grant, now)?;
            verify_signature(
                &g.grant_pub,
                SIG_LABEL_RESCUE_SESSION,
                &canonical_encode(&[requester_peer, partner_peer]),
                proof,
            )
            .map_err(|_| Refusal::Unauthorized)?;
            Ok(g)
        }
        Some(Credential::Delegated(d)) => {
            let g = open_delegation(d, now)?;
            if requester_node_id.map(|n| &n[..]) != Some(&d.delegate_node_id[..]) {
                return Err(Refusal::Unauthorized);
            }
            Ok(g)
        }
        _ => Err(Refusal::Unauthorized),
    }
}

/// Règle de couverture. `successor(o)` : nouveau `node_id` du pointeur de
/// migration **valide lu dans la DHT** sur `o`, s'il y en a un.
pub fn covers(grant: &Grant, owner: &Id, successor: &dyn Fn(&Id) -> Option<Id>) -> bool {
    if grant.issuer_node_id == *owner {
        // Pointeur présent sur l'émetteur : clé possiblement fuitée, révoquée.
        return successor(owner).is_none();
    }
    grant.covered_node_ids.contains(owner) && successor(owner) == Some(grant.issuer_node_id)
}

// ------------------------------------------------------- reçus de fragment

/// Reçu de dépôt signé par le partenaire (`priv_node`).
pub fn sign_receipt(priv_node: &[u8; 32], hash: &Id, depositor: &Id) -> Vec<u8> {
    sign(
        priv_node,
        SIG_LABEL_FRAGMENT_RECEIPT,
        &[&hash[..], &depositor[..]].concat(),
    )
    .to_vec()
}

/// Vérifie un reçu : seul un reçu valide compte parmi les k+2 confirmations.
pub fn verify_receipt(partner: &Id, hash: &Id, depositor: &Id, signature: &[u8]) -> bool {
    verify_signature(
        partner,
        SIG_LABEL_FRAGMENT_RECEIPT,
        &[&hash[..], &depositor[..]].concat(),
        signature,
    )
    .is_ok()
}

// ------------------------------------------------------------------ débit

/// Seau à jetons par `grant_pub` (64/s, rafale 256).
#[derive(Debug, Default)]
pub struct RescueLimiter {
    buckets: HashMap<Id, (u64, u64)>,
}

impl RescueLimiter {
    /// Consomme un jeton pour `key` à l'instant `now_s` (secondes).
    pub fn allow(&mut self, key: &Id, now_s: u64) -> bool {
        let (tokens, last) = self.buckets.entry(*key).or_insert((RESCUE_BURST, now_s));
        let refill = now_s
            .saturating_sub(*last)
            .saturating_mul(RESCUE_RATE_PER_SECOND);
        *tokens = (*tokens + refill).min(RESCUE_BURST);
        *last = now_s.max(*last);
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    }
}

// --------------------------------------------- rattachement automatique

fn attach_payload(pub_user: &Id, node_id: &Id) -> Vec<u8> {
    [&pub_user[..], &node_id[..]].concat()
}

/// Signature de `sig_priv_user` liant l'identité VDF à `pub_user` et au Nœud.
pub fn attach_signature(sig_priv_user: &[u8; 32], pub_user: &Id, node_id: &Id) -> Vec<u8> {
    sign(
        sig_priv_user,
        SIG_LABEL_ATTACH,
        &attach_payload(pub_user, node_id),
    )
    .to_vec()
}

pub fn verify_attach_signature(
    sig_pub_user: &[u8],
    pub_user: &Id,
    node_id: &Id,
    signature: &[u8],
) -> bool {
    verify_signature(
        sig_pub_user,
        SIG_LABEL_ATTACH,
        &attach_payload(pub_user, node_id),
        signature,
    )
    .is_ok()
}

// ------------------------------------------------------ espace de secours

fn deposit_payload(emergency_pub: &[u8], requester_peer: &[u8], partner_peer: &[u8]) -> Vec<u8> {
    let mut p = emergency_pub.to_vec();
    p.extend_from_slice(&canonical_encode(&[requester_peer, partner_peer]));
    p
}

/// Signature de `sig_priv_user` liant la clé de secours aux deux `PeerId`
/// de la connexion (`EmergencyCredential`).
pub fn emergency_deposit_signature(
    sig_priv_user: &[u8; 32],
    emergency_pub: &Id,
    requester_peer: &[u8],
    partner_peer: &[u8],
) -> Vec<u8> {
    sign(
        sig_priv_user,
        SIG_LABEL_EMERGENCY_DEPOSIT,
        &deposit_payload(emergency_pub, requester_peer, partner_peer),
    )
    .to_vec()
}

pub fn verify_emergency_deposit(
    sig_pub_user: &[u8],
    emergency_pub: &[u8],
    requester_peer: &[u8],
    partner_peer: &[u8],
    signature: &[u8],
) -> bool {
    verify_signature(
        sig_pub_user,
        SIG_LABEL_EMERGENCY_DEPOSIT,
        &deposit_payload(emergency_pub, requester_peer, partner_peer),
        signature,
    )
    .is_ok()
}

fn release_payload(emergency_pub: &[u8], timestamp: u64, hashes: &[u8]) -> Vec<u8> {
    let mut p = emergency_pub.to_vec();
    p.extend_from_slice(&timestamp.to_be_bytes());
    p.extend_from_slice(hashes);
    p
}

/// Corps d'un `EmergencyRelease` signé par `sig_priv_emergency`.
pub fn emergency_release(sig_priv_emergency: &[u8; 32], timestamp: u64, hashes: &[Id]) -> Body {
    let emergency_pub = pub_of(sig_priv_emergency);
    let hashes: Vec<u8> = hashes.concat();
    let signature = sign(
        sig_priv_emergency,
        SIG_LABEL_EMERGENCY_RELEASE,
        &release_payload(&emergency_pub, timestamp, &hashes),
    )
    .to_vec();
    Body::EmergencyRelease {
        emergency_pub: emergency_pub.to_vec(),
        timestamp,
        hashes,
        signature,
    }
}

pub fn verify_emergency_release(
    emergency_pub: &[u8],
    timestamp: u64,
    hashes: &[u8],
    signature: &[u8],
) -> bool {
    verify_signature(
        emergency_pub,
        SIG_LABEL_EMERGENCY_RELEASE,
        &release_payload(emergency_pub, timestamp, hashes),
        signature,
    )
    .is_ok()
}
