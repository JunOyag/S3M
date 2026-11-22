//! Canal Nœud ↔ Utilisateurs — id `protocols.canal-noeud`, partie commune
//! Nœud/Connecteur, sans I/O. Réf. spec : docs/04-protocols/canal-noeud.md.
//!
//! - Messages du Nœud (`Info` signé par `priv_node`, `Alert` signé par la
//!   clé d'annonce hors seed), vérification et curseur de lecture.
//! - Boîte d'envoi du Nœud et messages reçus des Utilisateurs (conservation,
//!   débit).
//! - Copie de l'alerte dans l'annuaire (`AlertEntry`).

use flatbuffers::FlatBufferBuilder;
use serde::{Deserialize, Serialize};

use crate::dht::{
    alert_dht_key, build_envelope, sign, verify_envelope, verify_signature, DhtError, EntryKind,
    VerifyContext,
};
use crate::exchange::{Id, Refusal};
use crate::fb::{dht as fbd, exchange as fb};

pub const SIG_LABEL_NODE_MESSAGE: &str = "s3m/sig/node-message/v1";
pub const SIG_LABEL_NODE_ALERT: &str = "s3m/sig/node-alert/v1";
/// Taille maximale d'un texte (octets UTF-8).
pub const MAX_TEXT_BYTES: usize = 4096;
/// Messages rendus au plus par `ReadMessages`.
pub const MAX_READ: usize = 64;
/// Messages conservés au plus par le Nœud.
pub const MAX_KEPT: usize = 256;
/// Conservation des messages par le Nœud.
pub const RETENTION_S: u64 = 2_592_000;
/// Messages d'un Utilisateur au plus par fenêtre de [`DAY_S`].
pub const POSTS_PER_DAY: usize = 10;
pub const DAY_S: u64 = 86_400;
/// Part du quota de l'Utilisateur occupée par chacun de ses messages conservés.
pub const MESSAGE_COST_BYTES: u64 = 4096;
/// Republication de l'enveloppe d'alerte.
pub const ALERT_REPUBLISH_S: u64 = 2_592_000;
/// Lecture de l'alerte dans l'annuaire au moins à cet intervalle.
pub const ALERT_POLL_S: u64 = 86_400;

/// Sorte de message (`MessageKind`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[default]
    Info,
    Alert,
}

/// `NodeMessage`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMessage {
    pub node_id: Id,
    pub seq: u64,
    pub timestamp: u64,
    pub kind: Kind,
    pub text: String,
    /// Alerte seulement : Nœud de remplacement.
    pub successor: Option<Id>,
    /// `Info` seulement : seul destinataire (`pub_user`), sinon tous.
    pub recipient: Option<Id>,
    /// `Info` seulement : nouvelle `pub_node_announce` proposée.
    pub announce_replacement: Option<Id>,
}

/// `SignedNodeMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

fn label(kind: Kind) -> &'static str {
    match kind {
        Kind::Info => SIG_LABEL_NODE_MESSAGE,
        Kind::Alert => SIG_LABEL_NODE_ALERT,
    }
}

/// Sérialise un `NodeMessage`.
pub fn encode_message(m: &NodeMessage) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let node_id = b.create_vector(&m.node_id);
    let text = b.create_string(&m.text);
    let successor = m.successor.map(|s| b.create_vector(&s));
    let recipient = m.recipient.map(|s| b.create_vector(&s));
    let replacement = m.announce_replacement.map(|s| b.create_vector(&s));
    let o = fb::NodeMessage::create(
        &mut b,
        &fb::NodeMessageArgs {
            node_id: Some(node_id),
            seq: m.seq,
            timestamp: m.timestamp,
            kind: match m.kind {
                Kind::Info => fb::MessageKind::Info,
                Kind::Alert => fb::MessageKind::Alert,
            },
            text: Some(text),
            successor_node_id: successor,
            recipient,
            announce_replacement: replacement,
        },
    );
    b.finish_minimal(o);
    b.finished_data().to_vec()
}

/// Désérialise un `NodeMessage` (sans vérifier de signature).
pub fn decode_message(buf: &[u8]) -> Result<NodeMessage, Refusal> {
    let m = flatbuffers::root::<fb::NodeMessage>(buf).map_err(|_| Refusal::Malformed)?;
    let id = |v: Option<flatbuffers::Vector<'_, u8>>| -> Result<Id, Refusal> {
        v.ok_or(Refusal::Malformed)?
            .bytes()
            .try_into()
            .map_err(|_| Refusal::Malformed)
    };
    let kind = match m.kind() {
        fb::MessageKind::Info => Kind::Info,
        fb::MessageKind::Alert => Kind::Alert,
        _ => return Err(Refusal::Malformed),
    };
    Ok(NodeMessage {
        node_id: id(m.node_id())?,
        seq: m.seq(),
        timestamp: m.timestamp(),
        kind,
        text: m.text().unwrap_or_default().to_string(),
        successor: match m.successor_node_id() {
            Some(v) => Some(id(Some(v))?),
            None => None,
        },
        recipient: match m.recipient() {
            Some(v) => Some(id(Some(v))?),
            None => None,
        },
        announce_replacement: match m.announce_replacement() {
            Some(v) => Some(id(Some(v))?),
            None => None,
        },
    })
}

/// Signe un message : `priv_node` pour `Info`, `priv_node_announce` pour `Alert`.
pub fn sign_message(priv_key: &[u8; 32], m: &NodeMessage) -> Signed {
    let message = encode_message(m);
    let signature = sign(priv_key, label(m.kind), &message).to_vec();
    Signed { message, signature }
}

/// Vérifie un message de `node_id` : signature (clé du Nœud ou clé
/// d'annonce épinglée), taille du texte, successeur réservé à l'alerte.
pub fn verify_message(
    s: &Signed,
    node_id: &Id,
    announce: Option<&Id>,
) -> Result<NodeMessage, Refusal> {
    let m = decode_message(&s.message)?;
    if &m.node_id != node_id {
        return Err(Refusal::Unauthorized);
    }
    if m.text.len() > MAX_TEXT_BYTES {
        return Err(Refusal::TooLarge);
    }
    let key: &[u8] = match m.kind {
        Kind::Info if m.successor.is_some() => return Err(Refusal::Malformed),
        Kind::Alert if m.recipient.is_some() || m.announce_replacement.is_some() => {
            return Err(Refusal::Malformed)
        }
        Kind::Info => node_id,
        Kind::Alert => announce.ok_or(Refusal::Unauthorized)?,
    };
    verify_signature(key, label(m.kind), &s.message, &s.signature)
        .map_err(|_| Refusal::Unauthorized)?;
    Ok(m)
}

/// Derniers `seq` acceptés, par sorte (côté Connecteur).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub info: u64,
    pub alert: u64,
}

impl Cursor {
    /// Accepte `m` si son `seq` dépasse le dernier de sa sorte, et avance.
    pub fn accept(&mut self, m: &NodeMessage) -> bool {
        let last = match m.kind {
            Kind::Info => &mut self.info,
            Kind::Alert => &mut self.alert,
        };
        if m.seq <= *last {
            return false;
        }
        *last = m.seq;
        true
    }
}

/// Boîte d'envoi du Nœud.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outbox {
    /// Dans l'ordre d'émission.
    pub sent: Vec<(NodeMessage, Signed)>,
}

impl Outbox {
    /// Numéro du prochain message de la sorte `kind`.
    pub fn next_seq(&self, kind: Kind) -> u64 {
        self.sent
            .iter()
            .filter(|(m, _)| m.kind == kind)
            .map(|(m, _)| m.seq)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// Ajoute un message déjà signé (vérifié pour `node_id`).
    pub fn push(&mut self, s: Signed, node_id: &Id, announce: Option<&Id>) -> Result<(), Refusal> {
        let m = verify_message(&s, node_id, announce)?;
        if m.seq < self.next_seq(m.kind) {
            return Err(Refusal::Replayed);
        }
        self.sent.push((m, s));
        Ok(())
    }

    /// Oublie les messages plus vieux que [`RETENTION_S`], puis les plus
    /// anciens au-delà de [`MAX_KEPT`].
    pub fn prune(&mut self, now: u64) {
        self.sent
            .retain(|(m, _)| m.timestamp.saturating_add(RETENTION_S) > now);
        let extra = self.sent.len().saturating_sub(MAX_KEPT);
        self.sent.drain(..extra);
    }

    /// Réponse à `ReadMessages` : les [`MAX_READ`] plus anciens messages
    /// de `seq` supérieur, toutes sortes confondues.
    /// Messages de `seq` supérieur destinés à `user` (sans destinataire, ou
    /// adressés à lui).
    pub fn since(&self, info: u64, alert: u64, user: &Id) -> Vec<Signed> {
        self.sent
            .iter()
            .filter(|(m, _)| match m.kind {
                Kind::Info => m.seq > info,
                Kind::Alert => m.seq > alert,
            })
            .filter(|(m, _)| m.recipient.is_none_or(|r| &r == user))
            .take(MAX_READ)
            .map(|(_, s)| s.clone())
            .collect()
    }

    /// Alerte la plus récente.
    pub fn last_alert(&self) -> Option<&Signed> {
        self.sent
            .iter()
            .filter(|(m, _)| m.kind == Kind::Alert)
            .max_by_key(|(m, _)| m.seq)
            .map(|(_, s)| s)
    }
}

/// `UserMessage` : message reçu d'un Utilisateur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserMessage {
    pub user_id: Id,
    pub timestamp: u64,
    pub text: String,
}

/// Messages reçus par le Nœud.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbox {
    pub received: Vec<UserMessage>,
}

impl Inbox {
    /// `PostMessage` : taille et débit ([`POSTS_PER_DAY`] par [`DAY_S`]).
    pub fn post(&mut self, user_id: &Id, text: &str, now: u64) -> Result<(), Refusal> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(Refusal::TooLarge);
        }
        let recent = self
            .received
            .iter()
            .filter(|m| &m.user_id == user_id && m.timestamp.saturating_add(DAY_S) > now)
            .count();
        if recent >= POSTS_PER_DAY {
            return Err(Refusal::RateLimited);
        }
        self.received.push(UserMessage {
            user_id: *user_id,
            timestamp: now,
            text: text.to_string(),
        });
        Ok(())
    }

    /// Oublie les messages plus vieux que [`RETENTION_S`] ; rend leurs
    /// auteurs (un par message, pour rendre [`MESSAGE_COST_BYTES`]).
    pub fn prune(&mut self, now: u64) -> Vec<Id> {
        let mut gone = Vec::new();
        self.received.retain(|m| {
            let keep = m.timestamp.saturating_add(RETENTION_S) > now;
            if !keep {
                gone.push(m.user_id);
            }
            keep
        });
        gone
    }

    /// Supprime le message de `user_id` reçu à `timestamp` ; rend `true`
    /// s'il existait.
    pub fn remove(&mut self, user_id: &Id, timestamp: u64) -> bool {
        match self
            .received
            .iter()
            .position(|m| &m.user_id == user_id && m.timestamp == timestamp)
        {
            Some(i) => {
                self.received.remove(i);
                true
            }
            None => false,
        }
    }
}

// --------------------------------------------------------------- annuaire

/// Enveloppe `AlertEntry` signée par `priv_node_announce`, publiée sous
/// [`alert_dht_key`]. `timestamp` est celui de l'alerte : l'enveloppe est
/// republiée telle quelle.
pub fn alert_entry_envelope(priv_announce: &[u8; 32], alert: &Signed, timestamp: u64) -> Vec<u8> {
    let announce = ed25519_dalek::SigningKey::from_bytes(priv_announce)
        .verifying_key()
        .to_bytes();
    let mut b = FlatBufferBuilder::new();
    let key = b.create_vector(&announce);
    let message = b.create_vector(&alert.message);
    let signature = b.create_vector(&alert.signature);
    let sm = fb::SignedNodeMessage::create(
        &mut b,
        &fb::SignedNodeMessageArgs {
            message: Some(message),
            signature: Some(signature),
        },
    );
    let e = fbd::AlertEntry::create(
        &mut b,
        &fbd::AlertEntryArgs {
            pub_node_announce: Some(key),
            timestamp,
            alert: Some(sm),
        },
    );
    fbd::finish_alert_entry_buffer(&mut b, e);
    let payload = b.finished_data().to_vec();
    build_envelope(
        &payload,
        &sign(priv_announce, EntryKind::Alert.signature_label(), &payload),
    )
}

/// Clé DHT de l'alerte d'un Nœud.
pub fn alert_key(pub_node_announce: &Id) -> Id {
    alert_dht_key(pub_node_announce)
}

/// Vérifie une enveloppe `AlertEntry` et rend `(pub_node_announce, alerte)`.
pub fn open_alert_entry(envelope: &[u8], now: u64) -> Result<(Id, Signed), DhtError> {
    let ctx = VerifyContext {
        now,
        node_lookup_key: None,
        previous_seq: None,
    };
    let no_vdf = |_: &[u8; s3m_core::vdf::TAGGED_IDENTITY_LEN],
                  _: &s3m_core::vdf::VdfProof|
     -> Result<bool, s3m_core::CoreError> { Ok(false) };
    let payload = verify_envelope(envelope, EntryKind::Alert, &ctx, &no_vdf)?;
    let e = fbd::root_as_alert_entry(&payload).map_err(|_| DhtError::Format("AlertEntry"))?;
    let announce: Id = e
        .pub_node_announce()
        .ok_or(DhtError::BadSignature)?
        .bytes()
        .try_into()
        .map_err(|_| DhtError::Format("pub_node_announce"))?;
    let a = e.alert().ok_or(DhtError::Format("alert"))?;
    let bytes =
        |v: Option<flatbuffers::Vector<'_, u8>>| v.map(|x| x.bytes().to_vec()).unwrap_or_default();
    Ok((
        announce,
        Signed {
            message: bytes(a.message()),
            signature: bytes(a.signature()),
        },
    ))
}
