//! Canal Nœud ↔ Utilisateurs, côté Nœud — id `protocols.canal-noeud`.
//! Réf. spec : docs/04-protocols/canal-noeud.md.
//!
//! Clé d'annonce hors seed (phrase de 24 mots remise une fois, jamais
//! conservée), boîte d'envoi, messages reçus, copie de l'alerte dans
//! l'annuaire (republiée telle quelle).

use s3m_protocol::exchange::{Id, Refusal};
use s3m_protocol::message::{
    alert_entry_envelope, alert_key, sign_message, Inbox, Kind, NodeMessage, Outbox,
    ALERT_REPUBLISH_S, MAX_TEXT_BYTES,
};
use serde::{Deserialize, Serialize};

fn pub_of(seed: &[u8; 32]) -> Id {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Nouvelle clé d'annonce : `(priv_node_announce, phrase de 24 mots)`.
pub fn new_announce_key() -> ([u8; 32], String) {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("CSPRNG du système");
    let phrase = bip39::Mnemonic::from_entropy(&k)
        .expect("32 octets")
        .to_string();
    (k, phrase)
}

/// `priv_node_announce` depuis sa phrase de 24 mots.
pub fn announce_from_phrase(phrase: &str) -> Result<[u8; 32], String> {
    let words = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    let m = bip39::Mnemonic::parse_normalized(&words.to_lowercase())
        .map_err(|_| "phrase d'annonce invalide".to_string())?;
    m.to_entropy()
        .try_into()
        .map_err(|_| "phrase d'annonce de 24 mots attendue".to_string())
}

/// État du canal, conservé avec l'état du Nœud.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    /// `pub_node_announce`, publiée dans l'entrée Node.
    pub announce: Option<Id>,
    pub outbox: Outbox,
    pub inbox: Inbox,
    /// Enveloppe `AlertEntry` de la dernière alerte, republiée telle quelle.
    pub alert_envelope: Option<Vec<u8>>,
    pub alert_published_at: u64,
}

fn check_text(text: &str) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("message vide".into());
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "message trop long ({MAX_TEXT_BYTES} octets au plus)"
        ));
    }
    Ok(())
}

impl Channel {
    /// Crée la clé d'annonce si le Nœud n'en a pas ; rend la phrase.
    pub fn create_announce(&mut self) -> Result<String, String> {
        if self.announce.is_some() {
            return Err("ce Nœud a déjà une clé d'annonce".into());
        }
        let (k, phrase) = new_announce_key();
        self.announce = Some(pub_of(&k));
        Ok(phrase)
    }

    /// Message courant signé par `priv_node` ; rend son numéro.
    pub fn post_info(&mut self, priv_node: &[u8; 32], text: &str, now: u64) -> Result<u64, String> {
        check_text(text)?;
        let node_id = pub_of(priv_node);
        let seq = self.outbox.next_seq(Kind::Info);
        let m = NodeMessage {
            node_id,
            seq,
            timestamp: now,
            kind: Kind::Info,
            text: text.to_string(),
            successor: None,
        };
        self.outbox
            .push(sign_message(priv_node, &m), &node_id, None)
            .map_err(|e| e.to_string())?;
        Ok(seq)
    }

    /// Alerte signée par la clé d'annonce (phrase saisie par l'opérateur),
    /// copiée dans l'annuaire au prochain tour ; rend son numéro.
    pub fn post_alert(
        &mut self,
        node_id: &Id,
        priv_announce: &[u8; 32],
        text: &str,
        successor: Option<Id>,
        now: u64,
    ) -> Result<u64, String> {
        check_text(text)?;
        let announce = self.announce.ok_or("ce Nœud n'a pas de clé d'annonce")?;
        if pub_of(priv_announce) != announce {
            return Err("cette phrase n'est pas la clé d'annonce de ce Nœud".into());
        }
        if successor.as_ref() == Some(node_id) {
            return Err("le Nœud de remplacement doit être un autre Nœud".into());
        }
        let seq = self.outbox.next_seq(Kind::Alert);
        let m = NodeMessage {
            node_id: *node_id,
            seq,
            timestamp: now,
            kind: Kind::Alert,
            text: text.to_string(),
            successor,
        };
        let s = sign_message(priv_announce, &m);
        self.alert_envelope = Some(alert_entry_envelope(priv_announce, &s, now));
        self.alert_published_at = 0;
        self.outbox
            .push(s, node_id, Some(&announce))
            .map_err(|e| e.to_string())?;
        Ok(seq)
    }

    /// `(clé DHT, enveloppe)` de l'alerte à (re)publier maintenant.
    pub fn alert_due(&self, now: u64) -> Option<(Id, Vec<u8>)> {
        let env = self.alert_envelope.clone()?;
        let announce = self.announce?;
        let due = self.alert_published_at == 0
            || now >= self.alert_published_at.saturating_add(ALERT_REPUBLISH_S);
        due.then(|| (alert_key(&announce), env))
    }

    /// `ReadMessages`.
    pub fn read(&self, since_info: u64, since_alert: u64) -> Vec<s3m_protocol::message::Signed> {
        self.outbox.since(since_info, since_alert)
    }

    /// `PostMessage`.
    pub fn receive(&mut self, user: &Id, text: &str, now: u64) -> Result<(), Refusal> {
        self.inbox.post(user, text, now)
    }

    pub fn prune(&mut self, now: u64) {
        self.outbox.prune(now);
        self.inbox.prune(now);
    }
}
