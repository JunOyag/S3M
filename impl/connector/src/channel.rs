//! Canal Nœud ↔ Utilisateurs, côté Connecteur — id `protocols.canal-noeud`.
//! Réf. spec : docs/04-protocols/canal-noeud.md.
//!
//! Épinglage de la clé d'annonce, vérification et conservation des
//! messages du Nœud, alerte (bandeau, méfiance envers le pointeur de
//! migration), copie de l'alerte relue et republiée dans l'annuaire.

use s3m_protocol::exchange::Id;
use s3m_protocol::message::{verify_message, Cursor, Kind, Signed, ALERT_REPUBLISH_S};
use serde::{Deserialize, Serialize};

/// Noms de l'identité (`deploiement.pseudos`), conservés dans `names.json`
/// et publiés dans l'entrée User chiffrée.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Names {
    /// Pseudo de l'identité.
    pub pseudo: String,
    /// Nom donné au Nœud par l'Utilisateur.
    pub node_label: String,
    /// Nom publié par l'opérateur (entrée Node), dernière lecture.
    #[serde(default)]
    pub node_name: Option<String>,
}

impl Names {
    /// Adopte les noms lus dans l'entrée User (nouvel appareil).
    pub fn adopt(&mut self, pseudo: &str, node_label: &str) {
        self.pseudo = s3m_protocol::pseudo::sanitize(pseudo);
        self.node_label = s3m_protocol::pseudo::sanitize(node_label);
    }

    /// Affichage du Nœud : nom local, sinon nom publié, et l'empreinte.
    pub fn node_display(&self, node_id: &[u8]) -> String {
        s3m_protocol::pseudo::display(
            &[Some(self.node_label.as_str()), self.node_name.as_deref()],
            node_id,
        )
    }
}

/// Messages du Nœud conservés au plus.
pub const MAX_RECEIVED: usize = 100;

/// Message reçu et vérifié.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Received {
    pub kind: Kind,
    pub seq: u64,
    pub timestamp: u64,
    pub text: String,
    pub successor: Option<Id>,
    /// Adressé à cet Utilisateur seul.
    #[serde(default)]
    pub personal: bool,
    /// Remplacement de la clé d'annonce proposé.
    #[serde(default)]
    pub announce_replacement: Option<Id>,
    /// Lu par l'Utilisateur (un message conservé avant cette notion compte
    /// comme lu).
    #[serde(default = "already_read")]
    pub read: bool,
}

fn already_read() -> bool {
    true
}

/// État du canal, conservé dans `channel.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelState {
    /// Nœud auquel s'appliquent l'épinglage et le curseur.
    pub node_id: Option<Id>,
    /// `pub_node_announce` épinglée.
    pub announce: Option<Id>,
    pub cursor: Cursor,
    /// Du plus ancien au plus récent.
    pub received: Vec<Received>,
    /// Dernière alerte, et son acquittement par l'utilisateur.
    pub alert: Option<Received>,
    pub alert_acknowledged: bool,
    /// Enveloppe `AlertEntry` vue, republiée telle quelle.
    pub alert_envelope: Option<Vec<u8>>,
    pub alert_republished_at: u64,
    pub alert_polled_at: u64,
    /// Messages envoyés au Nœud : `(instant, texte)`.
    pub sent: Vec<(u64, String)>,
    /// Remplacement de clé d'annonce proposé, en attente de l'accord de
    /// l'Utilisateur : `(nouvelle clé, seq)`.
    #[serde(default)]
    pub pending_announce: Option<(Id, u64)>,
    /// Messages acceptés depuis toujours (notifications de la barre des tâches).
    #[serde(default)]
    pub received_total: u64,
}

impl ChannelState {
    /// Se place sur `node_id` : un autre Nœud efface l'épinglage, le
    /// curseur et l'alerte. Épingle `announce` si aucune clé ne l'est.
    pub fn pin(&mut self, node_id: &Id, announce: Option<Id>) {
        if self.node_id.as_ref() != Some(node_id) {
            *self = Self {
                node_id: Some(*node_id),
                sent: std::mem::take(&mut self.sent),
                ..Self::default()
            };
        }
        if self.announce.is_none() {
            self.announce = announce;
        }
    }

    /// Vérifie et retient un message du Nœud ; rend `true` s'il est nouveau.
    /// `me` : `pub_user` ; un message adressé à un autre est rejeté.
    pub fn accept(&mut self, s: &Signed, me: Option<&Id>) -> bool {
        let Some(node_id) = self.node_id else {
            return false;
        };
        let Ok(m) = verify_message(s, &node_id, self.announce.as_ref()) else {
            return false;
        };
        if m.recipient.is_some() && m.recipient.as_ref() != me {
            return false;
        }
        if !self.cursor.accept(&m) {
            return false;
        }
        let r = Received {
            kind: m.kind,
            seq: m.seq,
            timestamp: m.timestamp,
            text: m.text,
            successor: m.successor,
            personal: m.recipient.is_some(),
            announce_replacement: m.announce_replacement,
            read: false,
        };
        // Remplacement de clé : jamais appliqué sans l'accord de l'Utilisateur.
        if let Some(k) = m.announce_replacement {
            if self.announce != Some(k) {
                self.pending_announce = Some((k, m.seq));
            }
        }
        if r.kind == Kind::Alert {
            self.alert = Some(r.clone());
            self.alert_acknowledged = false;
        }
        self.received.push(r);
        self.received_total += 1;
        let extra = self.received.len().saturating_sub(MAX_RECEIVED);
        self.received.drain(..extra);
        true
    }

    /// Alerte lue dans l'annuaire : acceptée si elle vient de la clé
    /// épinglée ; l'enveloppe est retenue pour être republiée.
    pub fn accept_entry(&mut self, announce: &Id, alert: &Signed, envelope: Vec<u8>) -> bool {
        if self.announce.as_ref() != Some(announce) {
            return false;
        }
        let fresh = self.accept(alert, None);
        let newer = self.alert.as_ref().is_some_and(|a| {
            s3m_protocol::message::decode_message(&alert.message).is_ok_and(|m| m.seq == a.seq)
        });
        if newer && self.alert_envelope.as_ref() != Some(&envelope) {
            self.alert_envelope = Some(envelope);
            self.alert_republished_at = 0;
        }
        fresh
    }

    /// Marque lu le message `(kind, seq)` ; rend `true` s'il ne l'était pas.
    pub fn mark_read(&mut self, kind: Kind, seq: u64) -> bool {
        match self
            .received
            .iter_mut()
            .find(|m| m.kind == kind && m.seq == seq && !m.read)
        {
            Some(m) => {
                m.read = true;
                true
            }
            None => false,
        }
    }

    /// Marque tous les messages lus ; rend leur nombre.
    pub fn mark_all_read(&mut self) -> usize {
        let mut n = 0;
        for m in self.received.iter_mut().filter(|m| !m.read) {
            m.read = true;
            n += 1;
        }
        n
    }

    /// Messages non lus.
    pub fn unread(&self) -> usize {
        self.received.iter().filter(|m| !m.read).count()
    }

    /// L'Utilisateur accepte (`true`) ou refuse le remplacement de clé
    /// d'annonce proposé ; rend la clé désormais épinglée.
    pub fn decide_replacement(&mut self, accept: bool) -> Option<Id> {
        if let Some((k, _)) = self.pending_announce.take() {
            if accept {
                self.announce = Some(k);
                self.alert_envelope = None;
                self.alert_republished_at = 0;
                self.alert_polled_at = 0;
            }
        }
        self.announce
    }

    /// Le Nœud courant a émis une alerte : son pointeur de migration n'est
    /// plus suivi automatiquement.
    pub fn distrusts(&self, node_id: &Id) -> bool {
        self.alert.is_some() && self.node_id.as_ref() == Some(node_id)
    }

    /// Nœud de remplacement proposé par l'alerte.
    pub fn successor(&self) -> Option<Id> {
        self.alert.as_ref().and_then(|a| a.successor)
    }

    /// Enveloppe d'alerte à republier maintenant.
    pub fn republish_due(&self, now: u64) -> Option<Vec<u8>> {
        let due = self.alert_republished_at == 0
            || now >= self.alert_republished_at.saturating_add(ALERT_REPUBLISH_S);
        self.alert_envelope.clone().filter(|_| due)
    }
}
