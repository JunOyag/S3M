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
    pub fn accept(&mut self, s: &Signed) -> bool {
        let Some(node_id) = self.node_id else {
            return false;
        };
        let Ok(m) = verify_message(s, &node_id, self.announce.as_ref()) else {
            return false;
        };
        if !self.cursor.accept(&m) {
            return false;
        }
        let r = Received {
            kind: m.kind,
            seq: m.seq,
            timestamp: m.timestamp,
            text: m.text,
            successor: m.successor,
        };
        if r.kind == Kind::Alert {
            self.alert = Some(r.clone());
            self.alert_acknowledged = false;
        }
        self.received.push(r);
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
        let fresh = self.accept(alert);
        let newer = self.alert.as_ref().is_some_and(|a| {
            s3m_protocol::message::decode_message(&alert.message).is_ok_and(|m| m.seq == a.seq)
        });
        if newer && self.alert_envelope.as_ref() != Some(&envelope) {
            self.alert_envelope = Some(envelope);
            self.alert_republished_at = 0;
        }
        fresh
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
