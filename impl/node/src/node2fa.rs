//! 2FA de l'opérateur du Nœud (`deploiement.packaging#2fa-noeud`) : une fois
//! activé (code confirmé), les actions critiques du dashboard s'exécutent
//! aussitôt avec un code valide ; sans code (ou 2FA non activé), elles sont
//! différées de 72 h, annulables, notées au journal et signalées par les
//! alertes de l'opérateur.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Délai d'une action critique sans code 2FA.
pub const DEFER_S: u64 = 72 * 3600;
const FILE: &str = "operations-noeud.json";

/// Actions toujours critiques ; `volume_apply` l'est si le brouillon
/// déclare un volume perdu ou en efface un.
pub const CRITICAL: &[&str] = &[
    "replace_announce_key",
    "send_alert",
    "regenerate_totp",
    "vault_plain",
    "disable_node_2fa",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    /// Série TOTP confirmée par un code ; `None` : 2FA non activé (une
    /// régénération change la série : à réactiver).
    pub enabled_serial: Option<u32>,
    /// Dernier pas TOTP accepté (un code ne sert qu'une fois).
    pub last_step: u64,
    pub next_id: u64,
    pub pending: Vec<Op>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Op {
    pub id: u64,
    pub name: String,
    pub values: Value,
    pub label: String,
    pub created_at: u64,
    pub due_at: u64,
}

impl State {
    pub fn enabled(&self, serial: u32) -> bool {
        self.enabled_serial == Some(serial)
    }

    /// Code TOTP valide (±1 pas), jamais deux fois le même pas.
    pub fn check(&mut self, secret: &[u8; 20], code: &str, now: u64) -> bool {
        let code = code.trim();
        let Ok(c) = code.parse::<u32>() else {
            return false;
        };
        if code.len() != 6 {
            return false;
        }
        let step = now / crate::admin::TOTP_STEP;
        match [step.wrapping_sub(1), step, step + 1]
            .into_iter()
            .find(|s| *s > self.last_step && crate::admin::hotp(secret, *s, 6) == c)
        {
            Some(s) => {
                self.last_step = s;
                true
            }
            None => false,
        }
    }

    /// Met une action en attente ; rend l'opération créée.
    pub fn defer(&mut self, name: &str, values: Value, label: &str, now: u64) -> Op {
        self.next_id += 1;
        let op = Op {
            id: self.next_id,
            name: name.into(),
            values,
            label: label.into(),
            created_at: now,
            due_at: now + DEFER_S,
        };
        self.pending.push(op.clone());
        op
    }

    /// Opérations échues, retirées de la liste.
    pub fn take_due(&mut self, now: u64) -> Vec<Op> {
        let (due, keep): (Vec<Op>, Vec<Op>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|o| o.due_at <= now);
        self.pending = keep;
        due
    }
}

pub fn load(dir: &Path) -> State {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save(dir: &Path, st: &State) {
    let tmp = dir.join(format!("{FILE}.tmp"));
    if std::fs::write(&tmp, serde_json::to_vec_pretty(st).expect("sérialisable")).is_ok() {
        let _ = std::fs::rename(tmp, dir.join(FILE));
    }
}

/// Libellé lisible d'une action critique.
pub fn label(name: &str) -> &'static str {
    match name {
        "replace_announce_key" => "remplacement de la clé d'annonce",
        "send_alert" => "envoi d'une alerte de compromission aux utilisateurs",
        "regenerate_totp" => "régénération du 2FA",
        "vault_plain" => "remise en clair de la phrase secrète du Nœud",
        "disable_node_2fa" => "désactivation du 2FA du Nœud",
        "volume_apply" => "application des modifications de volumes (volume perdu ou effacé)",
        _ => "action critique",
    }
}

/// Champ « code 2FA » ajouté aux formulaires des actions critiques, partout
/// dans l'état présenté (panneaux compris).
pub fn add_code_fields(v: &mut Value, critical: &dyn Fn(&str) -> bool, enabled: bool) {
    match v {
        Value::Object(m) => {
            let is_form = m.get("nom").and_then(Value::as_str).is_some_and(critical)
                && (m.contains_key("libellé") || m.contains_key("champs"))
                && !m.contains_key("panneau");
            if is_form {
                let champs = m.entry("champs").or_insert_with(|| json!([]));
                if let Some(a) = champs.as_array_mut() {
                    if !a.iter().any(|x| x == "code 2FA") {
                        a.push(json!("code 2FA"));
                    }
                }
                let types = m.entry("types").or_insert_with(|| json!({}));
                types["code 2FA"] = json!("secret");
                let aide = m.entry("aide").or_insert_with(|| json!({}));
                aide["code 2FA"] = json!(if enabled {
                    "Code à 6 chiffres de votre application d'authentification : exécution immédiate. Vide : exécution dans 72 h, annulable."
                } else {
                    "2FA du Nœud non activé : l'action sera exécutée dans 72 h, annulable (activez le 2FA pour agir aussitôt)."
                });
            }
            for x in m.values_mut() {
                add_code_fields(x, critical, enabled);
            }
        }
        Value::Array(a) => {
            for x in a {
                add_code_fields(x, critical, enabled);
            }
        }
        _ => {}
    }
}
