//! Contacts du Connecteur : identifiants S3m d'autres utilisateurs et
//! pseudo choisi localement, conservés dans `contacts.json` (données de
//! l'identité). Les partages acceptent le pseudo d'un contact à la place de
//! son identifiant ; les écrans l'affichent au lieu de l'empreinte.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const CONTACTS_FILE: &str = "contacts.json";

/// Un contact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Pseudo choisi par l'utilisateur (vide : aucun).
    pub pseudo: String,
    /// Identifiant S3m (`user_id`, hex).
    pub user_id: String,
}

/// Carnet de contacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contacts {
    pub list: Vec<Contact>,
}

/// Identifiant S3m saisi : 64 caractères hexadécimaux.
pub fn parse_user_id(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| "identifiant : 64 caractères hexadécimaux attendus".to_string())
}

impl Contacts {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join(CONTACTS_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let p = dir.join(CONTACTS_FILE);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).expect("sérialisable"))?;
        std::fs::rename(tmp, p)
    }

    /// Ajoute, ou modifie le contact `previous` (identifiant hex).
    pub fn upsert(
        &mut self,
        previous: Option<&str>,
        pseudo: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let pseudo = s3m_protocol::pseudo::sanitize(pseudo.trim());
        let id = hex::encode(parse_user_id(user_id)?);
        let prev = previous.map(|p| p.trim().to_lowercase());
        let other = |c: &Contact| prev.as_deref() != Some(c.user_id.as_str());
        if self.list.iter().any(|c| other(c) && c.user_id == id) {
            return Err("cet identifiant est déjà dans vos contacts".into());
        }
        if !pseudo.is_empty()
            && self
                .list
                .iter()
                .any(|c| other(c) && c.pseudo.eq_ignore_ascii_case(&pseudo))
        {
            return Err(format!("le pseudo « {pseudo} » est déjà pris"));
        }
        if pseudo.len() == 64 && parse_user_id(&pseudo).is_ok() {
            return Err("un pseudo ne peut pas être un identifiant".into());
        }
        let c = Contact {
            pseudo,
            user_id: id,
        };
        match prev.and_then(|p| self.list.iter().position(|x| x.user_id == p)) {
            Some(i) => self.list[i] = c,
            None => self.list.push(c),
        }
        self.list.sort_by(|a, b| {
            (a.pseudo.is_empty(), a.pseudo.to_lowercase())
                .cmp(&(b.pseudo.is_empty(), b.pseudo.to_lowercase()))
        });
        Ok(())
    }

    pub fn remove(&mut self, user_id: &str) -> bool {
        let id = user_id.trim().to_lowercase();
        let n = self.list.len();
        self.list.retain(|c| c.user_id != id);
        self.list.len() != n
    }

    /// Destinataire saisi : vide (aucun), identifiant, ou pseudo d'un contact.
    pub fn resolve(&self, input: &str) -> Result<Option<[u8; 32]>, String> {
        let s = input.trim();
        if s.is_empty() {
            return Ok(None);
        }
        if let Ok(id) = parse_user_id(s) {
            return Ok(Some(id));
        }
        match self.list.iter().find(|c| c.pseudo.eq_ignore_ascii_case(s)) {
            Some(c) => parse_user_id(&c.user_id).map(Some),
            None => Err(format!(
                "« {s} » : ni pseudo d'un contact, ni identifiant de 64 caractères"
            )),
        }
    }

    /// Pseudo du contact `user_id` (hex), s'il en a un.
    pub fn pseudo_of(&self, user_id: &str) -> Option<String> {
        let id = user_id.trim().to_lowercase();
        self.list
            .iter()
            .find(|c| c.user_id == id && !c.pseudo.is_empty())
            .map(|c| c.pseudo.clone())
    }

    /// Affichage d'un utilisateur : pseudo du contact, sinon empreinte.
    pub fn display(&self, user_id: &str) -> String {
        self.pseudo_of(user_id).unwrap_or_else(|| {
            hex::decode(user_id)
                .map(|b| s3m_protocol::pseudo::fingerprint(&b))
                .unwrap_or_default()
        })
    }

    /// Pseudos, pour les suggestions des champs « destinataire ».
    pub fn pseudos(&self) -> Vec<String> {
        self.list
            .iter()
            .filter(|c| !c.pseudo.is_empty())
            .map(|c| c.pseudo.clone())
            .collect()
    }
}
