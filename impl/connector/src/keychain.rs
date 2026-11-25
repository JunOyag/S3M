//! Trousseau des clés maîtresses après une rotation d'identité
//! (`securite.incidents-compromissions#rotation-user`,
//! `crypto.master-key-chain`) : les anciennes clés, chiffrées sous la clé
//! maîtresse courante, gardées sur l'appareil et dans l'espace de
//! l'Utilisateur ([`TREE_PATH`]) pour qu'un appareil neuf les retrouve avec
//! la seule nouvelle phrase de récupération.

use std::collections::HashMap;
use std::path::Path;

use s3m_core::master_key_chain::{resolve_master_key, rewrap_chain_on_rotation, MasterKeyEntry};
use s3m_core::version::CURRENT_HEADER;
use serde::{Deserialize, Serialize};

/// Fichier du trousseau sur l'appareil (dossier de données de l'identité).
pub const FILE: &str = "keychain.json";
/// Copie dans l'espace de l'Utilisateur (chiffrée comme tout fichier).
pub const TREE_DIR: &str = "/.s3m";
pub const TREE_PATH: &str = "/.s3m/cles-anciennes.json";

/// Trousseau : version courante et anciennes clés `(version, clé chiffrée)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keychain {
    pub version: u16,
    pub chain: Vec<(u16, String)>,
}

impl Keychain {
    /// Anciennes clés `historical` chiffrées sous `current` (version
    /// `version`).
    pub fn wrap(
        historical: &HashMap<u16, [u8; 32]>,
        current: &[u8; 32],
        version: u16,
    ) -> Result<Self, String> {
        let chain = rewrap_chain_on_rotation(&CURRENT_HEADER, historical, current, version)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            version,
            chain: chain
                .into_iter()
                .map(|e| (e.version, hex::encode(e.wrapped_key)))
                .collect(),
        })
    }

    /// Toutes les clés : anciennes déchiffrées et courante.
    pub fn keys(&self, current: &[u8; 32]) -> Result<HashMap<u16, [u8; 32]>, String> {
        let chain: Vec<MasterKeyEntry> = self
            .chain
            .iter()
            .map(|(v, w)| MasterKeyEntry {
                version: *v,
                wrapped_key: hex::decode(w).unwrap_or_default(),
            })
            .collect();
        let mut out = HashMap::new();
        for (v, _) in &self.chain {
            let k = resolve_master_key(&CURRENT_HEADER, &chain, current, self.version, *v)
                .map_err(|e| format!("trousseau : clé {v} illisible ({e})"))?;
            out.insert(*v, k);
        }
        out.insert(self.version, *current);
        Ok(out)
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("sérialisable")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }

    pub fn load(data_dir: &Path) -> Option<Self> {
        Self::decode(&std::fs::read(data_dir.join(FILE)).ok()?)
    }

    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        let tmp = data_dir.join("keychain.json.tmp");
        std::fs::write(&tmp, self.encode())?;
        std::fs::rename(tmp, data_dir.join(FILE))
    }
}
