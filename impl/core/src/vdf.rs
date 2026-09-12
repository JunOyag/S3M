//! VDF de Wesolowski — génération et vérification d'identité anti-Sybil.
//! Réf. spec §2.1.
//!
//! RÈGLE CLAUDE.md #5 : ce module est un BINDING FFI vers `chiavdf`
//! (bibliothèque auditée du projet Chia), PAS une réimplémentation de
//! l'arithmétique de classes de formes quadratiques. Toute PR qui ajoute une
//! implémentation Rust pure de `Cl(Δ)`/NUDUPL ici doit être rejetée — ouvrir
//! une entrée dans impl/SPEC_GAPS.md si le binding FFI s'avère bloquant
//! plutôt que de contourner par une réimplémentation maison.
//!
//! Δ (discriminant global, §2.1) est un paramètre de PROTOCOLE fixe — une
//! constante `const GENESIS_DISCRIMINANT_SEED: &str = "P2P-Storage-VDF-Genesis-2026";`
//! à dériver une seule fois (script séparé, pas au runtime) et à figer en dur
//! ici. Ne jamais la recalculer dynamiquement dans le chemin chaud.

use crate::error::CoreError;

pub struct VdfProof {
    pub y: Vec<u8>,
    pub pi: Vec<u8>,
}

/// Calcul séquentiel (~1 min sur machine de référence, §2.1). Bloquant par
/// construction — à appeler depuis un thread dédié côté impl/node, jamais
/// depuis une boucle async.
pub fn generate_identity_proof(_pub_key: &[u8; 32]) -> Result<VdfProof, CoreError> {
    todo!("Phase 0 — binding FFI chiavdf : create_discriminant, prove(x, T)")
}

/// Vérification en temps logarithmique — utilisable par tout pair DHT.
pub fn verify_identity_proof(_pub_key: &[u8; 32], _proof: &VdfProof) -> Result<bool, CoreError> {
    todo!("Phase 0 — binding FFI chiavdf : verify(x, y, proof, T)")
}
