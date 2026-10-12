//! K_node_self — confidentialité de la cartographie de dispersion du Nœud.
//! Id `crypto.k-node-self` (Phase 0). Réf. spec : docs/03-crypto/
//! k-node-self.md (§3.8). Symétrique de `k_self`, côté Nœud.
//!
//! ```text
//! K_node_self = KDF(priv_node, "node-recovery")
//! ```
//! Dérivée uniquement de la clé privée du Nœud — dérivable de la seed seule,
//! sans état local préservé (restauration complète possible, page spec,
//! §« Ce qu'elle protège »).
//!
//! Choix d'implémentation du « KDF » de la spec : HKDF-SHA-256 (bibliothèque
//! `hkdf`, cf. impl/TECH_STACK.md et `k_self.rs`), sortie 32 octets,
//! `info = "node-recovery"`, salt HKDF interne par défaut (aucun salt
//! externe nommé par la formule — même cas que `K_self`).
//!
//! `priv_node` : graine Ed25519 de 32 octets du Nœud (schéma de chemins
//! SLIP-0010, voir `crypto.identity-derivation` — la dérivation
//! seed → graine est hors périmètre de ce module).
//!
//! Invariants testés : déterminisme, sensibilité à `priv_node`, séparation
//! de domaine (le domaine `info` « node-recovery » est distinct de
//! « attachment-recovery » — les clés User et Nœud d'une même graine ne
//! collisionnent pas) — voir `tests/k_node_self_vectors.rs`.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CoreError;

/// Dérive `K_node_self` depuis la graine Ed25519 du Nœud.
///
/// Chiffre `node_snapshot_root_hash` et `node_snapshot_root_partners` dans
/// l'entrée DHT publique du Nœud : sans lui, un observateur reconstruirait
/// le graphe des relations de dispersion (page spec, §« Ce qu'elle protège »).
pub fn derive_k_node_self(priv_node: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, priv_node)
        .expand(b"node-recovery", &mut okm)
        .map_err(|_| CoreError::KdfFailure)?;
    Ok(okm)
}
