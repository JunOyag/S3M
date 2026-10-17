//! VDF de Wesolowski — génération et vérification d'identité anti-Sybil.
//! Réf. spec §2.1 (`docs/01-network-dht/vdf-identity.md`).
//!
//! RÈGLE CLAUDE.md #5 : ce module est un BINDING FFI vers `chiavdf`
//! (bibliothèque auditée du projet Chia), PAS une réimplémentation de
//! l'arithmétique de classes de formes quadratiques. Toute PR qui ajoute une
//! implémentation Rust pure de `Cl(Δ)`/NUDUPL ici doit être rejetée — ouvrir
//! une entrée dans impl/SPEC_GAPS.md si le binding FFI s'avère bloquant
//! plutôt que de contourner par une réimplémentation maison.
//!
//! Points d'arbitrage (entrées `network.vdf-identity` d'impl/SPEC_GAPS.md,
//! tranchées le 17/10/2026) que ce module applique :
//! - **Δ par identité** : `challenge = SHA-256(pub_key)`, `Δ = −HashPrime(
//!   challenge, 1024)` recalculé par le vérificateur — jamais reçu du
//!   prouveur. (Le stub initial documentait un « Δ global » avec graine
//!   GENESIS : périmé — la page a été mise à jour en conséquence.)
//! - Constantes de protocole : `DISCRIMINANT_BITS = 1024`, `T = 5_400_000`,
//!   `recursion = 0` — ci-dessous.
//! - Forme de départ : l'élément par défaut de chiavdf, sérialisation BQFC
//!   de 100 octets `0x08 ‖ 99 × 0x00` — le drapeau `BQFC_IS_GEN` (`1 << 3`
//!   dans `bqfc.c`), soit la forme génératrice `(2, 1, (1 − Δ)/8)`, et non
//!   l'élément neutre `(1, 1, (1 − Δ)/4)`.
//! - Garde-fous avant **tout** appel FFI (`verify_n_wesolowski` transmet
//!   `x_s` sans sa longueur à la couche C++) : forme de départ 100 octets et
//!   discriminant 128 octets (tailles fixes, garanties par le type), preuve
//!   `y ‖ π` = 200 octets (contrôles de `y` et `π` ci-dessous).
//!
//! Liaison : feature `vdf` (non active par défaut) hors cible `wasm32` —
//! voir `impl/TECH_STACK.md`. Sans cette feature (dev local sans outillage
//! C++) ou en WASM (le Connecteur charge chiavdf par liaison native :
//! `bun:ffi` ou binaire sidecar), les fonctions renvoient
//! [`CoreError::VdfUnavailable`]. Les builds et tests `--features vdf`
//! tournent en CI (`.github/workflows/vdf-identity.yml`) : une machine de
//! développement Windows sans droits administrateur ne peut pas installer
//! l'outillage MSVC (arbitrage du 17/10/2026).

use crate::error::CoreError;

/// Taille du discriminant en bits (λ) — plafond de la bibliothèque, et
/// paramètre Chia en production (page § « Paramètres de protocole »).
pub const DISCRIMINANT_BITS: usize = 1024;

/// `T` de protocole, en itérations (page § « Calibration de T ») : de
/// l'ordre de 30 s à 1,5 min selon la plateforme. Toute preuve produite avec
/// un autre `T` est rejetée par [`verify_identity_proof`] — les variantes
/// `_params` ci-dessous sont réservées aux tests, à la calibration et au
/// diagnostic.
pub const T: u64 = 5_400_000;

/// `recursion` de protocole : preuve de Wesolowski simple, sans récursion.
pub const RECURSION: u64 = 0;

/// Taille d'une forme sérialisée BQFC (`BQFC_FORM_SIZE` de chiavdf) : `y`,
/// `π` et la forme de départ font chacun 100 octets.
pub const FORM_SIZE: usize = 100;

/// Taille de la preuve complète `y ‖ π` (page § « Paramètres de protocole »).
pub const PROOF_SIZE: usize = 200;

/// Taille du discriminant sérialisé : `λ / 8`.
pub const DISCRIMINANT_SIZE: usize = 128;

/// Preuve publiée avec l'identité : le tuple DHT est `(pub_key, y ‖ π)`.
/// `T`, `recursion`, `λ` et la dérivation de `Δ` sont implicites — constantes
/// de protocole ci-dessus, connues de tout vérificateur.
#[derive(Debug, Clone)]
pub struct VdfProof {
    pub y: Vec<u8>,
    pub pi: Vec<u8>,
}

/// Génère la preuve d'identité avec les constantes de protocole ([`T`]
/// itérations, [`RECURSION`]). Calcul séquentiel bloquant (~30 s à 1,5 min
/// selon la plateforme) : à appeler depuis un thread dédié côté `impl/node`,
/// jamais depuis une boucle async.
pub fn generate_identity_proof(pub_key: &[u8; 32]) -> Result<VdfProof, CoreError> {
    generate_identity_proof_params(pub_key, T)
}

/// Variante de [`generate_identity_proof`] avec `t` explicite — usage tests,
/// calibration (réexamen de `T`, page § « Calibration de T ») et diagnostic.
/// Une preuve générée avec `t ≠` [`T`] ne passera **pas** la vérification de
/// protocole.
pub fn generate_identity_proof_params(pub_key: &[u8; 32], t: u64) -> Result<VdfProof, CoreError> {
    if t == 0 {
        return Err(CoreError::InvalidVdfParameter { reason: "T = 0" });
    }
    sys::generate(pub_key, t)
}

/// Vérifie une preuve en temps logarithmique — utilisable par tout pair DHT.
/// Le vérificateur recalcule `Δ` lui-même à partir de `pub_key` et n'accepte
/// jamais un `Δ` fourni par le prouveur (page § « Setup »), sans quoi une
/// preuve calculée une seule fois serait réutilisable pour toutes les
/// identités.
pub fn verify_identity_proof(pub_key: &[u8; 32], proof: &VdfProof) -> Result<bool, CoreError> {
    verify_identity_proof_params(pub_key, proof, T, RECURSION)
}

/// Variante de [`verify_identity_proof`] avec `t` et `recursion` explicites
/// — usage tests et diagnostic (voir [`generate_identity_proof_params`]).
pub fn verify_identity_proof_params(
    pub_key: &[u8; 32],
    proof: &VdfProof,
    t: u64,
    recursion: u64,
) -> Result<bool, CoreError> {
    if t == 0 {
        return Err(CoreError::InvalidVdfParameter { reason: "T = 0" });
    }
    // Garde-fous avant tout appel FFI (arbitrage du 17/10/2026) :
    // `verify_n_wesolowski` lit `x_s` à taille fixe SANS en recevoir la
    // longueur — lecture hors limites possible sur une entrée venant d'un
    // pair hostile. `y` et `π` doivent valoir 100 octets chacun (donc
    // `y ‖ π` = 200 octets pour `recursion = 0`) ; la forme de départ (100)
    // et le discriminant (128) sont à taille fixe par leur type Rust.
    if proof.y.len() != FORM_SIZE {
        return Err(CoreError::InvalidVdfLength {
            field: "VdfProof.y",
            expected: FORM_SIZE,
            got: proof.y.len(),
        });
    }
    if proof.pi.len() != FORM_SIZE {
        return Err(CoreError::InvalidVdfLength {
            field: "VdfProof.pi",
            expected: FORM_SIZE,
            got: proof.pi.len(),
        });
    }
    sys::verify(pub_key, proof, t, recursion)
}

/// Binding réel : la crate `chiavdf` n'est liée qu'avec la feature `vdf`,
/// sur une cible non-`wasm32` (dépendance de cible dans Cargo.toml).
#[cfg(all(feature = "vdf", not(target_arch = "wasm32")))]
mod sys {
    use super::*;
    use sha2::{Digest, Sha256};

    pub fn generate(pub_key: &[u8; 32], t: u64) -> Result<VdfProof, CoreError> {
        let challenge = Sha256::digest(pub_key);
        let x_s = default_start_form();
        // `prove` dérive Δ du challenge lui-même (CreateDiscriminant, même
        // masque HashPrime que le vérificateur) : les deux côtés calculent le
        // même discriminant sans jamais l'échanger sur le réseau.
        let blob = chiavdf::prove(&challenge, &x_s, DISCRIMINANT_BITS, t)
            .ok_or(CoreError::VdfProveFailure)?;
        if blob.len() != PROOF_SIZE {
            return Err(CoreError::InvalidVdfLength {
                field: "sortie de prove()",
                expected: PROOF_SIZE,
                got: blob.len(),
            });
        }
        Ok(VdfProof {
            y: blob[..FORM_SIZE].to_vec(),
            pi: blob[FORM_SIZE..].to_vec(),
        })
    }

    pub fn verify(
        pub_key: &[u8; 32],
        proof: &VdfProof,
        t: u64,
        recursion: u64,
    ) -> Result<bool, CoreError> {
        let challenge = Sha256::digest(pub_key);
        // Δ recalculé par le vérificateur : 128 octets = λ bits (HashPrime
        // force le bit λ−1, l'export du discriminant tient donc exactement
        // 128 octets).
        let mut discriminant = [0u8; DISCRIMINANT_SIZE];
        if !chiavdf::create_discriminant(&challenge, &mut discriminant) {
            return Err(CoreError::VdfDiscriminantFailure);
        }
        let x_s = default_start_form();
        let mut blob = [0u8; PROOF_SIZE];
        blob[..FORM_SIZE].copy_from_slice(&proof.y);
        blob[FORM_SIZE..].copy_from_slice(&proof.pi);
        Ok(chiavdf::verify_n_wesolowski(
            &discriminant,
            &x_s,
            &blob,
            t,
            recursion,
        ))
    }

    /// Forme de départ fixe de chiavdf : sérialisation BQFC `0x08 ‖ 99 × 0x00`
    /// — drapeau `BQFC_IS_GEN` (`1 << 3` dans `bqfc.c`) = forme génératrice
    /// `(2, 1, (1 − Δ)/8)`, valide car le masque `HashPrime {0, 1, 2, λ−1}`
    /// impose `p ≡ 7 mod 8`, donc `Δ = −p ≡ 1 mod 8`. C'est le discriminant —
    /// et non la forme de départ — qui porte l'identité : deux identités
    /// distinctes calculent dans deux `Cl(Δ)` différents.
    fn default_start_form() -> [u8; FORM_SIZE] {
        let mut x_s = [0u8; FORM_SIZE];
        x_s[0] = 0x08;
        x_s
    }
}

/// Hors feature `vdf` ou en WASM : la VDF n'est pas liée (voir l'en-tête du
/// module). Le Connecteur l'obtient par liaison native par plateforme
/// (`bun:ffi` ou binaire sidecar), jamais par le pont WASM.
#[cfg(not(all(feature = "vdf", not(target_arch = "wasm32"))))]
mod sys {
    use super::*;

    pub fn generate(_pub_key: &[u8; 32], _t: u64) -> Result<VdfProof, CoreError> {
        Err(CoreError::VdfUnavailable)
    }

    pub fn verify(
        _pub_key: &[u8; 32],
        _proof: &VdfProof,
        _t: u64,
        _recursion: u64,
    ) -> Result<bool, CoreError> {
        Err(CoreError::VdfUnavailable)
    }
}

