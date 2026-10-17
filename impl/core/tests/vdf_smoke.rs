//! Vecteurs et invariants pour `network.vdf-identity` (Phase 0).
//!
//! Conforme à l'arbitrage SPEC_GAPS du 17/10/2026 : ces tests tournent en CI
//! (`cargo test --features vdf`, `.github/workflows/vdf-identity.yml`) — la
//! crate `chiavdf` ne se compile ni en WASM ni sur la machine de
//! développement Windows sans outillage MSVC (voir impl/TECH_STACK.md,
//! section « Environnement de build et CI »). Sans la feature `vdf`, ce
//! fichier entier est neutralisé (`#![cfg]`) et `cargo test` local reste
//! vert.
//!
//! Invariants couverts (page `docs/01-network-dht/vdf-identity.md`) :
//! - aller-retour génération/vérification avec les constantes de protocole
//!   (`T = 5 400 000`), avec borne de temps ;
//! - preuve rejetée pour une autre identité (Δ différent), octet altéré,
//!   mauvais `T`, `recursion ≠ 0` (preuve de 200 octets insuffisante) ;
//! - entrées hostiles : preuve vide ou tronquée, octets aléatoires,
//!   `T = 0`, `T = u64::MAX` — toutes bornées en temps.
//!
//! Règle fixtures : les entrées ci-dessous sont des constantes de test
//! internes arbitraires, jamais des valeurs attendues produites par le code.
#![cfg(feature = "vdf")]

use std::time::{Duration, Instant};

use p2p_storage_core::vdf::{
    generate_identity_proof, generate_identity_proof_params, verify_identity_proof,
    verify_identity_proof_params, VdfProof, FORM_SIZE,
};
use p2p_storage_core::CoreError;

/// `T` rapide pour les tests hors aller-retour de protocole (~1 s sur les
/// runners CI au débit mesuré de la page § « Calibration de T »). Le
/// protocole impose `T = 5 400 000` : c'est ce que valide le test
/// `roundtrip_verifies_with_protocol_constants` ci-dessous.
const FAST_T: u64 = 100_000;

/// Bornes de temps — filets anti-régression, pas des benchmarks : marges
/// larges sur les durées mesurées de la page § « Calibration de T »
/// (31 s à 83 s pour `T = 5 400 000`, débit minimal mesuré 65 068 it/s).
const GEN_PROTOCOL_BOUND: Duration = Duration::from_secs(300);
const GEN_FAST_BOUND: Duration = Duration::from_secs(120);
/// La vérification est logarithmique (~20 ms mesurés, Δ recalcul compris).
const VERIFY_BOUND: Duration = Duration::from_secs(30);

/// Identité de test A (fixture arbitraire).
const PUB_KEY_A: [u8; 32] = [0xA1; 32];
/// Identité de test B, distincte de A.
const PUB_KEY_B: [u8; 32] = [0xB2; 32];

fn fast_proof(pub_key: &[u8; 32]) -> VdfProof {
    generate_identity_proof_params(pub_key, FAST_T).expect("génération VDF (T rapide)")
}

/// Octets déterministes (xorshift64*) — fixture interne arbitraire, sans
/// générateur aléatoire dans la suite.
fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Aller-retour avec les constantes de protocole : `T = 5 400 000`,
/// `recursion = 0`, `DISCRIMINANT_BITS = 1024`, durées bornées.
#[test]
fn roundtrip_verifies_with_protocol_constants() {
    let start = Instant::now();
    let proof = generate_identity_proof(&PUB_KEY_A).expect("génération avec T de protocole");
    let gen = start.elapsed();
    assert!(
        gen < GEN_PROTOCOL_BOUND,
        "génération à T = 5 400 000 trop lente : {gen:?}"
    );
    assert_eq!(proof.y.len(), FORM_SIZE);
    assert_eq!(proof.pi.len(), FORM_SIZE);

    let start = Instant::now();
    let valid = verify_identity_proof(&PUB_KEY_A, &proof).expect("vérification de protocole");
    let dur = start.elapsed();
    assert!(
        valid,
        "la preuve générée avec les constantes de protocole doit vérifier"
    );
    assert!(dur < VERIFY_BOUND, "vérification trop lente : {dur:?}");
}

/// Même aller-retour avec un petit `T` (test rapide du binding — sert aussi
/// de preuve valide aux négatifs ci-dessous).
#[test]
fn roundtrip_verifies_with_fast_t() {
    let start = Instant::now();
    let proof = fast_proof(&PUB_KEY_A);
    let gen = start.elapsed();
    assert!(
        gen < GEN_FAST_BOUND,
        "génération (T rapide) trop lente : {gen:?}"
    );

    let start = Instant::now();
    let valid = verify_identity_proof_params(&PUB_KEY_A, &proof, FAST_T, 0).expect("vérification");
    let dur = start.elapsed();
    assert!(valid);
    assert!(dur < VERIFY_BOUND, "vérification trop lente : {dur:?}");
}

/// Δ découle de `pub_key` : une preuve calculée pour A n'est pas réutilisable
/// pour une autre identité B (page § « Setup » — le vérificateur recalcule
/// Δ lui-même ; Δ n'est jamais choisi par le prouveur).
#[test]
fn proof_is_rejected_for_another_identity() {
    let proof = fast_proof(&PUB_KEY_A);
    let start = Instant::now();
    let valid = verify_identity_proof_params(&PUB_KEY_B, &proof, FAST_T, 0).expect("vérification");
    assert!(start.elapsed() < VERIFY_BOUND);
    assert!(
        !valid,
        "une preuve d'identité A ne doit jamais valoir pour B (Δ différent)"
    );
}

/// Une preuve dont un octet de `y` a été altéré doit être rejetée.
#[test]
fn proof_is_rejected_when_a_byte_is_altered() {
    let mut proof = fast_proof(&PUB_KEY_A);
    proof.y[10] ^= 0x01;
    let start = Instant::now();
    let valid = verify_identity_proof_params(&PUB_KEY_A, &proof, FAST_T, 0).expect("vérification");
    assert!(start.elapsed() < VERIFY_BOUND);
    assert!(!valid, "un octet altéré de y doit invalider la preuve");
}

/// `T` est une constante de protocole : vérifier avec un `T` différent de
/// celui de la génération doit échouer.
#[test]
fn proof_is_rejected_with_wrong_t() {
    let proof = fast_proof(&PUB_KEY_A);
    let start = Instant::now();
    let valid =
        verify_identity_proof_params(&PUB_KEY_A, &proof, FAST_T + 1, 0).expect("vérification");
    assert!(start.elapsed() < VERIFY_BOUND);
    assert!(!valid, "un mauvais T doit invalider la preuve");
}

/// `recursion = 0` est la valeur de protocole : avec `recursion ≠ 0`, le
/// vérificateur attend un blob plus long (segments n-wesolowski) — les
/// 200 octets de la preuve de protocole doivent être rejetés sans lecture
/// hors limites (chiavdf vérifie la longueur du blob côté C++).
#[test]
fn proof_is_rejected_with_nonzero_recursion() {
    let proof = fast_proof(&PUB_KEY_A);
    let start = Instant::now();
    let valid = verify_identity_proof_params(&PUB_KEY_A, &proof, FAST_T, 1).expect("vérification");
    let dur = start.elapsed();
    assert!(
        dur < VERIFY_BOUND,
        "vérification avec recursion ≠ 0 trop lente : {dur:?}"
    );
    assert!(
        !valid,
        "recursion = 1 sur une preuve de 200 octets doit être rejetée"
    );
}

/// `T = u64::MAX` : appel pathologique côté vérificateur — la vérification
/// doit rester bornée en temps et rejeter la preuve.
#[test]
fn verification_with_t_max_is_bounded_and_rejected() {
    let proof = fast_proof(&PUB_KEY_A);
    let start = Instant::now();
    let valid = verify_identity_proof_params(&PUB_KEY_A, &proof, u64::MAX, 0).expect("vérification");
    let dur = start.elapsed();
    assert!(dur < VERIFY_BOUND, "T = u64::MAX doit rester borné : {dur:?}");
    assert!(!valid, "T = u64::MAX ne doit jamais valider une preuve produite à FAST_T");
}

/// Entrées hostiles : preuve vide et preuve tronquée (π sur 99 octets) —
/// rejetées par le contrôle de longueurs AVANT tout appel FFI.
#[test]
fn empty_and_truncated_proofs_are_rejected() {
    let start = Instant::now();

    let empty = VdfProof {
        y: Vec::new(),
        pi: Vec::new(),
    };
    let err = verify_identity_proof(&PUB_KEY_A, &empty).expect_err("preuve vide rejetée");
    assert!(matches!(
        err,
        CoreError::InvalidVdfLength {
            field: "VdfProof.y",
            expected: FORM_SIZE,
            got: 0
        }
    ));

    let mut truncated = fast_proof(&PUB_KEY_A);
    truncated.pi.pop();
    let err = verify_identity_proof(&PUB_KEY_A, &truncated).expect_err("preuve tronquée rejetée");
    assert!(matches!(
        err,
        CoreError::InvalidVdfLength {
            field: "VdfProof.pi",
            expected: FORM_SIZE,
            got: 99
        }
    ));

    assert!(start.elapsed() < VERIFY_BOUND);
}

/// Entrées hostiles : octets pseudo-aléatoires (fixture déterministe) ne
/// doivent jamais vérifier, en temps borné.
#[test]
fn random_bytes_proof_is_rejected() {
    let proof = VdfProof {
        y: deterministic_bytes(0x00C0_FFEE, FORM_SIZE),
        pi: deterministic_bytes(0xDEAD_BEEF, FORM_SIZE),
    };
    let start = Instant::now();
    let accepted = verify_identity_proof(&PUB_KEY_A, &proof).unwrap_or(false);
    let dur = start.elapsed();
    assert!(
        dur < VERIFY_BOUND,
        "vérification d'octets aléatoires trop lente : {dur:?}"
    );
    assert!(!accepted, "des octets aléatoires ne doivent jamais valider");
}

/// `T = 0` est rejeté côté wrapper avant tout appel FFI (génération ET
/// vérification) — comportement déterministe, temps trivialement borné.
#[test]
fn t_zero_is_rejected_before_any_ffi_call() {
    let start = Instant::now();

    let err = generate_identity_proof_params(&PUB_KEY_A, 0).expect_err("génération T=0 rejetée");
    assert!(matches!(err, CoreError::InvalidVdfParameter { .. }));

    let proof = fast_proof(&PUB_KEY_A);
    let err = verify_identity_proof_params(&PUB_KEY_A, &proof, 0, 0)
        .expect_err("vérification T=0 rejetée");
    assert!(matches!(err, CoreError::InvalidVdfParameter { .. }));

    assert!(start.elapsed() < VERIFY_BOUND);
}