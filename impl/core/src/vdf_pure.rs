//! Vérification Wesolowski pure Rust — `network.vdf-verifier-pure`.
//!
//! Cette voie est indépendante de `vdf.rs` : elle ne lie pas chiavdf, MPIR ou
//! GMP et s'appuie sur `kyn-vdf` (arithmétique de formes binaires quadratiques
//! en `num-bigint`, composition NUCOMP/NUDUPL et vérification
//! $\pi^\ell x^r = y$). Le recours à cette bibliothèque évite de recopier
//! l'arithmétique de classes de formes dans le crate; les vecteurs et tests
//! ici valident la compatibilité au format et au protocole Chia. Cette
//! dépendance ne fait pas la génération du délai.
//!
//! Les identités taguées sont hachées exactement comme `key_algorithm ||
//! raw_public_key`: le tag est un octet, et chaque octet fourni est inclus
//! dans SHA-256. Le discriminant est toujours reconstruit à partir de ce
//! challenge; aucun discriminant fourni par l'appelant n'est accepté.
//! L'API legacy prend encore la clé brute 32-octets pour ne pas casser
//! `network.vdf-identity`.
//!
//! Les tailles, `T`, et les règles de décodage sont protocolaires. Les formes
//! BQFC doivent être canoniques: après décodage chaque segment est ré-encodé
//! et comparé aux octets reçus, ce qui rejette notamment les flags spéciaux
//! accompagnés de données surnuméraires.

use sha2::{Digest, Sha256};

use crate::{
    error::CoreError,
    vdf::{VdfProof, DISCRIMINANT_BITS, FORM_SIZE, PROOF_SIZE, T},
};

/// Vérifie une preuve avec l'identité taguée complète (`key_algorithm` puis
/// clé publique brute). Hache toute la tranche sans retirer ni normaliser le
/// tag et recalcule ensuite le discriminant associé.
///
/// Une entrée de moins de deux octets ne peut contenir un tag et une clé
/// publique non vide. La taille et l'encodage de la clé propre à chaque
/// algorithme sont validés par l'appelant qui connaît le format d'identité.
pub fn verify_tagged_identity_proof(
    tagged_identity: &[u8],
    proof: &VdfProof,
) -> Result<bool, CoreError> {
    if tagged_identity.len() < 2 {
        return Err(CoreError::InvalidVdfParameter {
            reason: "identité taguée vide ou sans clé publique",
        });
    }

    verify_identity_bytes(tagged_identity, proof)
}

/// Vérification pure de compatibilité pour l'API legacy à clé brute de
/// 32 octets. Les nouvelles identités devraient employer
/// [`verify_tagged_identity_proof`] afin que le discriminant lie aussi
/// `key_algorithm`.
pub fn verify_legacy_identity_proof(
    public_key: &[u8; 32],
    proof: &VdfProof,
) -> Result<bool, CoreError> {
    verify_identity_bytes(public_key, proof)
}

fn verify_identity_bytes(identity_bytes: &[u8], proof: &VdfProof) -> Result<bool, CoreError> {
    verify_identity_bytes_with_iterations(identity_bytes, proof, T)
}

/// Same verifier with explicit iterations for the module's tests. Production
/// entry points above always pass the protocol constant `T`.
fn verify_identity_bytes_with_iterations(
    identity_bytes: &[u8],
    proof: &VdfProof,
    iterations: u64,
) -> Result<bool, CoreError> {
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

    let challenge = Sha256::digest(identity_bytes);
    let mut encoded_proof = [0u8; PROOF_SIZE];
    encoded_proof[..FORM_SIZE].copy_from_slice(&proof.y);
    encoded_proof[FORM_SIZE..].copy_from_slice(&proof.pi);
    verify_challenge(&challenge, &encoded_proof, iterations)
}

/// Vérification de la preuve pour un challenge déjà dérivé et `T` donné.
/// Privée pour que les API exposées ne permettent pas de substituer un
/// challenge ou un discriminant fourni par un pair.
fn verify_challenge(
    challenge: &[u8],
    encoded_proof: &[u8; PROOF_SIZE],
    iterations: u64,
) -> Result<bool, CoreError> {
    if iterations == 0 {
        return Err(CoreError::InvalidVdfParameter { reason: "T = 0" });
    }

    let discriminant = match kyn_vdf::create_discriminant(challenge, DISCRIMINANT_BITS) {
        Ok(discriminant) => discriminant,
        // Une entrée invalide ou un échec de décodage ne valide jamais
        // une identité. La dérivation ne peut échouer avec les
        // constantes et le challenge SHA-256 protocolaires.
        Err(_) => return Ok(false),
    };

    let y_bytes = &encoded_proof[..FORM_SIZE];
    let pi_bytes = &encoded_proof[FORM_SIZE..];
    let y = match kyn_vdf::deserialize_form(&discriminant, y_bytes) {
        Ok(form) => form,
        Err(_) => return Ok(false),
    };
    let pi = match kyn_vdf::deserialize_form(&discriminant, pi_bytes) {
        Ok(form) => form,
        Err(_) => return Ok(false),
    };

    // BQFC has special one-byte forms. Require exact canonical encodings;
    // otherwise non-zero trailing bytes or unused flag bits could be
    // silently discarded by a permissive decoder.
    for (form, bytes) in [(&y, y_bytes), (&pi, pi_bytes)] {
        let canonical = match kyn_vdf::serialize_form(form, DISCRIMINANT_BITS) {
            Ok(canonical) => canonical,
            Err(_) => return Ok(false),
        };
        if canonical.as_slice() != bytes {
            return Ok(false);
        }
    }

    let generator = match kyn_vdf::math::Form::generator(&discriminant) {
        Some(generator) => generator,
        None => return Ok(false),
    };

    // `kyn-vdf` computes HashPrime(serialize(x) || serialize(y), 264),
    // r = 2^T mod ell, then checks pi^ell * x^r == y using pure-Rust
    // class-group arithmetic. The group operations are logarithmic in T.
    Ok(kyn_vdf::verify_wesolowski(&discriminant, &generator, &y, &pi, iterations).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference Chia-format vector exercised by kyn-vdf's verifier tests:
    // challenge 42 repeated 32 times, T=100, and y || pi (200 bytes).
    // Keep this test in the shared module so native and wasm builds compile
    // and execute the same verifier path.
    const CHALLENGE: [u8; 32] = [0x42; 32];
    const PROOF_HEX: &str = "0300032167dfd0eb393ed5d544e6499ba24def860ecd8a3600490f2f87b003c3e7855763969d34e2d1c60910297df3aead9f078a1f4d3973903f532977f9639f693cdbd331e8ba96bd61c895726dd157d67310ae98d1632c9bb9f28e0d7337403c0a010004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    fn reference_proof() -> [u8; PROOF_SIZE] {
        let bytes = hex::decode(PROOF_HEX).expect("valid reference-vector hex");
        bytes
            .try_into()
            .expect("reference vector is exactly 200 bytes")
    }

    #[test]
    fn accepts_chia_reference_vector_and_rejects_altered_bytes() {
        let proof = reference_proof();
        let d = kyn_vdf::create_discriminant(&CHALLENGE, DISCRIMINANT_BITS).unwrap();
        let y = kyn_vdf::deserialize_form(&d, &proof[..FORM_SIZE]).unwrap();
        let pi = kyn_vdf::deserialize_form(&d, &proof[FORM_SIZE..]).unwrap();
        assert_eq!(
            kyn_vdf::serialize_form(&y, DISCRIMINANT_BITS).unwrap(),
            proof[..FORM_SIZE]
        );
        assert_eq!(
            kyn_vdf::serialize_form(&pi, DISCRIMINANT_BITS).unwrap(),
            proof[FORM_SIZE..]
        );
        assert!(verify_challenge(&CHALLENGE, &proof, 100).expect("verification"));

        let mut altered = proof;
        altered[50] ^= 1;
        assert!(!verify_challenge(&CHALLENGE, &altered, 100).expect("verification"));
    }

    #[test]
    fn rejects_wrong_challenge_wrong_iterations_and_malformed_forms() {
        let proof = reference_proof();
        let wrong_challenge = [43; 32];
        assert!(!verify_challenge(&wrong_challenge, &proof, 100).expect("verification"));
        assert!(!verify_challenge(&CHALLENGE, &proof, 101).expect("verification"));

        let mut malformed = proof;
        malformed[0] |= 0x80;
        assert!(!verify_challenge(&CHALLENGE, &malformed, 100).expect("verification"));

        assert!(matches!(
            verify_challenge(&CHALLENGE, &proof, 0),
            Err(CoreError::InvalidVdfParameter { reason: "T = 0" })
        ));
    }

    #[test]
    fn identity_api_enforces_lengths_and_tagged_identity_shape() {
        let proof = VdfProof {
            y: vec![0; FORM_SIZE],
            pi: vec![0; FORM_SIZE],
        };
        assert!(matches!(
            verify_tagged_identity_proof(&[], &proof),
            Err(CoreError::InvalidVdfParameter { .. })
        ));
        assert!(matches!(
            verify_tagged_identity_proof(&[1], &proof),
            Err(CoreError::InvalidVdfParameter { .. })
        ));

        let short = VdfProof {
            y: vec![],
            pi: vec![0; FORM_SIZE],
        };
        assert!(matches!(
            verify_legacy_identity_proof(&[0; 32], &short),
            Err(CoreError::InvalidVdfLength {
                field: "VdfProof.y",
                ..
            })
        ));
    }

    /// Regenerates short reference vectors with chiavdf/MPIR, then compares
    /// the pure-Rust equation for tagged and legacy identity byte strings.
    /// This is test-only: the variable iteration count is not part of the
    /// production API.
    #[cfg(all(feature = "vdf", not(target_arch = "wasm32")))]
    mod mpir_cross_check {
        use super::*;
        use std::time::{Instant, SystemTime, UNIX_EPOCH};

        const FAST_T: u64 = 100;

        fn trace(phase: &str, edge: &str) -> Instant {
            let unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_millis();
            eprintln!("[unix_ms={unix_ms}] T={FAST_T} {phase} {edge}");
            Instant::now()
        }

        fn trace_end(phase: &str, started: Instant) {
            let elapsed = started.elapsed();
            let unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_millis();
            eprintln!("[unix_ms={unix_ms}] T={FAST_T} {phase} END elapsed={elapsed:?}");
        }

        fn mpir_proof(identity_bytes: &[u8]) -> (VdfProof, [u8; FORM_SIZE], [u8; 128]) {
            let challenge = Sha256::digest(identity_bytes);
            let mut start_form = [0u8; FORM_SIZE];
            start_form[0] = 0x08;

            let started = trace("create_discriminant", "START");
            let mut discriminant = [0u8; 128];
            assert!(
                chiavdf::create_discriminant(&challenge, &mut discriminant),
                "chiavdf::create_discriminant failed"
            );
            trace_end("create_discriminant", started);

            // chiavdf 1.1.14 exposes no standalone hash-to-form operation.
            // Its prove wrapper deserializes x_s internally, so that work
            // cannot be separately timed through the published Rust API.
            let unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_millis();
            eprintln!(
                "[unix_ms={unix_ms}] T={FAST_T} hash-to-form/DeserializeForm NOT_EXPOSED as separate API operation; executed inside chiavdf::prove"
            );

            // The published `prove` wrapper combines CreateDiscriminant,
            // DeserializeForm, the complete ProveSlow evaluation/proof, and
            // serialization. None of those internal boundaries is exposed
            // for separate timing by the Rust API.
            let started = trace(
                "chiavdf::prove (combined; internals not separately measurable)",
                "START",
            );
            let blob = chiavdf::prove(&challenge, &start_form, DISCRIMINANT_BITS, FAST_T)
                .expect("chiavdf::prove failed to return an MPIR proof");
            trace_end(
                "chiavdf::prove (combined; internals not separately measurable)",
                started,
            );
            assert_eq!(
                blob.len(),
                PROOF_SIZE,
                "chiavdf::prove returned an unexpected proof length"
            );

            (
                VdfProof {
                    y: blob[..FORM_SIZE].to_vec(),
                    pi: blob[FORM_SIZE..].to_vec(),
                },
                start_form,
                discriminant,
            )
        }

        fn assert_same_decision(
            identity_bytes: &[u8],
            proof: &VdfProof,
            start_form: &[u8; FORM_SIZE],
            discriminant: &[u8; 128],
        ) -> bool {
            let started = trace("pure verify_identity_bytes_with_iterations", "START");
            let pure_result = verify_identity_bytes_with_iterations(identity_bytes, proof, FAST_T);
            trace_end("pure verify_identity_bytes_with_iterations", started);
            let pure = pure_result.expect("pure Rust verifier failed to produce a decision");
            let mut blob = [0u8; PROOF_SIZE];
            blob[..FORM_SIZE].copy_from_slice(&proof.y);
            blob[FORM_SIZE..].copy_from_slice(&proof.pi);
            let started = trace("chiavdf::verify_n_wesolowski", "START");
            let mpir = chiavdf::verify_n_wesolowski(discriminant, start_form, &blob, FAST_T, 0);
            trace_end("chiavdf::verify_n_wesolowski", started);
            assert_eq!(pure, mpir, "pure Rust and MPIR decisions differ");
            pure
        }

        /// Independently times MPIR verification of the existing Chia
        /// reference vector. This is not a proof generated by MPIR.
        #[test]
        fn verifies_chia_reference_vector_with_mpir() {
            let challenge = CHALLENGE;
            let proof = reference_proof();
            let mut start_form = [0u8; FORM_SIZE];
            start_form[0] = 0x08;

            let started = trace("create_discriminant for Chia reference", "START");
            let mut discriminant = [0u8; 128];
            assert!(
                chiavdf::create_discriminant(&challenge, &mut discriminant),
                "chiavdf::create_discriminant failed for Chia reference"
            );
            trace_end("create_discriminant for Chia reference", started);

            let started = trace("chiavdf::verify_n_wesolowski Chia reference", "START");
            let valid = chiavdf::verify_n_wesolowski(&discriminant, &start_form, &proof, FAST_T, 0);
            trace_end("chiavdf::verify_n_wesolowski Chia reference", started);
            assert!(
                valid,
                "chiavdf::verify_n_wesolowski must accept the Chia reference vector"
            );
        }

        #[test]
        fn tagged_identity_mpir_vector_and_rejections_match() {
            let tagged_identity = [vec![0x07], vec![0x31; 32]].concat();
            let (proof, start_form, discriminant) = mpir_proof(&tagged_identity);
            assert!(
                assert_same_decision(&tagged_identity, &proof, &start_form, &discriminant),
                "MPIR cross-check must accept the generated T=100 tagged-identity vector"
            );

            let mut altered = proof.clone();
            altered.pi[25] ^= 1;
            assert!(
                !assert_same_decision(&tagged_identity, &altered, &start_form, &discriminant),
                "MPIR cross-check must reject the altered T=100 tagged-identity proof"
            );

            let mut other_tag = tagged_identity.clone();
            other_tag[0] ^= 1;
            let (_, other_start, other_discriminant) = mpir_proof(&other_tag);
            assert!(
                !assert_same_decision(&other_tag, &proof, &other_start, &other_discriminant),
                "MPIR cross-check must reject a proof bound to a different identity tag"
            );
        }

        #[test]
        fn legacy_identity_mpir_vector_matches() {
            let public_key = [0xA1; 32];
            let (proof, start_form, discriminant) = mpir_proof(&public_key);
            assert!(
                assert_same_decision(&public_key, &proof, &start_form, &discriminant),
                "MPIR cross-check must accept the generated T=100 legacy-identity vector"
            );
        }
    }
}
