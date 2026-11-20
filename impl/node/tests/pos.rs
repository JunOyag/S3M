//! Invariants de `securite.pos-challenges`.

use s3m_core::erasure::encode_parity;
use s3m_node::pos::*;

fn data() -> Vec<Vec<u8>> {
    (0..4).map(|i| vec![i as u8 + 1; 4096]).collect()
}

/// La référence est recalculée en local depuis les k blocs : un partenaire
/// honnête (qui détient le vrai fragment) passe ; un autre fragment = fraude.
#[test]
fn honest_partner_passes_and_wrong_fragment_is_fraud() {
    let d = data();
    let refs: Vec<&[u8]> = d.iter().map(|x| x.as_slice()).collect();
    let parity = encode_parity(&refs, 3).unwrap();
    let nonce = [9; 32];
    let expected = expected_response(&refs, 3, 5, &nonce).unwrap();
    let honest = challenge_response(&parity[5], &nonce);
    assert_eq!(judge(&expected, Some(&honest)), Verdict::Passed);
    let cheat = challenge_response(&parity[6], &nonce);
    assert_eq!(judge(&expected, Some(&cheat)), Verdict::Fraud);
    assert_eq!(judge(&expected, None), Verdict::Timeout);
    // Nonce neuf : une réponse rejouée ne vaut rien.
    let other = expected_response(&refs, 3, 5, &[1; 32]).unwrap();
    assert_eq!(judge(&other, Some(&honest)), Verdict::Fraud);
}

/// Toute demande de bloc complet vaut challenge.
#[test]
fn full_block_request_is_judged_like_a_challenge() {
    let d = data();
    let refs: Vec<&[u8]> = d.iter().map(|x| x.as_slice()).collect();
    let parity = encode_parity(&refs, 3).unwrap();
    assert_eq!(
        judge_full_block(&parity[0], Some(&parity[0])),
        Verdict::Passed
    );
    let mut bad = parity[0].clone();
    bad[0] ^= 1;
    assert_eq!(judge_full_block(&parity[0], Some(&bad)), Verdict::Fraud);
    assert_eq!(judge_full_block(&parity[0], None), Verdict::Timeout);
}

#[test]
fn timeout_follows_measured_mean_latency() {
    let mut t = LatencyTracker::default();
    assert_eq!(t.timeout_ms(), 1_000);
    t.record(100);
    assert_eq!(t.timeout_ms(), 1_000);
    for _ in 0..50 {
        t.record(800);
    }
    assert!(t.mean_ms().unwrap() > 790);
    assert!(t.timeout_ms() >= 2_080);
}

/// QoS : le bridage s'applique au transfert de blocs, jamais au PoS.
#[test]
fn pos_messages_are_never_throttled() {
    let mut th = Throttle::new(100_000);
    assert!(th.allow(Traffic::BlockTransfer, 65_536, 0));
    assert!(!th.allow(Traffic::BlockTransfer, 65_536, 0));
    for _ in 0..1_000 {
        assert!(th.allow(Traffic::Pos, 64, 0));
    }
    assert!(th.allow(Traffic::BlockTransfer, 65_536, 1));
}
