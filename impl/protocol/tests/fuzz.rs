//! Fuzzing déterministe des décodeurs (cahier de tests NOD-19) : octets
//! aléatoires et messages valides altérés ne provoquent jamais de panique ;
//! un message accepté se réencode.

use s3m_protocol::exchange::*;

/// Générateur xorshift (reproductible, sans dépendance).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn samples() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let req = |body| encode_request(&Request { credential: None, body });
    let requests = vec![
        req(Body::GetBlock { hash: vec![1; 32] }),
        req(Body::PutBlock { data: vec![2; 300] }),
        req(Body::CommitRoot { base_root: vec![3; 32], new_root: vec![4; 32], root_seal: vec![5; 47] }),
        req(Body::ReleaseBlocks { hashes: vec![6; 64] }),
        req(Body::ListRoots),
        req(Body::BlockStatus { hashes: vec![7; 96] }),
        req(Body::RotateUser { new_user_id: vec![8; 32], new_salt: vec![9; 16], code: String::new() }),
    ];
    let responses = vec![
        encode_response(&Response::RootState {
            committed: true,
            current_root: vec![1; 32],
            quota_bytes: 10,
            used_bytes: 5,
            current_root_seal: vec![2; 47],
        }),
        encode_response(&Response::RootList {
            versions: vec![RootVersion { root: vec![3; 32], root_seal: vec![], valid_from: 1, replaced_at: 2 }],
            retention_s: 30,
        }),
        encode_response(&Response::BlockStatusAnswer { present: vec![1], pending: vec![0] }),
        encode_response(&Response::Failure(Refusal::Maintenance)),
    ];
    (requests, responses)
}

#[test]
fn random_and_mutated_messages_never_panic() {
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let (requests, responses) = samples();
    for i in 0..20_000 {
        let data = match i % 3 {
            0 => {
                let n = rng.below(2_048);
                rng.bytes(n)
            }
            1 => {
                let mut m = requests[rng.below(requests.len())].clone();
                for _ in 0..1 + rng.below(8) {
                    let j = rng.below(m.len());
                    m[j] = rng.next() as u8;
                }
                m
            }
            _ => {
                let mut m = responses[rng.below(responses.len())].clone();
                let cut = rng.below(m.len() + 1);
                m.truncate(cut);
                m
            }
        };
        if let Ok(r) = decode_request(&data) {
            let _ = encode_request(&r);
        }
        if let Ok(r) = decode_response(&data) {
            let _ = encode_response(&r);
        }
    }
}

/// Enveloppes d'annuaire reçues d'un pair : jamais de panique, même pour
/// une charge utile minuscule ou tronquée.
#[test]
fn random_directory_envelopes_never_panic() {
    use s3m_protocol::dht::{accept_record, build_envelope};
    let mut rng = Rng(0x0dd_ba11_cafe_f00d);
    let vdf = |_: &[u8; 33], _: &s3m_core::vdf::VdfProof| Ok(true);
    for i in 0..20_000 {
        let n = if i % 2 == 0 { rng.below(12) } else { rng.below(600) };
        let payload = rng.bytes(n);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&rng.bytes(64));
        let mut env = build_envelope(&payload, &sig);
        if i % 3 == 0 && !env.is_empty() {
            let j = rng.below(env.len());
            env[j] = rng.next() as u8;
        }
        let key = rng.bytes(32);
        let _ = accept_record(&key, &env, None, 1_800_000_000, &vdf);
        let m = rng.below(64);
        let raw = rng.bytes(m);
        let _ = accept_record(&key, &raw, None, 1_800_000_000, &vdf);
    }
}
