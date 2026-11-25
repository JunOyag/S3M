//! Fuzzing déterministe du traitement des requêtes par le Nœud (cahier de
//! tests NOD-19) : champs aléatoires sous un identifiant valide, requêtes
//! altérées : jamais de panique.

use s3m_core::k_attach::derive_k_attach_as_user;
use s3m_node::exchange::{NodeService, UserAccount};
use s3m_protocol::exchange::*;

const NODE: [u8; 32] = [0x10; 32];
const USER: [u8; 32] = [0x40; 32];
const SALT: [u8; 16] = [7; 16];

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

fn pk(s: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(s).verifying_key().to_bytes()
}

fn credential() -> Credential {
    let k = derive_k_attach_as_user(&USER, &pk(&NODE), &SALT).unwrap();
    Credential::User {
        user_id: pk(&USER).to_vec(),
        proof: connector_proof(&k, b"c", b"n").to_vec(),
    }
}

fn body(r: &mut Rng) -> Body {
    let len = |r: &mut Rng| [0, 1, 16, 31, 32, 33, 47, 64, 65, 96].get(r.below(10)).copied().unwrap_or(32);
    match r.below(10) {
        0 => Body::GetBlock { hash: { let n = len(r); r.bytes(n) } },
        1 => Body::PutBlock { data: { let n = r.below(70_000); r.bytes(n) } },
        2 => Body::CommitRoot {
            base_root: { let n = len(r); r.bytes(n) },
            new_root: { let n = len(r); r.bytes(n) },
            root_seal: { let n = len(r); r.bytes(n) },
        },
        3 => Body::ReleaseBlocks { hashes: { let n = len(r); r.bytes(n) } },
        4 => Body::ListBlocks { after: { let n = len(r); r.bytes(n) }, limit: r.next() as u32 },
        5 => Body::BlockStatus { hashes: { let n = len(r); r.bytes(n) } },
        6 => Body::RotateUser { new_user_id: { let n = len(r); r.bytes(n) }, new_salt: { let n = len(r); r.bytes(n) } },
        7 => Body::PurgeRoots { before: r.next() },
        8 => Body::ReportIncident { hash: { let n = len(r); r.bytes(n) } },
        _ => Body::ListRoots,
    }
}

#[test]
fn random_requests_never_panic_the_node() {
    let mut s = NodeService::new(NODE);
    let reset = |s: &mut NodeService| {
        s.users.clear();
        s.revoked_users.clear();
        s.users.insert(pk(&USER), UserAccount { salt: SALT.to_vec(), quota_bytes: 1 << 24, used_bytes: 0, root: [0; 32] });
    };
    reset(&mut s);
    let mut r = Rng(0xfeed_face_1234_5678);
    for i in 0..500u64 {
        if i % 50 == 0 {
            reset(&mut s);
        }
        let req = Request { credential: Some(credential()), body: body(&mut r) };
        // Directement, puis après un aller-retour altéré sur le réseau.
        let _ = s.handle(b"c", None, b"n", req.clone(), 1_000_000 + i);
        let mut wire = encode_request(&req);
        if !wire.is_empty() {
            let j = r.below(wire.len());
            wire[j] = r.next() as u8;
        }
        if let Ok(req) = decode_request(&wire) {
            let _ = s.handle(b"c", None, b"n", req, 1_000_000 + i);
        }
    }
}
