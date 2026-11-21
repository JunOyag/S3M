//! Pseudos et empreintes — id `deploiement.pseudos`, partie commune, sans
//! I/O. Réf. spec : docs/07-deploiement/pseudos.md.

use s3m_core::symmetric_suite::{canonical_encode, hash_sha256};

/// Taille maximale d'un nom (octets UTF-8).
pub const MAX_NAME_BYTES: usize = 64;
const LABEL: &str = "s3m/fingerprint/v1";
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Empreinte courte d'une clé publique : 60 bits en base32, `XXXX-XXXX-XXXX`.
pub fn fingerprint(key: &[u8]) -> String {
    let mut m = canonical_encode(&[LABEL.as_bytes()]);
    m.extend_from_slice(key);
    let h = hash_sha256(&m);
    let bits = u64::from_be_bytes(h[..8].try_into().expect("8 o")) >> 4;
    let mut out = String::with_capacity(14);
    for i in 0..12 {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        let v = (bits >> (55 - 5 * i)) & 31;
        out.push(ALPHABET[v as usize] as char);
    }
    out
}

/// Nom nettoyé : caractères de contrôle retirés, espaces de bord ôtés,
/// tronqué à [`MAX_NAME_BYTES`] sur une frontière de caractère.
pub fn sanitize(name: &str) -> String {
    let clean: String = name.chars().filter(|c| !c.is_control()).collect();
    let t = clean.trim();
    let mut end = t.len().min(MAX_NAME_BYTES);
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    t[..end].trim_end().to_string()
}

/// Affichage `nom · empreinte`, ou l'empreinte seule sans nom. Le premier
/// nom non vide de `names` l'emporte (nom local d'abord).
pub fn display(names: &[Option<&str>], key: &[u8]) -> String {
    let fp = fingerprint(key);
    match names
        .iter()
        .flatten()
        .map(|n| sanitize(n))
        .find(|n| !n.is_empty())
    {
        Some(n) => format!("{n} · {fp}"),
        None => fp,
    }
}
