//! Tests de `deploiement.pseudos` (partie commune).

use s3m_protocol::pseudo::*;

#[test]
fn fingerprint_is_12_base32_chars_in_three_groups_and_key_dependent() {
    let a = fingerprint(&[1; 32]);
    assert_eq!(a.len(), 14);
    assert_eq!(a.matches('-').count(), 2);
    assert!(a
        .chars()
        .all(|c| c == '-' || c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    assert_eq!(a, fingerprint(&[1; 32]));
    assert_ne!(a, fingerprint(&[2; 32]));
}

#[test]
fn names_are_cleaned_bounded_and_never_shown_without_fingerprint() {
    assert_eq!(sanitize("  Mai\u{7}son\n "), "Maison");
    let long = "é".repeat(40); // 80 o
    let s = sanitize(&long);
    assert!(s.len() <= MAX_NAME_BYTES && s.chars().all(|c| c == 'é'));
    let fp = fingerprint(&[1; 32]);
    assert_eq!(display(&[None, Some("  ")], &[1; 32]), fp);
    assert_eq!(
        display(&[Some(""), Some("Nœud de Paul")], &[1; 32]),
        format!("Nœud de Paul · {fp}")
    );
    assert_eq!(
        display(&[Some("Maison"), Some("Nœud de Paul")], &[1; 32]),
        format!("Maison · {fp}")
    );
}
