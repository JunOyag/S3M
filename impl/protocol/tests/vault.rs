//! Coffre local (`deploiement.packaging#coffre-local`) : phrase de passe,
//! réécriture, retour en clair. Le magasin du système n'est pas exercé ici
//! (il écrirait dans celui du développeur).
#![cfg(feature = "vault")]

use s3m_protocol::vault::*;

#[test]
fn a_passphrase_vault_locks_unlocks_rewrites_and_returns_to_plain() {
    let dir = std::env::temp_dir().join(format!("s3m-vault-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let seed = dir.join("node.seed");
    std::fs::write(&seed, "abandon ability able\n").unwrap();
    assert_eq!(storage(&seed), Storage::Plain);
    assert_eq!(read(&seed).unwrap().trim(), "abandon ability able");
    assert!(protect_passphrase(&seed, "abandon ability able", "court", true).is_err());
    protect_passphrase(&seed, "abandon ability able", "phrase de passe", true).unwrap();
    assert_eq!(storage(&seed), Storage::Passphrase);
    assert!(!seed.exists(), "clair supprimé");
    let k = unlock_key(&seed).expect("clé de déverrouillage");
    // Déverrouillé dans ce processus (clé gardée) : lecture et réécriture.
    assert_eq!(read(&seed).unwrap(), "abandon ability able");
    write(&seed, "zoo zoo wrong").unwrap();
    assert!(matches!(unlock(&seed, "mauvaise phrase"), Err(VaultError::BadPassphrase)));
    assert_eq!(unlock(&seed, "phrase de passe").unwrap(), "zoo zoo wrong");
    // Changement de phrase de passe : même clé de déverrouillage.
    protect_passphrase(&seed, "zoo zoo wrong", "autre phrase", true).unwrap();
    assert_eq!(unlock_key(&seed), Some(k));
    to_plain(&seed, "zoo zoo wrong").unwrap();
    assert_eq!(storage(&seed), Storage::Plain);
    assert_eq!(read(&seed).unwrap().trim(), "zoo zoo wrong");
    remove(&seed);
    assert_eq!(storage(&seed), Storage::Missing);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Magasin du système réel (écrit puis supprime une entrée) : lancé à la
/// main, `cargo test --features vault -- --ignored`.
#[test]
#[ignore]
fn the_system_store_keeps_the_phrase() {
    let dir = std::env::temp_dir().join(format!("s3m-vault-sys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let seed = dir.join("user.seed");
    std::fs::write(&seed, "abandon ability able\n").unwrap();
    assert_eq!(auto_protect(&seed), Storage::System);
    assert!(!seed.exists());
    assert_eq!(read(&seed).unwrap().trim(), "abandon ability able");
    write(&seed, "zoo zoo wrong").unwrap();
    assert_eq!(read(&seed).unwrap(), "zoo zoo wrong");
    remove(&seed);
    assert!(read(&seed).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
