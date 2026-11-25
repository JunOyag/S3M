//! Recherche du Nœud de rattachement d'une identité reprise : saisie de
//! l'Utilisateur et points d'entrée de l'annuaire.

use s3m_connector::find_node::*;

const ID: [u8; 32] = [0x42; 32];

#[test]
fn an_identifier_a_peer_id_or_a_fingerprint_is_accepted() {
    assert_eq!(parse_node_ref(&hex::encode(ID)), Ok(NodeRef::Id(ID)));
    let key = libp2p::identity::ed25519::PublicKey::try_from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&ID).verifying_key().to_bytes(),
    )
    .unwrap();
    let peer = libp2p::PeerId::from(libp2p::identity::PublicKey::from(key.clone()));
    assert_eq!(
        parse_node_ref(&format!(" {peer} ")),
        Ok(NodeRef::Id(key.to_bytes()))
    );
    assert_eq!(
        parse_node_ref("zdxk-lttn-b343"),
        Ok(NodeRef::Fingerprint("ZDXKLTTNB343".into()))
    );
    assert!(parse_node_ref("  ").is_err());
}

#[test]
fn a_fingerprint_is_matched_among_known_nodes_only() {
    let fp = s3m_protocol::pseudo::fingerprint(&ID[..]);
    let other = [0x43; 32];
    assert_eq!(match_fingerprint(&fp.to_lowercase(), &[other, ID]), Some(ID));
    assert_eq!(match_fingerprint(&fp, &[other]), None);
}

#[test]
fn entry_points_come_from_the_lan_and_the_other_identities() {
    let dir = std::env::temp_dir().join(format!("p2p-find-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("identites").join("2").join("data")).unwrap();
    let a = "/ip4/192.168.1.2/tcp/4001/p2p/12D3KooWFne3deqBNmqP2oSD639YgsFhuJvLUusjgFkbqJWdPSVP";
    let b = "/ip4/192.168.1.3/tcp/4001";
    std::fs::write(
        dir.join("identites").join("2").join("data").join("dht_peers.json"),
        serde_json::to_vec(&[a]).unwrap(),
    )
    .unwrap();
    let got: Vec<String> = entry_points(&dir, &[b.to_string()])
        .iter()
        .map(|m| m.to_string())
        .collect();
    assert_eq!(got, vec![b.to_string(), a.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}
