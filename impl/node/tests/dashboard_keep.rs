//! `deploiement.packaging` § API locale : adresse du dashboard stable
//! (favoris) — port et jeton conservés d'un démarrage à l'autre.

use std::sync::Arc;

use s3m_node::local_http::serve;

fn token_of(url: &str) -> String {
    url.split("#token=").nth(1).unwrap().to_string()
}

#[tokio::test]
async fn token_and_port_are_kept_across_restarts() {
    let dir = std::env::temp_dir().join(format!("s3m-keep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let st: s3m_node::local_http::StatusFn = Arc::new(|| serde_json::json!({}));
    let act: s3m_node::local_http::ActionFn = Arc::new(|_, _| Ok(serde_json::json!({})));
    let a = serve(0, st.clone(), act.clone(), None, &[], Some(&dir))
        .await
        .unwrap();
    // Port encore pris par le premier serveur : un autre port, même jeton.
    let b = serve(0, st.clone(), act.clone(), None, &[], Some(&dir))
        .await
        .unwrap();
    assert_eq!(token_of(&a), token_of(&b));
    assert_ne!(a, b);
    // Sans conservation : nouveau jeton à chaque démarrage.
    let c = serve(0, st, act, None, &[], None).await.unwrap();
    assert_ne!(token_of(&a), token_of(&c));
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("dashboard.json")).unwrap()).unwrap();
    assert_eq!(saved["token"].as_str().unwrap(), token_of(&b));
}
