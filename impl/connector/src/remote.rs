//! Dashboard d'un Nœud administré à distance — id `deploiement.appairage-admin`
//! § Canal. Servi sur `127.0.0.1` par le Connecteur (règles de l'API locale),
//! il relaie `status` et `action` par une session du canal d'administration.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::admin_client::RemoteSession;
use crate::local_http::{self, ActionFn, Asset, StatusFn};

const ASSETS: &[Asset] = &[
    (
        "logo.png",
        "image/png",
        include_bytes!("../dashboard/logo.png"),
    ),
    (
        "index.html",
        "text/html; charset=utf-8",
        include_bytes!("../dashboard/index.html"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../dashboard/app.js"),
    ),
];

fn decorate(mut v: Value, addr: &str) -> Value {
    let title = v
        .get("titre")
        .and_then(|t| t.as_str())
        .unwrap_or("S3m Nœud")
        .to_string();
    if let Some(o) = v.as_object_mut() {
        o.insert("titre".into(), json!(format!("{title} (à distance)")));
        o.remove("carte");
        o.insert(
            "connexion".into(),
            json!({ "Nœud": addr, "canal": "chiffré, authentifié" }),
        );
    }
    v
}

/// Sert le dashboard distant de `session` ; rend son URL.
pub async fn serve_remote(session: RemoteSession) -> Result<String, String> {
    let addr = session.addr.to_string();
    let first = session.status().await?;
    let cache = Arc::new(Mutex::new(decorate(first, &addr)));
    {
        let (cache, session, addr) = (cache.clone(), session.clone(), addr.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                match session.status().await {
                    Ok(v) => *cache.lock().unwrap() = decorate(v, &addr),
                    Err(e) => {
                        *cache.lock().unwrap() = json!({
                            "titre": "S3m Nœud (à distance) — connexion terminée",
                            "état": format!("{e}. Un Nœud qui vient d'être configuré redémarre avec son identité définitive : administrez-le ensuite depuis le tableau de bord de S3m avec le code 2FA."),
                        });
                        return;
                    }
                }
            }
        });
    }
    let st_fn: StatusFn = {
        let cache = cache.clone();
        Arc::new(move || cache.lock().unwrap().clone())
    };
    let act_fn: ActionFn = {
        let session = session.clone();
        Arc::new(move |name, body| {
            // Appel depuis un fil bloquant (local_http) : attente de la réponse.
            tokio::runtime::Handle::current().block_on(session.action(name, body))
        })
    };
    local_http::serve(0, st_fn, act_fn, ASSETS)
        .await
        .map_err(|e| e.to_string())
}
