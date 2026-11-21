//! Serveur de l'API locale du dashboard — id `deploiement.packaging`.
//! (Copie de `impl/node/src/local_http.rs` : les deux binaires sont
//! indépendants ; toute modification s'applique aux deux.)
//! Réf. spec : docs/07-deploiement/packaging.md § API locale. Les règles de
//! protection sont celles de `s3m_protocol::local_api`.
//!
//! Routes : fichiers statiques du dashboard, `GET /api/status`,
//! `POST /api/action/<nom>` (JSON), `GET /api/ws` (état poussé toutes les
//! 5 s après le jeton du premier message).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use s3m_protocol::local_api::{ApiRejection, LocalApiGuard};
use serde_json::Value;

/// État courant, sérialisé pour le dashboard.
pub type StatusFn = Arc<dyn Fn() -> Value + Send + Sync>;
/// Action du dashboard : `(nom, paramètres) → résultat`.
pub type ActionFn = Arc<dyn Fn(&str, Value) -> Result<Value, String> + Send + Sync>;

/// Fichier statique : `(chemin, type MIME, contenu)`.
pub type Asset = (&'static str, &'static str, &'static [u8]);

#[derive(Clone)]
struct AppState {
    guard: LocalApiGuard,
    status: StatusFn,
    action: ActionFn,
    map: Option<StatusFn>,
    assets: &'static [Asset],
}

fn hdr(h: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn reject(e: ApiRejection) -> Response {
    (StatusCode::FORBIDDEN, e.to_string()).into_response()
}

#[allow(clippy::result_large_err)]
fn check(st: &AppState, h: &HeaderMap) -> Result<(), Response> {
    st.guard
        .check_http(
            hdr(h, header::ORIGIN),
            hdr(h, header::HOST),
            hdr(h, header::AUTHORIZATION),
        )
        .map_err(reject)
}

async fn asset(State(st): State<AppState>, h: HeaderMap, path: Option<Path<String>>) -> Response {
    // Les fichiers statiques ne portent aucun secret : seuls Origin/Host
    // sont contrôlés (le jeton arrive par le fragment d'URL).
    if let Err(e) = st
        .guard
        .check_ws_handshake(hdr(&h, header::ORIGIN), hdr(&h, header::HOST))
    {
        return reject(e);
    }
    let want = path.map(|p| p.0).unwrap_or_else(|| "index.html".into());
    match st.assets.iter().find(|(p, _, _)| *p == want) {
        Some((_, mime, body)) => (
            [
                (header::CONTENT_TYPE, *mime),
                (header::CACHE_CONTROL, "no-store"),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:*",
                ),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            *body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn status(State(st): State<AppState>, h: HeaderMap) -> Response {
    if let Err(r) = check(&st, &h) {
        return r;
    }
    Json((st.status)()).into_response()
}

async fn action(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check(&st, &h) {
        return r;
    }
    // Fil bloquant : une action peut attendre une réponse du réseau.
    let f = st.action.clone();
    match tokio::task::spawn_blocking(move || f(&name, body)).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, e).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn ws(State(st): State<AppState>, h: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    if let Err(e) = st
        .guard
        .check_ws_handshake(hdr(&h, header::ORIGIN), hdr(&h, header::HOST))
    {
        return reject(e);
    }
    upgrade.on_upgrade(move |mut socket| async move {
        let Some(Ok(Message::Text(token))) = socket.recv().await else {
            return;
        };
        if st.guard.check_ws_first_message(&token).is_err() {
            let _ = socket.close().await;
            return;
        }
        loop {
            let msg = Message::Text((st.status)().to_string());
            if socket.send(msg).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
}

/// Lie `127.0.0.1:<port>` (0 : port libre), tire un jeton de 256 bits
/// (conservé dans `keep` s'il est donné) et sert le dashboard. Rend l'URL
/// d'ouverture (jeton dans le fragment).
pub async fn serve(
    port: u16,
    status_fn: StatusFn,
    action_fn: ActionFn,
    assets: &'static [Asset],
    keep: Option<&std::path::Path>,
) -> std::io::Result<String> {
    serve_with_map(port, status_fn, action_fn, None, assets, keep).await
}

async fn map(State(st): State<AppState>, h: HeaderMap) -> Response {
    if let Err(r) = check(&st, &h) {
        return r;
    }
    let Some(f) = st.map.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Fil bloquant : la carte peut venir du réseau (Nœud administré à distance).
    match tokio::task::spawn_blocking(move || f()).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Port et jeton du dashboard conservés dans `<dir>/dashboard.json`, pour
/// que l'adresse reste la même d'un démarrage à l'autre (favoris). Le
/// port configuré l'emporte ; à défaut, le port conservé, ou un port libre
/// s'il est pris.
async fn bind_kept(
    port: u16,
    keep: Option<&std::path::Path>,
) -> std::io::Result<(tokio::net::TcpListener, [u8; 32])> {
    let file = keep.map(|d| d.join("dashboard.json"));
    let saved: Option<Value> = file
        .as_ref()
        .and_then(|f| std::fs::read(f).ok())
        .and_then(|b| serde_json::from_slice(&b).ok());
    let saved_port = saved
        .as_ref()
        .and_then(|v| v.get("port")?.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(0);
    let want = if port != 0 { port } else { saved_port };
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", want)).await {
        Ok(l) => l,
        Err(_) if port == 0 && want != 0 => tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?,
        Err(e) => return Err(e),
    };
    let kept: Option<[u8; 32]> = saved
        .as_ref()
        .and_then(|v| v.get("token")?.as_str().map(str::to_owned))
        .and_then(|t| hex::decode(t).ok()?.try_into().ok());
    let token = match kept.filter(|_| file.is_some()) {
        Some(t) => t,
        None => {
            let mut t = [0u8; 32];
            getrandom::getrandom(&mut t).map_err(std::io::Error::other)?;
            t
        }
    };
    if let Some(f) = &file {
        let v = serde_json::json!({ "port": listener.local_addr()?.port(), "token": hex::encode(token) });
        let tmp = f.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&v).expect("sérialisable"))?;
        std::fs::rename(&tmp, f)?;
    }
    Ok((listener, token))
}

/// Comme [`serve`], avec la carte du monde (`GET /api/map`).
pub async fn serve_with_map(
    port: u16,
    status_fn: StatusFn,
    action_fn: ActionFn,
    map_fn: Option<StatusFn>,
    assets: &'static [Asset],
    keep: Option<&std::path::Path>,
) -> std::io::Result<String> {
    let (listener, token) = bind_kept(port, keep).await?;
    let guard = LocalApiGuard::new(token, listener.local_addr()?).map_err(std::io::Error::other)?;
    let url = guard.dashboard_url();
    let st = AppState {
        guard,
        status: status_fn,
        action: action_fn,
        map: map_fn,
        assets,
    };
    let app = Router::new()
        .route("/", get(asset))
        .route("/api/status", get(status))
        .route("/api/action/:name", post(action))
        .route("/api/map", get(map))
        .route("/api/ws", get(ws))
        .route("/:file", get(asset))
        .with_state(st);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(url)
}
