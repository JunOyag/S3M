//! Serveur de l'API locale du dashboard — id `deploiement.packaging`.
//! Réf. spec : docs/07-deploiement/packaging.md § API locale. Les règles de
//! protection sont celles de `p2p_storage_protocol::local_api`.
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
use p2p_storage_protocol::local_api::{ApiRejection, LocalApiGuard};
use serde_json::Value;

/// État courant, sérialisé pour le dashboard.
pub type StatusFn = Arc<dyn Fn() -> Value + Send + Sync>;
/// Action du dashboard : `(nom, paramètres) → résultat`.
pub type ActionFn = Arc<dyn Fn(&str, Value) -> Result<Value, String> + Send + Sync>;

/// Fichier statique : `(chemin, type MIME, contenu)`.
pub type Asset = (&'static str, &'static str, &'static str);

#[derive(Clone)]
struct AppState {
    guard: LocalApiGuard,
    status: StatusFn,
    action: ActionFn,
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
                    "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:*",
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
    match (st.action)(&name, body) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
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

/// Lie `127.0.0.1:<port>` (0 : port libre), tire un jeton de 256 bits et
/// sert le dashboard. Rend l'URL d'ouverture (jeton dans le fragment).
pub async fn serve(
    port: u16,
    status_fn: StatusFn,
    action_fn: ActionFn,
    assets: &'static [Asset],
) -> std::io::Result<String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).map_err(std::io::Error::other)?;
    let guard = LocalApiGuard::new(token, listener.local_addr()?).map_err(std::io::Error::other)?;
    let url = guard.dashboard_url();
    let st = AppState {
        guard,
        status: status_fn,
        action: action_fn,
        assets,
    };
    let app = Router::new()
        .route("/", get(asset))
        .route("/api/status", get(status))
        .route("/api/action/:name", post(action))
        .route("/api/ws", get(ws))
        .route("/:file", get(asset))
        .with_state(st);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(url)
}
