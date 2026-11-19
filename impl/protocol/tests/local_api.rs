//! `deploiement.packaging` § API locale.

use p2p_storage_protocol::local_api::*;

const TOKEN: [u8; 32] = [0xAB; 32];

fn guard() -> LocalApiGuard {
    LocalApiGuard::new(TOKEN, "127.0.0.1:8765".parse().unwrap()).unwrap()
}

fn bearer() -> String {
    format!("Bearer {}", "ab".repeat(32))
}

#[test]
fn binding_must_be_loopback_ipv4() {
    for addr in ["0.0.0.0:8765", "192.168.1.2:8765", "[::1]:8765"] {
        assert!(matches!(
            LocalApiGuard::new(TOKEN, addr.parse().unwrap()),
            Err(ApiRejection::NotLoopback)
        ));
    }
}

/// Le jeton n'apparaît que dans le fragment de l'URL d'ouverture.
#[test]
fn token_is_handed_over_in_the_url_fragment() {
    let url = guard().dashboard_url();
    let (base, fragment) = url.split_once('#').unwrap();
    assert_eq!(base, "http://127.0.0.1:8765/");
    assert_eq!(fragment, format!("token={}", "ab".repeat(32)));
}

#[test]
fn http_requests_require_bearer_token_host_and_matching_origin() {
    let g = guard();
    let host = Some("127.0.0.1:8765");
    assert!(g.check_http(None, host, Some(&bearer())).is_ok());
    assert!(g
        .check_http(Some("http://127.0.0.1:8765"), host, Some(&bearer()))
        .is_ok());
    assert_eq!(g.check_http(None, host, None), Err(ApiRejection::BadToken));
    assert_eq!(
        g.check_http(None, host, Some("Bearer abab")),
        Err(ApiRejection::BadToken)
    );
    assert_eq!(
        g.check_http(Some("http://evil.example"), host, Some(&bearer())),
        Err(ApiRejection::BadOrigin)
    );
    // Rebond DNS : Host d'un autre nom résolu vers 127.0.0.1.
    assert_eq!(
        g.check_http(None, Some("evil.example:8765"), Some(&bearer())),
        Err(ApiRejection::BadHost)
    );
}

#[test]
fn websocket_checks_handshake_then_first_message_token() {
    let g = guard();
    assert!(g
        .check_ws_handshake(Some("http://127.0.0.1:8765"), Some("127.0.0.1:8765"))
        .is_ok());
    assert_eq!(
        g.check_ws_handshake(Some("http://evil.example"), Some("127.0.0.1:8765")),
        Err(ApiRejection::BadOrigin)
    );
    assert!(g.check_ws_first_message(&"ab".repeat(32)).is_ok());
    assert_eq!(
        g.check_ws_first_message("bonjour"),
        Err(ApiRejection::BadToken)
    );
}
