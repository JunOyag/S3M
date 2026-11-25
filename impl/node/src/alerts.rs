//! Alertes critiques hors tableau de bord (`deploiement.packaging#alertes`) :
//! fenêtre sur la machine du Nœud (Windows), courriel (SMTP) et appel HTTP
//! (webhook). Chaque alerte est envoyée à son apparition, et de nouveau si
//! elle disparaît puis revient.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Canaux d'alerte (configuration du Nœud).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Fenêtre d'alerte sur la machine du Nœud (Windows).
    #[serde(default = "yes")]
    pub popup: bool,
    /// URL appelée en POST (JSON) à chaque alerte.
    #[serde(default)]
    pub webhook: Option<String>,
    /// Serveur SMTP `hôte:port` (STARTTLS sur 587, TLS sur 465).
    #[serde(default)]
    pub smtp_server: Option<String>,
    #[serde(default)]
    pub smtp_user: Option<String>,
    #[serde(default)]
    pub smtp_password: Option<String>,
    /// Destinataire(s), séparés par des virgules.
    #[serde(default)]
    pub email_to: Option<String>,
    /// Expéditeur ; par défaut l'utilisateur SMTP.
    #[serde(default)]
    pub email_from: Option<String>,
}

fn yes() -> bool {
    true
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            popup: true,
            webhook: None,
            smtp_server: None,
            smtp_user: None,
            smtp_password: None,
            email_to: None,
            email_from: None,
        }
    }
}

/// Alerte : `(clé stable, titre, texte)`.
pub type Alert = (String, String, String);

/// Alertes apparues depuis le dernier appel ; `sent` garde les clés en
/// cours (une alerte disparue puis revenue est renvoyée).
pub fn new_alerts(current: &[Alert], sent: &mut BTreeMap<String, u64>, now: u64) -> Vec<Alert> {
    sent.retain(|k, _| current.iter().any(|(c, _, _)| c == k));
    let mut out = Vec::new();
    for a in current {
        if !sent.contains_key(&a.0) {
            sent.insert(a.0.clone(), now);
            out.push(a.clone());
        }
    }
    out
}

/// Envoie une alerte sur tous les canaux configurés ; rend les erreurs.
pub fn dispatch(cfg: &AlertConfig, node: &str, title: &str, text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(url) = cfg.webhook.as_deref().filter(|u| !u.trim().is_empty()) {
        let body = json!({ "nœud": node, "alerte": title, "détail": text });
        if let Err(e) = ureq::post(url.trim())
            .timeout(std::time::Duration::from_secs(10))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            errors.push(format!("webhook : {e}"));
        }
    }
    if let (Some(server), Some(to)) = (
        cfg.smtp_server.as_deref().filter(|s| !s.trim().is_empty()),
        cfg.email_to.as_deref().filter(|s| !s.trim().is_empty()),
    ) {
        if let Err(e) = send_mail(cfg, server, to, &format!("[S3m] {node} : {title}"), text) {
            errors.push(format!("courriel : {e}"));
        }
    }
    if cfg.popup {
        popup(&format!("S3m — {node}"), &format!("{title}\n\n{text}"));
    }
    errors
}

fn send_mail(cfg: &AlertConfig, server: &str, to: &str, subject: &str, text: &str) -> Result<(), String> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};
    let (host, port) = match server.trim().rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "port SMTP invalide")?),
        None => (server.trim(), 587),
    };
    let from = cfg
        .email_from
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cfg.smtp_user.clone())
        .ok_or("expéditeur manquant")?;
    let mut m = Message::builder()
        .from(from.trim().parse().map_err(|e| format!("expéditeur : {e}"))?)
        .subject(subject);
    for t in to.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        m = m.to(t.parse().map_err(|e| format!("destinataire {t} : {e}"))?);
    }
    let email = m.body(text.to_string()).map_err(|e| e.to_string())?;
    let builder = if port == 465 {
        SmtpTransport::relay(host)
    } else {
        SmtpTransport::starttls_relay(host)
    }
    .map_err(|e| e.to_string())?
    .port(port)
    .timeout(Some(std::time::Duration::from_secs(20)));
    let builder = match (&cfg.smtp_user, &cfg.smtp_password) {
        (Some(u), Some(p)) if !u.is_empty() => builder.credentials(Credentials::new(u.clone(), p.clone())),
        _ => builder,
    };
    builder.build().send(&email).map(|_| ()).map_err(|e| e.to_string())
}

/// Fenêtre d'alerte non bloquante sur le bureau (Windows).
#[cfg(windows)]
fn popup(title: &str, text: &str) {
    let (title, text) = (title.to_string(), text.to_string());
    std::thread::spawn(move || {
        use windows::core::HSTRING;
        use windows::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
        };
        unsafe {
            MessageBoxW(
                None,
                &HSTRING::from(text),
                &HSTRING::from(title),
                MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND,
            );
        }
    });
}

#[cfg(not(windows))]
fn popup(title: &str, text: &str) {
    eprintln!("{title} : {text}");
}
