//! Modification de la configuration depuis le dashboard Nœud —
//! `deploiement.packaging` § Dashboard Nœud.
//!
//! Le fichier `node.json` est relu tel quel (chemins relatifs préservés),
//! seuls les champs édités sont modifiés, la configuration complète est
//! validée puis écrite de façon atomique. Les réglages marqués « à chaud »
//! s'appliquent immédiatement ; les autres au prochain redémarrage.
//! Identité, répertoires, volumes et paramètres k / coef ne sont pas
//! modifiables ici (risque de perte de données).

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::daemon::Config;

/// Type d'un champ éditable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Number,
    Decimal,
    Bool,
    /// Liste de chaînes, saisie séparée par des virgules.
    List,
    /// Durée en secondes (saisie « 10s », « 10min », « 2h », « 7d »).
    Seconds,
    /// Durée en jours (même saisie).
    Days,
    /// Taille en octets, présentée et saisie en Mio.
    Mebibytes,
}

/// Durée saisie (« 10s », « 10min », « 2h », « 7d » ou « 7j », nombre seul
/// dans l'unité `unit_s`) en secondes (`deploiement.packaging#durees`).
pub fn parse_duration(s: &str, unit_s: u64) -> Option<u64> {
    let t = s.trim().to_lowercase().replace(',', ".");
    let split = t.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(t.len());
    let (n, u) = t.split_at(split);
    let n: f64 = n.trim().parse().ok()?;
    let mult = match u.trim() {
        "" => unit_s,
        "s" | "sec" => 1,
        "min" | "m" => 60,
        "h" => 3_600,
        "d" | "j" => 86_400,
        _ => return None,
    };
    (n >= 0.0).then(|| (n * mult as f64).round() as u64)
}

/// Champ éditable : `(groupe, libellé, chemin JSON, type, à chaud, aide)`.
pub struct Field {
    pub group: &'static str,
    pub label: &'static str,
    pub path: &'static str,
    pub kind: Kind,
    pub live: bool,
    pub help: &'static str,
}

const fn f(
    group: &'static str,
    label: &'static str,
    path: &'static str,
    kind: Kind,
    live: bool,
    help: &'static str,
) -> Field {
    Field {
        group,
        label,
        path,
        kind,
        live,
        help,
    }
}

/// Champs éditables, par groupe.
pub const FIELDS: &[Field] = &[
    f(
        "Réseau",
        "adresse d'écoute (blocs et annuaire)",
        "listen",
        Kind::Text,
        false,
        "Échange de blocs et annuaire, TCP et QUIC sur le même port. Par défaut /ip4/0.0.0.0/tcp/4001 ; donnez un port différent à chaque Nœud d'une même machine.",
    ),
    f(
        "Réseau",
        "adresse IP publique",
        "public_ip",
        Kind::Text,
        false,
        "Adresse joignable depuis Internet ; vide : détection automatique (UPnP, AutoNAT).",
    ),
    f(
        "Réseau",
        "port public",
        "public_port",
        Kind::Number,
        false,
        "Port public de l'échange de blocs ; vide : port d'écoute.",
    ),
    f(
        "Réseau",
        "nœuds d'amorçage",
        "bootstrap",
        Kind::List,
        false,
        "Adresses /ip4/…/tcp/…/p2p/…, séparées par des virgules.",
    ),
    f(
        "Réseau",
        "ouverture de port UPnP",
        "upnp",
        Kind::Bool,
        false,
        "Demande à la box d'ouvrir le port du Nœud.",
    ),
    f(
        "Réseau",
        "annonce sur le réseau local",
        "mdns",
        Kind::Bool,
        false,
        "Permet aux Connecteurs du réseau local de trouver ce Nœud.",
    ),
    f(
        "Réseau",
        "port du tableau de bord",
        "api_port",
        Kind::Number,
        false,
        "Port local du tableau de bord (127.0.0.1 uniquement).",
    ),
    f(
        "Relais",
        "rendre le service de relais",
        "relay_server",
        Kind::Bool,
        false,
        "Relaie les Nœuds derrière un NAT (limites ci-dessous).",
    ),
    f(
        "Relais",
        "réservations au plus",
        "relay_limits.max_reservations",
        Kind::Number,
        false,
        "",
    ),
    f(
        "Relais",
        "durée maximale d'un circuit",
        "relay_limits.max_circuit_duration_s",
        Kind::Seconds,
        false,
        "",
    ),
    f(
        "Relais",
        "volume maximal d'un circuit (octets)",
        "relay_limits.max_circuit_bytes",
        Kind::Number,
        false,
        "",
    ),
    f(
        "Relais",
        "toujours réserver un relais",
        "force_relay",
        Kind::Bool,
        false,
        "Même sans NAT détecté (dépannage).",
    ),
    f(
        "Partenaires",
        "accepter les propositions",
        "partner_policy.accept",
        Kind::Bool,
        true,
        "",
    ),
    f(
        "Partenaires",
        "partenaires au plus",
        "partner_policy.max_partners",
        Kind::Number,
        true,
        "",
    ),
    f(
        "Partenaires",
        "espace offert aux partenaires (Mio)",
        "partner_policy.offer_bytes",
        Kind::Mebibytes,
        true,
        "Espace réservé aux fragments des partenaires (10 Gio par défaut), réparti à parts égales entre le nombre maximal de partenaires : c'est ce que chacun peut déposer ici, et réciproquement.",
    ),
    f(
        "Partenaires",
        "confiance initiale (fragments)",
        "partner_policy.trust_initial_blocks",
        Kind::Number,
        true,
        "Quota de départ d'un nouveau partenaire (64 Kio par fragment ; 256 = 16 Mio), doublé à chaque période sans manquement.",
    ),
    f(
        "Partenaires",
        "période de confiance",
        "partner_policy.trust_period_s",
        Kind::Seconds,
        true,
        "Durée après laquelle la confiance envers un partenaire double s'il a tenu ses promesses (7 jours par défaut).",
    ),
    f(
        "Partenaires",
        "remplissage de l'espace promis",
        "partner_policy.filler",
        Kind::Bool,
        true,
        "Vérifie que les partenaires disposent bien de l'espace promis en le remplissant de données de contrôle, libérées dès qu'il faut la place. Coûte de l'espace disque réel chez eux (et chez vous pour eux).",
    ),
    f(
        "Partenaires",
        "partenaires par sous-réseau (0 : sans limite)",
        "partner_policy.subnet_limit",
        Kind::Number,
        true,
        "Au plus ce nombre de partenaires par sous-réseau /24 (IPv4) ou /48 (IPv6) : un tricheur seul ne peut pas occuper toutes les places. 0 pour des essais sur une seule machine.",
    ),
    f(
        "Partenaires",
        "recherche automatique",
        "partnering.enabled",
        Kind::Bool,
        false,
        "",
    ),
    f(
        "Partenaires",
        "partenaires visés (0 : auto)",
        "partnering.target_partners",
        Kind::Number,
        false,
        "",
    ),
    f(
        "Partenaires",
        "seuil de placement",
        "partnering.placement_threshold",
        Kind::Decimal,
        false,
        "Score minimal (0 à 1) pour recevoir de nouveaux fragments.",
    ),
    f(
        "Partenaires",
        "seuil de retrait",
        "partnering.exit_threshold",
        Kind::Decimal,
        false,
        "Sous ce score pendant la durée ci-dessous : retrait.",
    ),
    f(
        "Partenaires",
        "durée avant retrait",
        "partnering.retire_after_s",
        Kind::Seconds,
        false,
        "",
    ),
    f(
        "Contrôles",
        "challenges par cycle",
        "upkeep.challenges_per_cycle",
        Kind::Number,
        false,
        "",
    ),
    f(
        "Contrôles",
        "période d'analyse",
        "upkeep.analysis_period_s",
        Kind::Seconds,
        false,
        "",
    ),
    f(
        "Contrôles",
        "fenêtre de disponibilité",
        "upkeep.available_window_s",
        Kind::Seconds,
        false,
        "",
    ),
    f(
        "Contrôles",
        "période de vérification locale",
        "upkeep.scrub_period_s",
        Kind::Seconds,
        false,
        "",
    ),
    f(
        "Contrôles",
        "délai de padding",
        "dispersal.idle_timeout_s",
        Kind::Seconds,
        false,
        "Attente avant de compléter un groupe incomplet.",
    ),
    f(
        "Contrôles",
        "partenaires minimum par stripe (essais)",
        "dispersal.min_confirmations",
        Kind::Number,
        false,
        "0 = 6 (k + 2, valeur normale). Abaisser jusqu'à 1 seulement pour des essais sur un réseau local de quelques Nœuds : vos fichiers ne supportent alors plus la perte de partenaires.",
    ),
    f(
        "Contrôles",
        "délai de grâce avant purge",
        "dispersal.grace_s",
        Kind::Seconds,
        false,
        "",
    ),
    f(
        "Administration à distance",
        "administration à distance",
        "remote_admin",
        Kind::Bool,
        false,
        "Depuis un Connecteur, avec le code 2FA.",
    ),
    f(
        "Administration à distance",
        "adresse d'écoute",
        "admin_listen",
        Kind::Text,
        false,
        "Par défaut /ip4/0.0.0.0/tcp/4003 ; donnez un port différent à chaque Nœud d'une même machine.",
    ),
    f(
        "Utilisateurs",
        "conservation des versions",
        "history_days",
        Kind::Days,
        true,
        "Versions passées des fichiers gardées pour les retours arrière (ransomware, suppression accidentelle), comptées dans le quota de chaque utilisateur ; 0 : aucune.",
    ),
    f(
        "Alertes",
        "fenêtre d'alerte sur cette machine",
        "alerts.popup",
        Kind::Bool,
        true,
        "Disque défaillant, maintenance, horloge douteuse : une fenêtre s'ouvre sur le bureau de la machine du Nœud (Windows).",
    ),
    f(
        "Alertes",
        "webhook (URL appelée en POST)",
        "alerts.webhook",
        Kind::Text,
        true,
        "Reçoit {\"nœud\", \"alerte\", \"détail\"} en JSON (supervision, messagerie d'équipe) ; vide : aucun.",
    ),
    f(
        "Alertes",
        "serveur SMTP (hôte:port)",
        "alerts.smtp_server",
        Kind::Text,
        true,
        "Envoi des alertes par courriel : STARTTLS sur 587, TLS sur 465 ; vide : aucun courriel.",
    ),
    f(
        "Alertes",
        "utilisateur SMTP",
        "alerts.smtp_user",
        Kind::Text,
        true,
        "Compte d'envoi (souvent l'adresse elle-même).",
    ),
    f(
        "Alertes",
        "mot de passe SMTP",
        "alerts.smtp_password",
        Kind::Text,
        true,
        "Gardé en clair dans node.json : préférez un mot de passe d'application dédié.",
    ),
    f(
        "Alertes",
        "destinataires des courriels",
        "alerts.email_to",
        Kind::Text,
        true,
        "Adresses séparées par des virgules.",
    ),
    f(
        "Vie privée",
        "enregistrer l'adresse des utilisateurs",
        "record_user_ips",
        Kind::Bool,
        true,
        "Pour la carte du tableau de bord.",
    ),
];

fn get<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |acc, k| acc.get(k))
}

fn set(v: &mut Value, path: &str, val: Value) {
    let mut cur = v;
    let parts: Vec<&str> = path.split('.').collect();
    for (i, k) in parts.iter().enumerate() {
        if !cur.is_object() {
            *cur = Value::Object(Map::new());
        }
        let obj = cur.as_object_mut().unwrap();
        if i + 1 == parts.len() {
            obj.insert(k.to_string(), val);
            return;
        }
        cur = obj
            .entry(k.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}

/// Valeur de formulaire d'un champ.
fn display(v: Option<&Value>, kind: Kind) -> Value {
    match (v, kind) {
        (None | Some(Value::Null), Kind::Bool) => json!(false),
        (None | Some(Value::Null), _) => json!(""),
        (Some(Value::Array(a)), Kind::List) => {
            json!(a
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", "))
        }
        (Some(x), Kind::Mebibytes) => x
            .as_u64()
            .map(|b| json!((b as f64 / 1_048_576.0 * 100.0).round() / 100.0))
            .unwrap_or_else(|| x.clone()),
        (Some(x), _) => x.clone(),
    }
}

fn parse(field: &Field, raw: &Value) -> Result<Value, String> {
    let s = match raw {
        Value::String(s) => s.trim().to_string(),
        Value::Bool(b) => {
            return if field.kind == Kind::Bool {
                Ok(json!(*b))
            } else {
                Err(format!("« {} » : valeur invalide", field.label))
            }
        }
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let bad = || format!("« {} » : valeur invalide ({s})", field.label);
    Ok(match field.kind {
        Kind::Bool => json!(matches!(
            s.to_lowercase().as_str(),
            "true" | "oui" | "1" | "on"
        )),
        Kind::Text if s.is_empty() => Value::Null,
        Kind::Text => json!(s),
        Kind::Number if s.is_empty() => Value::Null,
        Kind::Number => json!(s.parse::<u64>().map_err(|_| bad())?),
        Kind::Seconds if s.is_empty() => Value::Null,
        Kind::Seconds => json!(parse_duration(&s, 1).ok_or_else(bad)?),
        Kind::Days if s.is_empty() => Value::Null,
        Kind::Days => json!(parse_duration(&s, 86_400).ok_or_else(bad)? / 86_400),
        Kind::Mebibytes if s.is_empty() => Value::Null,
        Kind::Mebibytes => {
            let x: f64 = s.replace(',', ".").parse().map_err(|_| bad())?;
            json!((x * 1_048_576.0).round() as u64)
        }
        Kind::Decimal => {
            let x: f64 = s.replace(',', ".").parse().map_err(|_| bad())?;
            json!(x)
        }
        Kind::List => json!(s
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()),
    })
}

/// Formulaires du dashboard (un par groupe), pré-remplis depuis le fichier,
/// et liste des réglages enregistrés mais pas encore actifs.
pub fn forms(file: &Value, running: &Value) -> (Vec<Value>, Vec<String>) {
    let mut groups: Vec<&str> = FIELDS.iter().map(|f| f.group).collect();
    groups.dedup();
    let forms = groups
        .iter()
        .map(|g| {
            let fields: Vec<&Field> = FIELDS.iter().filter(|f| f.group == *g).collect();
            let mut valeurs = Map::new();
            let mut types = Map::new();
            let mut aide = Map::new();
            let mut unites = Map::new();
            for f in &fields {
                valeurs.insert(f.label.into(), display(get(file, f.path), f.kind));
                match f.kind {
                    Kind::Bool => {
                        types.insert(f.label.into(), json!("bool"));
                    }
                    Kind::Number | Kind::Mebibytes => {
                        types.insert(f.label.into(), json!("number"));
                    }
                    Kind::Seconds => {
                        types.insert(f.label.into(), json!("durée"));
                        unites.insert(f.label.into(), json!("s"));
                    }
                    Kind::Days => {
                        types.insert(f.label.into(), json!("durée"));
                        unites.insert(f.label.into(), json!("j"));
                    }
                    _ => {}
                }
                let h = format!(
                    "{}{}",
                    f.help,
                    if f.live { " (appliqué immédiatement)" } else { " (au prochain redémarrage)" }
                );
                aide.insert(f.label.into(), json!(h.trim()));
            }
            json!({
                "nom": "set_config", "titre": format!("Configuration — {g}"), "libellé": "Enregistrer",
                "champs": fields.iter().map(|f| f.label).collect::<Vec<_>>(),
                "valeurs": valeurs, "types": types, "aide": aide, "unités": unites,
            })
        })
        .collect();
    let pending = FIELDS
        .iter()
        .filter(|f| !f.live)
        .filter(|f| display(get(file, f.path), f.kind) != display(get(running, f.path), f.kind))
        .map(|f| f.label.to_string())
        .collect();
    (forms, pending)
}

/// Résultat d'une modification.
pub struct Applied {
    pub config: Config,
    pub live: Vec<&'static str>,
    pub restart: Vec<&'static str>,
}

/// Applique au fichier `path` les champs reçus (clés = libellés).
pub fn apply(path: &Path, input: &Value) -> Result<Applied, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut file: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let current = serde_json::from_value::<Config>(file.clone())
        .ok()
        .and_then(|c| serde_json::to_value(c).ok())
        .unwrap_or(Value::Null);
    let (mut live, mut restart) = (Vec::new(), Vec::new());
    for field in FIELDS {
        let Some(v) = input.get(field.label) else {
            continue;
        };
        let new = parse(field, v)?;
        if field.path == "listen" || field.path == "admin_listen" {
            check_listen(field.label, &new)?;
        }
        let old = get(&current, field.path).or_else(|| get(&file, field.path));
        if old == Some(&new) || (new.is_null() && old.is_none_or(Value::is_null)) {
            continue;
        }
        set(&mut file, field.path, new);
        // Adresse unique : les anciens ports séparés ne priment plus.
        if field.path == "listen" {
            if let Some(o) = file.as_object_mut() {
                o.remove("dht_listen");
                o.remove("blocks_listen");
            }
        }
        if field.live {
            live.push(field.label)
        } else {
            restart.push(field.label)
        }
    }
    // Validation de la configuration complète avant écriture.
    let config: Config = serde_json::from_value(file.clone())
        .map_err(|e| format!("configuration invalide : {e}"))?;
    if !live.is_empty() || !restart.is_empty() {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_string_pretty(&file).expect("sérialisable"),
        )
        .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    }
    Ok(Applied {
        config,
        live,
        restart,
    })
}

/// Adresse d'écoute : multiaddr `/ip4/…/tcp/<port>` (ou `/ip6/…`).
fn check_listen(label: &str, v: &Value) -> Result<(), String> {
    let s = v.as_str().unwrap_or_default();
    let m: libp2p::Multiaddr = s
        .parse()
        .map_err(|_| format!("{label} : adresse attendue, par exemple /ip4/0.0.0.0/tcp/4011"))?;
    let port = m.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Tcp(p) => Some(p),
        _ => None,
    });
    match port {
        Some(p) if p > 0 => Ok(()),
        _ => Err(format!(
            "{label} : port TCP attendu, par exemple /ip4/0.0.0.0/tcp/4011"
        )),
    }
}

/// Écrit une valeur de premier niveau dans le fichier (écriture atomique).
pub fn set_raw(path: &Path, key: &str, value: Value) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut file: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    set(&mut file, key, value);
    serde_json::from_value::<Config>(file.clone())
        .map_err(|e| format!("configuration invalide : {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(&file).expect("sérialisable"),
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Modifie le fichier brut par `f`, valide la configuration complète, puis
/// écrit de façon atomique.
pub fn edit_raw(path: &Path, f: impl FnOnce(&mut Value)) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut file: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    f(&mut file);
    serde_json::from_value::<Config>(file.clone())
        .map_err(|e| format!("configuration invalide : {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(&file).expect("sérialisable"),
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}
