//! Partages côté Connecteur : publication des pointeurs, retraits,
//! relecture des partages reçus, page « Partages » du tableau de bord
//! (`protocols.partage#connecteur`).

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::daemon::Shared;
use crate::drive::SHARED_DIR;
use crate::shares::{CachedPointer, Fetch, GivenShare, ReceivedShare, ReceivedTree, ShareStore};
use s3m_protocol::exchange::{Body, Credential, Request, Response};
use s3m_protocol::share::{
    open_share_entry, share_entry_envelope, sign_grant, ShareGrant, SharePointer, ShareToken,
};

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("CSPRNG du système");
    b
}

fn wait<F: std::future::Future>(rt: &tokio::runtime::Handle, f: F) -> F::Output {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| rt.block_on(f))
    } else {
        rt.block_on(f)
    }
}

fn save(sh: &Shared, store: &ShareStore) {
    let _ = store.save(&sh.config.data_dir);
}

/// Monte « Partagés avec moi » dans le lecteur : blocs lus chez le Nœud
/// du propriétaire avec son autorisation.
pub fn install_tree(sh: &Arc<Shared>) {
    let Some(drive) = sh.drive.clone() else {
        return;
    };
    let rt = tokio::runtime::Handle::current();
    let client = sh.share_client.clone();
    let fetch: Fetch = Arc::new(move |addrs, grant, sig, hash| {
        let client = client.as_ref()?;
        for a in addrs {
            let Ok(addr) = a.parse() else { continue };
            let req = Request {
                credential: Some(Credential::Share {
                    grant: grant.to_vec(),
                    signature: sig.to_vec(),
                }),
                body: Body::GetBlock {
                    hash: hash.to_vec(),
                },
            };
            if let Ok(Response::BlockData(d)) = wait(&rt, client.request(addr, req)) {
                return Some(d);
            }
        }
        None
    });
    drive.lock().unwrap().shared = Some(Arc::new(ReceivedTree::new(sh.shares.clone(), fetch)));
}

/// Un tour : publie les pointeurs dus, transmet les retraits, relit les
/// partages reçus.
pub async fn tick(sh: &Arc<Shared>) {
    let Some(dht) = sh.dht.get() else { return };
    let now = (sh.clock)();
    let given = sh.shares.lock().unwrap().given.clone();
    for (i, mut g) in given.into_iter().enumerate() {
        if g.revoke_done {
            continue;
        }
        let Some(token) = g.token(&sh.priv_user) else {
            continue;
        };
        if g.expires_at != 0 && now >= g.expires_at {
            g.revoked = true;
        }
        let element = match (g.revoked, sh.drive.clone()) {
            (false, Some(d)) => {
                let path = g.path.clone();
                tokio::task::spawn_blocking(move || d.lock().unwrap().shared_element(&path))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .flatten()
            }
            _ => None,
        };
        if element.is_none() && !g.revoked {
            // Élément supprimé de l'espace : le partage s'arrête.
            g.revoked = true;
        }
        if !g.publish_due(element.as_ref().map(|e| &e.first_block_hash), now) {
            continue;
        }
        let share_id = token.share_id();
        if g.revoked && sh.session.revoke_share(&share_id).await.is_err() {
            g.last_error = Some("retrait pas encore transmis au Nœud (injoignable ?)".into());
            sh.shares.lock().unwrap().given[i] = g;
            continue;
        }
        let grant = sign_grant(
            &sh.priv_user,
            &ShareGrant {
                owner_user_id: sh.pub_user,
                node_id: sh.pub_node,
                share_id,
                expires_at: g.expires_at,
            },
        );
        let e = element.clone().unwrap_or(crate::drive::SharedElement {
            is_dir: g.is_dir,
            name: String::new(),
            size_bytes: 0,
            modified_at: 0,
            first_block_hash: [0; 32],
            element_key: [0; 32],
        });
        let pointer = SharePointer {
            share_id,
            is_dir: e.is_dir,
            name: e.name,
            size_bytes: e.size_bytes,
            modified_at: e.modified_at,
            first_block_hash: e.first_block_hash,
            element_key: e.element_key,
            node_id: sh.pub_node,
            node_addrs: vec![sh.config.node.addr.clone()],
            owner_label: sh.names.lock().unwrap().pseudo.clone(),
            grant,
            revoked: g.revoked,
        };
        let seq = g.seq + 1;
        let result =
            match share_entry_envelope(&sh.priv_user, &token, &pointer, seq, now, &random()) {
                Ok(env) => dht
                    .put(token.dht_key().to_vec(), env)
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
        match result {
            Ok(()) => {
                g.seq = seq;
                g.published_at = now;
                g.published_first = hex::encode(pointer.first_block_hash);
                g.revoke_done = g.revoked;
                g.last_error = None;
            }
            Err(e) => g.last_error = Some(e),
        }
        sh.shares.lock().unwrap().given[i] = g;
    }
    let received = sh.shares.lock().unwrap().received.clone();
    for (i, mut r) in received.into_iter().enumerate() {
        if now < r.refreshed_at.saturating_add(crate::shares::REFRESH_S) {
            continue;
        }
        let Some(token) = r.token() else { continue };
        r.refreshed_at = now;
        match dht.get(token.dht_key().to_vec()).await {
            Ok(Some(env)) => match open_share_entry(&env, &token, now) {
                Ok((seq, p)) => {
                    if r.pointer.as_ref().is_none_or(|c| seq >= c.seq) {
                        r.pointer = Some(CachedPointer::of(seq, &p));
                    }
                    r.last_error = None;
                }
                Err(e) => r.last_error = Some(e.to_string()),
            },
            Ok(None) => {
                r.last_error =
                    Some("partage introuvable dans l'annuaire (pas encore publié ?)".into())
            }
            Err(e) => r.last_error = Some(e.to_string()),
        }
        if let Some(slot) = sh.shares.lock().unwrap().received.get_mut(i) {
            *slot = r;
        }
    }
    let store = sh.shares.lock().unwrap().clone();
    save(sh, &store);
}

fn spawn_tick(sh: &Arc<Shared>) {
    let sh = sh.clone();
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(async move { tick(&sh).await });
    }
}

fn fingerprint_of(hex_id: &str) -> String {
    hex::decode(hex_id)
        .map(|b| s3m_protocol::pseudo::fingerprint(&b))
        .unwrap_or_default()
}

/// Sections et actions de la page « Partages ».
pub fn status(sh: &Shared, v: &mut Value) {
    let store = sh.shares.lock().unwrap().clone();
    v["partages donnés"] = json!(store
        .given
        .iter()
        .rev()
        .map(|g| {
            let state = match (g.revoked, g.revoke_done, &g.last_error) {
                (true, true, _) => "retiré".to_string(),
                (true, false, _) => "retrait en cours".to_string(),
                (false, _, Some(e)) => format!("erreur : {e}"),
                (false, _, None) if g.seq == 0 => "publication en cours".to_string(),
                _ => "actif".to_string(),
            };
            let mut actions = vec![json!({ "nom": "show_share", "libellé": if g.recipient.is_some() { "Invitation" } else { "Lien" },
                "valeurs": { "id": g.id } })];
            if !g.revoked {
                actions.push(json!({ "nom": "revoke_share", "libellé": "Retirer", "style": "danger",
                    "valeurs": { "id": g.id },
                    "confirmer": "Retirer ce partage ? Le destinataire ne pourra plus rien lire ; ce qu'il a déjà téléchargé ne peut pas lui être repris." }));
            }
            json!({
                "élément": g.path,
                "type": if g.is_dir { "dossier" } else { "fichier" },
                "pour": g.recipient.as_ref().map(|r| fingerprint_of(r)).unwrap_or_else(|| "lien".into()),
                "créé le": g.created_at,
                "expire le": if g.expires_at == 0 { Value::Null } else { json!(g.expires_at) },
                "état": state,
                "_actions": actions,
            })
        })
        .collect::<Vec<_>>());
    let visible = store.visible();
    v["partages reçus"] = json!(store
        .received
        .iter()
        .rev()
        .map(|r| {
            let p = r.pointer.as_ref();
            let name = p
                .and_then(|p| visible.iter().find(|(_, x)| x == p).map(|(n, _)| n.clone()))
                .unwrap_or_else(|| p.map(|p| p.name.clone()).unwrap_or_else(|| "—".into()));
            let state = match (p, &r.last_error) {
                (Some(p), _) if p.revoked => "retiré par son propriétaire".to_string(),
                (Some(_), _) => format!("dans « {} »", SHARED_DIR.trim_start_matches('/')),
                (None, Some(e)) => format!("en attente : {e}"),
                (None, None) => "en attente".to_string(),
            };
            json!({
                "nom": name,
                "de": p.map(|p| p.owner_label.clone()).filter(|l| !l.is_empty()),
                "type": p.map(|p| if p.is_dir { "dossier" } else { "fichier" }),
                "taille (octets)": p.filter(|p| !p.is_dir).map(|p| p.size_bytes),
                "ajouté le": r.added_at,
                "état": state,
                "_actions": [{ "nom": "remove_received", "libellé": "Retirer de la liste", "style": "danger",
                               "valeurs": { "id": r.id },
                               "confirmer": "Retirer ce partage de votre liste ? Vous pourrez le rajouter avec son lien ou son invitation." }],
            })
        })
        .collect::<Vec<_>>());
    if let Some(a) = v.get_mut("actions").and_then(|a| a.as_array_mut()) {
        a.push(json!({ "nom": "create_share", "titre": "Partager un fichier ou un dossier", "libellé": "Créer le partage",
            "texte": [
                "En lecture seule. Le destinataire voit l'élément et, pour un dossier, toute son arborescence, à jour à chaque synchronisation.",
                "Destinataire vide : un lien, lisible par qui le détient. Avec l'identifiant d'un utilisateur S3m : une invitation que lui seul peut ouvrir."
            ],
            "champs": ["élément", "destinataire", "expiration (jours)"],
            "types": { "élément": "chemin", "expiration (jours)": "number" },
            "explorateurs": { "élément": "drive_browse" },
            "aide": { "élément": "Chemin dans votre espace S3m, par exemple /Photos ; « Parcourir… » pour le choisir (dossier, ou fichier en cliquant dessus)",
                      "destinataire": "Identifiant (user_id, 64 caractères) de l'utilisateur S3m ; vérifiez avec lui son empreinte. Vide : un lien",
                      "expiration (jours)": "Vide ou 0 : sans expiration" } }));
        a.push(json!({ "nom": "add_received", "titre": "Ajouter un partage reçu", "libellé": "Ajouter",
            "champs": ["lien ou invitation"], "types": { "lien ou invitation": "texte" },
            "aide": { "lien ou invitation": "Lien s3m://partage#… ou invitation S3MS1:… reçus du propriétaire" } }));
    }
}

fn reveal(title: &str, text: &str, recipient: bool) -> Value {
    json!({ "titre": title,
        "texte": if recipient { vec![
            "Transmettez cette invitation au destinataire par le moyen de votre choix (courriel, messagerie) : lui seul peut l'ouvrir.",
            "Dans S3m, il l'ajoute depuis la page Partages, « Ajouter un partage reçu » ; le partage apparaît dans son dossier « Partagés avec moi »."
        ] } else { vec![
            "Qui détient ce lien peut lire le partage : transmettez-le avec précaution.",
            "Le destinataire l'ajoute dans S3m, page Partages, « Ajouter un partage reçu » ; le partage apparaît dans son dossier « Partagés avec moi »."
        ] },
        "à copier": text,
        "fermer": "Fermer" })
}

/// Actions de la page « Partages » ; `None` si l'action n'en relève pas.
pub fn action(sh: &Arc<Shared>, name: &str, v: &Value) -> Option<Result<Value, String>> {
    let text = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let now = (sh.clock)();
    Some(match name {
        "drive_browse" => drive_browse(sh, &text("chemin")),
        "create_share" => (|| {
            let drive = sh.drive.clone().ok_or("pas de lecteur")?;
            let path = format!("/{}", text("élément").trim_matches('/'));
            if path.starts_with(SHARED_DIR) {
                return Err("un partage reçu ne peut pas être repartagé".to_string());
            }
            let e = drive
                .lock()
                .unwrap()
                .shared_element(&path)
                .map_err(|e| e.to_string())?
                .ok_or("élément introuvable, ou pas encore synchronisé avec votre Nœud")?;
            let recipient = match text("destinataire") {
                r if r.is_empty() => None,
                r => Some(
                    hex::decode(&r)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .ok_or(
                            "destinataire : identifiant de 64 caractères hexadécimaux attendu",
                        )?,
                ),
            };
            let days = v
                .get("expiration (jours)")
                .and_then(|x| {
                    x.as_u64()
                        .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
                })
                .unwrap_or(0);
            let token = ShareToken::new(&sh.priv_user, random());
            let shared_text = match &recipient {
                Some(r) => token
                    .invite(r, &random(), &random())
                    .map_err(|e| e.to_string())?,
                None => token.link(),
            };
            let g = GivenShare {
                id: hex::encode(token.share_id()),
                secret: hex::encode(token.secret),
                path,
                is_dir: e.is_dir,
                recipient: recipient.map(hex::encode),
                created_at: now,
                expires_at: if days == 0 { 0 } else { now + days * 86_400 },
                text: shared_text.clone(),
                ..Default::default()
            };
            let store = {
                let mut s = sh.shares.lock().unwrap();
                s.given.push(g);
                s.clone()
            };
            save(sh, &store);
            spawn_tick(sh);
            Ok(
                json!({ "ok": true, "message": "Partage créé ; publication dans l'annuaire en cours",
                "révéler": reveal(if recipient.is_some() { "Invitation à transmettre" } else { "Lien de partage" }, &shared_text, recipient.is_some()) }),
            )
        })(),
        "show_share" => {
            let s = sh.shares.lock().unwrap();
            match s.given.iter().find(|g| g.id == text("id")) {
                Some(g) => Ok(json!({ "ok": true, "message": "Partage",
                    "révéler": reveal(if g.recipient.is_some() { "Invitation à transmettre" } else { "Lien de partage" }, &g.text, g.recipient.is_some()) })),
                None => Err("partage introuvable".into()),
            }
        }
        "revoke_share" => {
            let store = {
                let mut s = sh.shares.lock().unwrap();
                let Some(g) = s.given.iter_mut().find(|g| g.id == text("id")) else {
                    return Some(Err("partage introuvable".into()));
                };
                g.revoked = true;
                s.clone()
            };
            save(sh, &store);
            spawn_tick(sh);
            Ok(
                json!({ "ok": true, "message": "Partage retiré ; votre Nœud et l'annuaire sont prévenus" }),
            )
        }
        "add_received" => (|| {
            let token =
                ShareToken::parse(&text("lien ou invitation"), &sh.priv_user, &sh.pub_user)?;
            let id = hex::encode(token.share_id());
            let store = {
                let mut s = sh.shares.lock().unwrap();
                if s.received.iter().any(|r| r.id == id) {
                    return Err("ce partage est déjà dans votre liste".to_string());
                }
                if s.given.iter().any(|g| g.id == id) {
                    return Err("c'est un de vos propres partages".to_string());
                }
                s.received.push(ReceivedShare::of(&token, now));
                s.clone()
            };
            save(sh, &store);
            spawn_tick(sh);
            Ok(
                json!({ "ok": true, "message": "Partage ajouté : il apparaît dans « Partagés avec moi » dès sa lecture dans l'annuaire" }),
            )
        })(),
        "remove_received" => {
            let store = {
                let mut s = sh.shares.lock().unwrap();
                s.received.retain(|r| r.id != text("id"));
                s.clone()
            };
            save(sh, &store);
            Ok(json!({ "ok": true, "message": "Partage retiré de votre liste" }))
        }
        _ => return None,
    })
}

/// Explorateur de son espace S3m (choix de l'élément à partager).
fn drive_browse(sh: &Shared, path: &str) -> Result<Value, String> {
    let drive = sh.drive.clone().ok_or("pas de lecteur")?;
    let p = format!("/{}", path.trim_matches('/'));
    let mut p = if p == "//" { "/".to_string() } else { p };
    // Chemin d'un fichier (élément déjà choisi) : son dossier.
    if drive
        .lock()
        .unwrap()
        .stat(&p)
        .ok()
        .flatten()
        .is_some_and(|m| !m.is_dir)
    {
        p = match p.rsplit_once('/') {
            Some(("", _)) | None => "/".to_string(),
            Some((up, _)) => up.to_string(),
        };
    }
    let entries = drive.lock().unwrap().list(&p).map_err(|e| e.to_string())?;
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for (n, m) in entries {
        if p == "/" && format!("/{n}") == SHARED_DIR {
            continue;
        }
        if m.is_dir {
            dirs.push(n);
        } else {
            files.push(n);
        }
    }
    let parent = (p != "/").then(|| {
        let up = p.rsplit_once('/').map(|(a, _)| a).unwrap_or("");
        if up.is_empty() {
            "/".to_string()
        } else {
            up.to_string()
        }
    });
    Ok(json!({ "ok": true, "données": {
        "chemin": p, "parent": parent, "dossiers": dirs, "fichiers": files,
        "racines": ["/"], "séparateur": "/", "création": false } }))
}

/// État des partages chargé au démarrage.
pub fn load(dir: &std::path::Path) -> Arc<Mutex<ShareStore>> {
    Arc::new(Mutex::new(ShareStore::load(dir)))
}
