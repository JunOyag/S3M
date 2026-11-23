//! Partages côté Connecteur : publication des pointeurs, retraits,
//! relecture des partages reçus, page « Partages » du tableau de bord
//! (`protocols.partage#connecteur`).

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::daemon::Shared;
use crate::drive::SHARED_DIR;
use crate::shares::{
    CachedPointer, Fetch, FetchError, GivenShare, ReceivedShare, ReceivedTree, ShareStore,
};
use s3m_protocol::exchange::{Body, Credential, Refusal, Request, Response};
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
        let client = client.as_ref().ok_or(FetchError::Unavailable)?;
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
            match wait(&rt, client.request(addr, req)) {
                Ok(Response::BlockData(d)) => return Ok(d),
                Ok(Response::Failure(Refusal::Unauthorized))
                | Err(crate::exchange::ExchangeError::Refused(Refusal::Unauthorized)) => {
                    return Err(FetchError::Denied)
                }
                _ => {}
            }
        }
        Err(FetchError::Unavailable)
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
                        let c = CachedPointer::of(seq, &p);
                        if r.folder.is_empty() {
                            r.folder = crate::shares::folder_name(&c);
                        }
                        r.pointer = Some(c);
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

/// Propriétaire (identifiant hex) inscrit dans l'autorisation du pointeur.
fn received_owner(p: &CachedPointer) -> Option<String> {
    let g = hex::decode(&p.grant).ok()?;
    let s = hex::decode(&p.grant_signature).ok()?;
    s3m_protocol::share::verify_grant(&g, &s)
        .ok()
        .map(|g| hex::encode(g.owner_user_id))
}

/// Expiration inscrite dans l'autorisation du pointeur reçu (0 : aucune).
fn received_expiry(p: &CachedPointer) -> Option<u64> {
    let g = hex::decode(&p.grant).ok()?;
    let s = hex::decode(&p.grant_signature).ok()?;
    s3m_protocol::share::verify_grant(&g, &s)
        .ok()
        .map(|g| g.expires_at)
}

/// Durée d'expiration saisie (jours, 0 : aucune).
fn days_of(v: &Value) -> u64 {
    v.get("expiration (jours)")
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .unwrap_or(0)
}

/// Nouveau partage (secret neuf) et texte à transmettre.
fn new_share(
    sh: &Shared,
    path: String,
    is_dir: bool,
    recipient: Option<[u8; 32]>,
    days: u64,
    now: u64,
) -> Result<(GivenShare, String), String> {
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
        is_dir,
        recipient: recipient.map(hex::encode),
        created_at: now,
        expires_at: if days == 0 { 0 } else { now + days * 86_400 },
        text: shared_text.clone(),
        ..Default::default()
    };
    Ok((g, shared_text))
}

/// Sections et actions de la page « Partages ».
pub fn status(sh: &Shared, v: &mut Value) {
    let contacts = sh.contacts.lock().unwrap().clone();
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
            let fixes = json!({ "id": g.id });
            let (texte, forms) = match (g.revoked, g.revoke_done) {
                (false, _) => (
                    vec![],
                    vec![
                        json!({ "nom": "show_share", "libellé": if g.recipient.is_some() { "Afficher l'invitation" } else { "Afficher le lien" },
                            "champs": [], "fixes": fixes }),
                        json!({ "nom": "revoke_share", "libellé": "Retirer le partage", "style": "danger", "champs": [], "fixes": fixes,
                            "confirmer": "Retirer ce partage ? Le destinataire ne pourra plus rien lire ; ce qu'il a déjà téléchargé ne peut pas lui être repris." }),
                    ],
                ),
                (true, true) => (
                    vec!["Partage retiré. « Repartager » crée un nouveau partage du même élément pour le même destinataire : un nouveau lien ou une nouvelle invitation, à lui retransmettre."],
                    vec![
                        json!({ "nom": "reshare_share", "titre": "Repartager", "libellé": "Repartager", "champs": ["expiration (jours)"],
                            "types": { "expiration (jours)": "number" }, "fixes": fixes,
                            "aide": { "expiration (jours)": "Vide ou 0 : sans expiration" } }),
                        json!({ "nom": "delete_share", "libellé": "Supprimer de la liste", "style": "danger", "champs": [], "fixes": fixes,
                            "confirmer": "Supprimer ce partage retiré de la liste ? Il ne pourra plus être repartagé d'ici." }),
                    ],
                ),
                (true, false) => (vec!["Retrait en cours de transmission à votre Nœud et à l'annuaire."], vec![]),
            };
            let pour = g.recipient.as_ref().map(|r| contacts.display(r)).unwrap_or_else(|| "Lien public".into());
            let expires = if g.expires_at == 0 { Value::Null } else { json!(g.expires_at) };
            let panel = json!({
                "titre": format!("Partage de {}", g.path),
                "texte": texte,
                "contenu": { "élément": g.path, "type": if g.is_dir { "dossier" } else { "fichier" }, "pour (partage)": pour,
                             "créé le": g.created_at, "expire le": expires, "état": state },
                "formulaires": forms,
            });
            json!({
                "élément": g.path,
                "type": if g.is_dir { "dossier" } else { "fichier" },
                "pour (partage)": pour,
                "créé le": g.created_at,
                "expire le": expires,
                "état": state,
                "_ouvrir": panel.clone(),
                "_actions": [{ "nom": "edit_share", "libellé": "Modifier", "panneau": panel }],
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
                // Pseudo du contact, sinon celui choisi par le propriétaire.
                "de": p.and_then(|p| received_owner(p).and_then(|o| contacts.pseudo_of(&o)))
                    .or_else(|| p.map(|p| p.owner_label.clone()))
                    .filter(|l| !l.is_empty()),
                "type": p.map(|p| if p.is_dir { "dossier" } else { "fichier" }),
                "taille (octets)": p.filter(|p| !p.is_dir).map(|p| p.size_bytes),
                "ajouté le": r.added_at,
                "expire le": p.and_then(received_expiry).filter(|t| *t != 0),
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
            "options": { "destinataire": contacts.pseudos() },
            "explorateurs": { "élément": "drive_browse" },
            "aide": { "élément": "Chemin dans votre espace S3m, par exemple /Photos ; « Parcourir… » pour le choisir (dossier, ou fichier en cliquant dessus)",
                      "destinataire": "Pseudo d'un de vos contacts (page Contacts), ou identifiant S3m (64 caractères) ; vide : un lien public",
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
            // Pseudo d'un contact ou identifiant.
            let recipient = sh
                .contacts
                .lock()
                .unwrap()
                .resolve(&text("destinataire"))
                .map_err(|e| format!("destinataire : {e}"))?;
            let (g, shared_text) = new_share(sh, path, e.is_dir, recipient, days_of(v), now)?;
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
        "reshare_share" => (|| {
            let old = sh
                .shares
                .lock()
                .unwrap()
                .given
                .iter()
                .find(|g| g.id == text("id"))
                .cloned()
                .ok_or("partage introuvable")?;
            if !(old.revoked && old.revoke_done) {
                return Err("seul un partage retiré peut être repartagé".to_string());
            }
            let drive = sh.drive.clone().ok_or("pas de lecteur")?;
            let e = drive
                .lock()
                .unwrap()
                .shared_element(&old.path)
                .map_err(|e| e.to_string())?
                .ok_or("l'élément n'existe plus dans votre espace")?;
            let recipient: Option<[u8; 32]> = old
                .recipient
                .as_deref()
                .and_then(|r| hex::decode(r).ok()?.try_into().ok());
            let (g, shared_text) =
                new_share(sh, old.path.clone(), e.is_dir, recipient, days_of(v), now)?;
            // Le retrait est définitif chez le Nœud : nouveau partage, qui
            // remplace l'ancien dans la liste.
            let store = {
                let mut s = sh.shares.lock().unwrap();
                s.given.retain(|x| x.id != old.id);
                s.given.push(g);
                s.clone()
            };
            save(sh, &store);
            spawn_tick(sh);
            Ok(
                json!({ "ok": true, "message": "Nouveau partage créé ; transmettez-le au destinataire",
                "révéler": reveal(if recipient.is_some() { "Nouvelle invitation à transmettre" } else { "Nouveau lien de partage" }, &shared_text, recipient.is_some()) }),
            )
        })(),
        "delete_share" => {
            let id = text("id");
            let store = {
                let mut s = sh.shares.lock().unwrap();
                let Some(g) = s.given.iter().find(|g| g.id == id) else {
                    return Some(Err("partage introuvable".into()));
                };
                if !(g.revoked && g.revoke_done) {
                    return Some(Err("retirez d'abord ce partage".into()));
                }
                s.given.retain(|g| g.id != id);
                s.clone()
            };
            save(sh, &store);
            Ok(json!({ "ok": true, "message": "Partage supprimé de la liste" }))
        }
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
