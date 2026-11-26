//! `S3m.exe` — application de la barre des tâches du Connecteur
//! (`deploiement.packaging` § Application de la barre des tâches).
//!
//! Application de session (pas un service Windows), sans console, une seule
//! instance par utilisateur. Démarre l'assistant de premier lancement s'il
//! n'y a pas de configuration dans `%APPDATA%\S3m`, sinon le Connecteur (lecteur
//! monté, synchronisation, dashboard). Icône colorée selon l'état, menu de
//! pilotage, notifications Windows.
#![cfg_attr(not(test), windows_subsystem = "windows")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use s3m_connector::daemon::{self, Config, Shared, TrayState, TrayView};
use s3m_connector::setup::{app_dir, config_path, serve_setup};
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "S3m";

static LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

fn log(msg: &str) {
    if let Some(f) = LOG.lock().unwrap().as_mut() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{now} {msg}");
    }
}

fn icon(state: TrayState) -> Icon {
    let raw: &[u8] = match state {
        TrayState::Ok => include_bytes!("../../assets/tray-ok.rgba"),
        TrayState::Syncing => include_bytes!("../../assets/tray-sync.rgba"),
        TrayState::Paused | TrayState::Starting => include_bytes!("../../assets/tray-paused.rgba"),
        TrayState::Offline => include_bytes!("../../assets/tray-offline.rgba"),
        TrayState::Error => include_bytes!("../../assets/tray-error.rgba"),
    };
    Icon::from_rgba(raw.to_vec(), 32, 32).expect("icône 32×32 RGBA")
}

/// Mode d'essai (`S3M_HEADLESS`) : ni navigateur ni notification ; l'URL
/// de l'assistant est écrite dans `setup.url` pour les scripts d'essai.
fn headless() -> bool {
    std::env::var_os("S3M_HEADLESS").is_some()
}

fn notify(text: &str) {
    log(&format!("notification : {text}"));
    if headless() {
        return;
    }
    let _ =
        tauri_winrt_notification::Toast::new(tauri_winrt_notification::Toast::POWERSHELL_APP_ID)
            .title("S3m")
            .text1(text)
            .show();
}

/// Ouvre une URL (le fragment `#token=…` est conservé) ou un dossier.
fn open(target: &str) {
    if headless() {
        if target.starts_with("http") {
            let _ = std::fs::write(app_dir().join("setup.url"), target);
        }
        return;
    }
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", target])
        .spawn();
}

fn autostart_enabled() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(RUN_VALUE))
        .is_ok()
}

fn set_autostart(on: bool) {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(RUN_KEY) {
        if on {
            if let Ok(exe) = std::env::current_exe() {
                let _ = key.set_value(RUN_VALUE, &format!("\"{}\"", exe.display()));
            }
        } else {
            let _ = key.delete_value(RUN_VALUE);
        }
    }
}

/// Variable d'environnement du redémarrage « Changer de Nœud » : dossier de
/// l'identité concernée (`1` : identité d'origine, anciennes versions).
const CHANGE_NODE_ENV: &str = "S3M_CHANGE_NODE";
/// Variable d'environnement du redémarrage « Archiver cette identité ».
const REMOVE_ENV: &str = "S3M_REMOVE_IDENTITY";

/// Relance S3m avec `(variable, dossier)` ; l'instance courante doit
/// ensuite quitter.
fn restart_with(var: &str, dir: &Path) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).env(var, dir).spawn();
    }
}

/// Verrou d'instance unique : fichier ouvert en exclusivité.
fn single_instance(dir: &Path) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .share_mode(0)
        .open(dir.join("s3m.lock"))
        .ok()
}

enum UserEvent {
    Menu(MenuEvent),
    Started(usize, Arc<Shared>, String),
    Setup(usize, String),
    ConfigReady(usize, PathBuf),
    Failed(usize, String),
    /// Identité arrêtée pour un changement de Nœud : configuration mise de
    /// côté (`Ok`), ou échec (redémarrage complet).
    Restarted(usize, Result<(), String>),
    /// Identité arrêtée pour appliquer un nouvel accès aux fichiers.
    Relaunch(usize),
}

fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Une identité et son sous-menu.
struct Ident {
    num: u32,
    dir: PathBuf,
    sub: Submenu,
    status: MenuItem,
    files: MenuItem,
    dash: MenuItem,
    sync: MenuItem,
    pause: MenuItem,
    change: MenuItem,
    remove: Option<MenuItem>,
    shared: Option<Arc<Shared>>,
    url: Option<String>,
    last: Option<TrayView>,
    failed: bool,
    offline_notified: bool,
    after_setup: bool,
    /// Nom affiché du sous-menu (pseudo · empreinte), suivi à chaque tour.
    label: String,
}

impl Ident {
    fn new(num: u32, dir: PathBuf) -> Self {
        let status = MenuItem::new("Démarrage…", false, None);
        let files = MenuItem::new("Ouvrir mes fichiers", false, None);
        let dash = MenuItem::new("Ouvrir le tableau de bord", false, None);
        let sync = MenuItem::new("Synchroniser maintenant", false, None);
        let pause = MenuItem::new("Suspendre la synchronisation", false, None);
        let change = MenuItem::new("Changer de Nœud…", true, None);
        // L'identité d'origine ne se retire que s'il en reste une autre
        // (activé à chaque tour).
        let remove = Some(MenuItem::new(ARCHIVE_TEXT, num > 1, None));
        let sub = Submenu::new(format!("Identité {num}"), true);
        let _ = sub.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &files,
            &dash,
            &PredefinedMenuItem::separator(),
            &sync,
            &pause,
            &PredefinedMenuItem::separator(),
            &change,
        ]);
        if let Some(r) = &remove {
            let _ = sub.append(r);
        }
        Ident {
            num,
            dir,
            sub,
            status,
            files,
            dash,
            sync,
            pause,
            change,
            remove,
            shared: None,
            url: None,
            last: None,
            failed: false,
            offline_notified: false,
            after_setup: false,
            label: String::new(),
        }
    }

    fn name(&self) -> String {
        match &self.shared {
            Some(sh) => daemon::identity_label(sh),
            None => format!("Identité {}", self.num),
        }
    }

    fn state(&self) -> TrayState {
        match (&self.last, self.failed) {
            (_, true) => TrayState::Error,
            (Some(v), _) => v.state,
            (None, _) => TrayState::Starting,
        }
    }
}

/// Lance le Connecteur de l'identité `i`, ou son assistant s'il n'est pas
/// configuré.
fn launch(
    rt: &tokio::runtime::Runtime,
    i: usize,
    dir: PathBuf,
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    let cfg = config_path(&dir);
    if cfg.exists() {
        start_connector(rt, i, cfg, proxy);
        return;
    }
    rt.spawn(async move {
        match serve_setup(dir).await {
            Err(e) => {
                let _ = proxy.send_event(UserEvent::Failed(i, e));
            }
            Ok((url, done)) => {
                let _ = proxy.send_event(UserEvent::Setup(i, url));
                if let Ok(path) = done.await {
                    let _ = proxy.send_event(UserEvent::ConfigReady(i, path));
                }
            }
        }
    });
}

fn start_connector(
    rt: &tokio::runtime::Runtime,
    i: usize,
    path: PathBuf,
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    rt.spawn(async move {
        let r = match Config::load(&path) {
            Err(e) => Err(e.to_string()),
            Ok(c) => {
                // Coffre local : phrase en clair rangée dans celui du système.
                s3m_protocol::vault::auto_protect(&c.seed_file);
                daemon::start(c, Arc::new(clock)).await.map_err(|e| e.to_string())
            }
        };
        let _ = proxy.send_event(match r {
            Ok((sh, url)) => UserEvent::Started(i, sh, url),
            Err(e) => UserEvent::Failed(i, e),
        });
    });
}

const ARCHIVE_TEXT: &str = "Archiver cette identité";

/// Entrée du menu « Identités archivées ».
struct ArchivedItem {
    ar: s3m_connector::identities::Archived,
    sub: Submenu,
    restore: MenuItem,
    purge: MenuItem,
}

/// Fenêtre de confirmation de la suppression définitive (Oui / Non, « Non »
/// par défaut) ; acceptée d'office en mode d'essai.
fn confirm_purge(label: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST,
        MB_YESNO,
    };
    if headless() {
        return true;
    }
    let text = format!(
        "Supprimer définitivement « {label} » de ce poste ?\n\n\
         Le dossier de cette identité est effacé, y compris sa phrase de \
         récupération (24 mots). Seule cette phrase, si vous l'avez notée, \
         permettra ensuite de retrouver l'accès à vos données.\n\n\
         Sans aucun appareil connecté sous cette identité, ses entrées dans \
         l'annuaire du réseau S3m expirent au bout de 6 mois : restaurez-la \
         avec sa phrase avant ce délai pour retrouver vos données.\n\n\
         Cette suppression est irréversible."
    );
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (t, c) = (wide(&text), wide("S3m — suppression définitive"));
    let r = unsafe {
        MessageBoxW(
            None,
            PCWSTR(t.as_ptr()),
            PCWSTR(c.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    r == IDYES
}

/// (Re)construit le menu « Identités archivées » (grisé s'il est vide).
fn fill_archives(menu: &Submenu, items: &mut Vec<ArchivedItem>, app: &Path) {
    for it in items.drain(..) {
        let _ = menu.remove(&it.sub);
    }
    for ar in s3m_connector::identities::archived(app) {
        let sub = Submenu::new(ar.label(), true);
        let restore = MenuItem::new("Réactiver", true, None);
        let purge = MenuItem::new("Supprimer définitivement…", true, None);
        let _ = sub.append_items(&[&restore, &purge]);
        let _ = menu.append(&sub);
        items.push(ArchivedItem {
            ar,
            sub,
            restore,
            purge,
        });
    }
    menu.set_enabled(!items.is_empty());
}

/// Changement de Nœud d'une seule identité, sans arrêter les autres :
/// identité arrêtée, configuration mise de côté, puis assistant.
fn begin_change(
    rt: &tokio::runtime::Runtime,
    i: usize,
    id: &mut Ident,
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    let Some(sh) = id.shared.take() else {
        return;
    };
    id.url = None;
    id.last = None;
    id.failed = false;
    id.status
        .set_text("Changement de Nœud : arrêt de l'identité…");
    for item in [&id.files, &id.dash, &id.sync, &id.pause, &id.change] {
        item.set_enabled(false);
    }
    let dir = id.dir.clone();
    rt.spawn(async move {
        daemon::stop(sh).await;
        // Fichiers relâchés en quelques instants : quelques essais.
        let stamp = clock();
        let mut r = Err(String::new());
        for _ in 0..20 {
            match s3m_connector::setup::set_aside_config(&dir, stamp) {
                Ok(()) => {
                    r = Ok(());
                    break;
                }
                Err(e) => {
                    r = Err(e.to_string());
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        let _ = proxy.send_event(UserEvent::Restarted(i, r));
    });
}

/// Redémarrage d'une seule identité (accès aux fichiers changé).
fn begin_relaunch(
    rt: &tokio::runtime::Runtime,
    i: usize,
    id: &mut Ident,
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    let Some(sh) = id.shared.take() else {
        return;
    };
    id.last = None;
    id.status
        .set_text("Accès aux fichiers : redémarrage de l'identité…");
    for item in [&id.files, &id.sync, &id.pause] {
        item.set_enabled(false);
    }
    rt.spawn(async move {
        daemon::stop(sh).await;
        let _ = proxy.send_event(UserEvent::Relaunch(i));
    });
}

/// Retrait demandé au redémarrage précédent : dossier synchronisé
/// déconnecté, dossier de l'identité mis de côté.
fn remove_identity(app: &Path, dir: &Path) {
    if let Ok(c) = Config::load(&config_path(dir)) {
        if daemon::access_mode(&c) == "dossier" {
            let _ = s3m_connector::cloud_folder::unregister(&daemon::folder_path(&c));
        }
    }
    match s3m_connector::identities::set_aside(app, dir, clock()) {
        Ok(to) => log(&format!("identité archivée : {}", to.display())),
        Err(e) => log(&format!("archivage d'identité : {e}")),
    }
}

fn main() {
    let dir = app_dir();
    let _ = std::fs::create_dir_all(dir.join("logs"));
    *LOG.lock().unwrap() = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("logs").join("s3m.log"))
        .ok();
    std::panic::set_hook(Box::new(|p| log(&format!("panique : {p}"))));
    // Journal : lignes au-delà de la conservation retirées au démarrage,
    // puis chaque jour.
    let logs = dir.join("logs");
    let purge = move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut f = LOG.lock().unwrap();
        let _ = daemon::purge_log(&logs.join("s3m.log"), daemon::log_days(&logs), now);
        // Fichier remplacé : réouvert en ajout.
        *f = std::fs::OpenOptions::new().create(true).append(true).open(logs.join("s3m.log")).ok();
    };
    purge();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(86_400));
        purge();
    });
    // Redémarrage demandé (changement de Nœud, retrait d'identité) :
    // l'ancienne instance libère le verrou en quittant.
    let changing = std::env::var_os(CHANGE_NODE_ENV).map(|v| {
        if v == "1" {
            dir.clone()
        } else {
            PathBuf::from(v)
        }
    });
    let removing = std::env::var_os(REMOVE_ENV).map(PathBuf::from);
    let mut lock = single_instance(&dir);
    for _ in 0..60 {
        if lock.is_some() || (changing.is_none() && removing.is_none()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        lock = single_instance(&dir);
    }
    let Some(_lock) = lock else {
        notify("S3m est déjà lancé (icône dans la barre des tâches).");
        return;
    };
    log("démarrage");
    if let Some(d) = &changing {
        match s3m_connector::setup::set_aside_config(d, clock()) {
            Ok(()) => log(&format!(
                "changement de Nœud ({}) : ancienne configuration mise de côté",
                d.display()
            )),
            Err(e) => log(&format!("changement de Nœud : {e}")),
        }
    }
    if let Some(d) = &removing {
        remove_identity(&dir, d);
    }
    let rt = tokio::runtime::Runtime::new().expect("runtime tokio");

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    {
        let proxy = proxy.clone();
        MenuEvent::set_event_handler(Some(move |e| {
            let _ = proxy.send_event(UserEvent::Menu(e));
        }));
    }

    let status = MenuItem::new("Démarrage…", false, None);
    let add = MenuItem::new("Ajouter une identité…", true, None);
    let archive_menu = Submenu::new("Identités archivées", false);
    let mut archives: Vec<ArchivedItem> = Vec::new();
    fill_archives(&archive_menu, &mut archives, &dir);
    let autostart = CheckMenuItem::new("Démarrer avec Windows", true, autostart_enabled(), None);
    let logs = MenuItem::new("Ouvrir les journaux", true, None);
    let quit = MenuItem::new("Quitter S3m", true, None);
    let menu = Menu::new();
    let mut idents: Vec<Ident> = s3m_connector::identities::list(&dir)
        .into_iter()
        .map(|(n, d)| Ident::new(n, d))
        .collect();
    let _ = menu.append_items(&[&status, &PredefinedMenuItem::separator()]);
    for id in &idents {
        let _ = menu.append(&id.sub);
    }
    let _ = menu.append_items(&[
        &PredefinedMenuItem::separator(),
        &add,
        &archive_menu,
        &autostart,
        &logs,
        &PredefinedMenuItem::separator(),
        &quit,
    ]);
    for (i, id) in idents.iter().enumerate() {
        launch(&rt, i, id.dir.clone(), proxy.clone());
    }

    let mut tray: Option<TrayIcon> = None;
    let mut last_overall: Option<(TrayState, String)> = None;
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(2));
        let many = idents.len() > 1;
        // Notification préfixée du nom de l'identité s'il y en a plusieurs.
        let say = |id: &Ident, text: &str| {
            if many {
                notify(&format!("{} : {text}", id.name()))
            } else {
                notify(text)
            }
        };
        match event {
            Event::NewEvents(StartCause::Init) => {
                tray = TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("S3m — démarrage…")
                    .with_icon(icon(TrayState::Starting))
                    .build()
                    .ok();
            }
            Event::UserEvent(UserEvent::Setup(i, url)) => {
                let id = &mut idents[i];
                log(&format!("assistant de configuration (identité {})", id.num));
                id.status.set_text("Configuration initiale à terminer");
                id.dash.set_text("Ouvrir l'assistant de configuration");
                id.dash.set_enabled(true);
                id.url = Some(url.clone());
                open(&url);
                notify("Bienvenue ! Terminez la configuration dans la page qui vient de s'ouvrir.");
            }
            Event::UserEvent(UserEvent::ConfigReady(i, path)) => {
                let id = &mut idents[i];
                log(&format!("configuration écrite (identité {})", id.num));
                id.dash.set_text("Ouvrir le tableau de bord");
                id.after_setup = true;
                start_connector(&rt, i, path, proxy.clone());
            }
            Event::UserEvent(UserEvent::Started(i, sh, url)) => {
                let id = &mut idents[i];
                // Premier lancement : le tableau de bord suit l'assistant.
                if std::mem::take(&mut id.after_setup) {
                    open(&url);
                }
                id.url = Some(url);
                id.shared = Some(sh);
                id.failed = false;
                id.sub.set_text(id.name());
                log(&format!("Connecteur démarré (identité {} : {})", id.num, id.name()));
                for item in [&id.dash, &id.sync, &id.pause] {
                    item.set_enabled(true);
                }
            }
            Event::UserEvent(UserEvent::Relaunch(i)) => {
                let id = &idents[i];
                log(&format!("accès aux fichiers changé : redémarrage (identité {})", id.num));
                start_connector(&rt, i, config_path(&id.dir), proxy.clone());
            }
            Event::UserEvent(UserEvent::Restarted(i, r)) => {
                let id = &mut idents[i];
                match r {
                    Ok(()) => {
                        log(&format!("changement de Nœud : configuration mise de côté (identité {})", id.num));
                        id.change.set_enabled(true);
                        launch(&rt, i, id.dir.clone(), proxy.clone());
                    }
                    Err(e) => {
                        // Fichiers encore ouverts : redémarrage complet, qui
                        // achève la mise de côté.
                        log(&format!("changement de Nœud sans redémarrage impossible (identité {}) : {e}", id.num));
                        restart_with(CHANGE_NODE_ENV, &id.dir);
                        *flow = ControlFlow::Exit;
                    }
                }
            }
            Event::UserEvent(UserEvent::Failed(i, e)) => {
                let id = &mut idents[i];
                log(&format!("échec (identité {}) : {e}", id.num));
                id.failed = true;
                id.status.set_text("Erreur au démarrage (voir les journaux)");
                say(id, &format!("S3m n'a pas pu démarrer : {e}"));
            }
            Event::UserEvent(UserEvent::Menu(e)) => {
                if e.id == quit.id() {
                    log("arrêt demandé");
                    *flow = ControlFlow::Exit;
                    return;
                } else if e.id == logs.id() {
                    open(&dir.join("logs").display().to_string());
                    return;
                } else if e.id == autostart.id() {
                    set_autostart(autostart.is_checked());
                    log(&format!("démarrage avec Windows : {}", autostart.is_checked()));
                    return;
                } else if e.id == add.id() {
                    match s3m_connector::identities::next_dir(&dir) {
                        Ok((n, d)) => {
                            log(&format!("ajout de l'identité {n}"));
                            let id = Ident::new(n, d.clone());
                            let _ = menu.insert(&id.sub, 2 + idents.len());
                            idents.push(id);
                            launch(&rt, idents.len() - 1, d, proxy.clone());
                        }
                        Err(e) => notify(&format!("Impossible d'ajouter une identité : {e}")),
                    }
                    return;
                }
                // Identités archivées : restaurer, supprimer définitivement.
                if let Some(k) = archives.iter().position(|a| a.restore.id() == &e.id) {
                    let ar = archives[k].ar.clone();
                    match s3m_connector::identities::restore(&dir, &ar.dir) {
                        Ok((n, d)) => {
                            log(&format!("identité restaurée : {} → {}", ar.dir.display(), d.display()));
                            notify(&format!("{} restaurée (identité {n}).", ar.label().split(" — ").next().unwrap_or("Identité")));
                            let id = Ident::new(n, d.clone());
                            let _ = menu.insert(&id.sub, 2 + idents.len());
                            idents.push(id);
                            launch(&rt, idents.len() - 1, d, proxy.clone());
                        }
                        Err(e) => notify(&format!("Restauration impossible : {e}")),
                    }
                    fill_archives(&archive_menu, &mut archives, &dir);
                    return;
                }
                if let Some(k) = archives.iter().position(|a| a.purge.id() == &e.id) {
                    let ar = archives[k].ar.clone();
                    if !confirm_purge(&ar.label()) {
                        return;
                    }
                    match s3m_connector::identities::purge(&dir, &ar.dir) {
                        Ok(()) => log(&format!("identité archivée supprimée : {}", ar.dir.display())),
                        Err(e) => notify(&format!("Suppression impossible : {e}")),
                    }
                    fill_archives(&archive_menu, &mut archives, &dir);
                    return;
                }
                let Some(i) = idents.iter().position(|id| {
                    [&id.files, &id.dash, &id.sync, &id.pause, &id.change]
                        .iter()
                        .any(|m| m.id() == &e.id)
                        || id.remove.as_ref().is_some_and(|r| r.id() == &e.id)
                }) else {
                    return;
                };
                let id = &mut idents[i];
                if e.id == *id.change.id() {
                    log(&format!("changement de Nœud demandé (identité {})", id.num));
                    say(id, "Changement de Nœud : cette identité s'arrête puis l'assistant s'ouvre ; votre identité est conservée, les autres continuent.");
                    begin_change(&rt, i, id, proxy.clone());
                } else if id.remove.as_ref().is_some_and(|r| r.id() == &e.id) {
                    log(&format!("archivage demandé (identité {})", id.num));
                    say(id, "Identité archivée : S3m redémarre sans elle. Rien n'est effacé ; menu « Identités archivées » pour la réactiver.");
                    restart_with(REMOVE_ENV, &id.dir);
                    *flow = ControlFlow::Exit;
                } else if e.id == *id.dash.id() {
                    if let Some(u) = &id.url {
                        open(u);
                    }
                } else if e.id == *id.files.id() {
                    if let Some(m) = id.shared.as_ref().and_then(|s| daemon::files_location(s)) {
                        open(&m);
                    }
                } else if let Some(sh) = &id.shared {
                    if e.id == *id.sync.id() {
                        let _g = rt.enter();
                        daemon::sync_now(sh);
                    } else if e.id == *id.pause.id() {
                        let now = !sh.paused.load(Ordering::Relaxed);
                        sh.paused.store(now, Ordering::Relaxed);
                        id.pause.set_text(if now { "Reprendre la synchronisation" } else { "Suspendre la synchronisation" });
                        log(if now { "synchronisation suspendue" } else { "synchronisation reprise" });
                    }
                }
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                for (i, id) in idents.iter_mut().enumerate() {
                    if id.num == 1 {
                        if let Some(r) = &id.remove {
                            r.set_enabled(many);
                        }
                    }
                    let Some(sh) = id.shared.clone() else { continue };
                    // Pseudo changé depuis le tableau de bord : nom du sous-menu.
                    let name = id.name();
                    if name != id.label {
                        id.sub.set_text(&name);
                        id.label = name;
                    }
                    if sh.change_node.load(Ordering::SeqCst) {
                        log(&format!("changement de Nœud demandé (tableau de bord, identité {})", id.num));
                        drop(sh);
                        begin_change(&rt, i, id, proxy.clone());
                        continue;
                    }
                    if sh.restart_identity.load(Ordering::SeqCst) {
                        drop(sh);
                        begin_relaunch(&rt, i, id, proxy.clone());
                        continue;
                    }
                    let v = daemon::tray_view(&sh);
                    if id.last.as_ref() != Some(&v) {
                        id.status.set_text(&v.text);
                        id.files.set_enabled(v.mounted);
                        id.sub.set_text(id.name());
                        // Notifications sur les transitions importantes.
                        let prev = id.last.clone();
                        if v.conflict && !prev.as_ref().is_some_and(|p| p.conflict) {
                            say(id, "Conflit de synchronisation : un autre appareil a modifié vos fichiers. Ouvrez le tableau de bord.");
                        }
                        if v.attached_quota.is_some() && prev.as_ref().is_some_and(|p| p.attached_quota.is_none()) {
                            say(id, "Rattachement automatique accepté par votre Nœud.");
                        }
                        if v.attach_error.is_some() && prev.as_ref().is_none_or(|p| p.attach_error != v.attach_error) {
                            say(id, &format!("Rattachement refusé : {}", v.attach_error.clone().unwrap_or_default()));
                        }
                        if v.text == s3m_connector::daemon::ROLLBACK_TEXT
                            && prev.as_ref().is_none_or(|p| p.text != v.text)
                        {
                            say(id, s3m_connector::daemon::ROLLBACK_TEXT);
                        }
                        if v.text == s3m_connector::daemon::MASS_CHANGE_TEXT
                            && prev.as_ref().is_none_or(|p| p.text != v.text)
                        {
                            say(id, s3m_connector::daemon::MASS_CHANGE_TEXT);
                        }
                        if v.files_missing && prev.as_ref().is_none_or(|p| !p.files_missing) {
                            say(id, s3m_connector::daemon::FILES_MISSING);
                        }
                        if v.sync_error.is_some() && prev.as_ref().is_none_or(|p| p.sync_error.is_none()) {
                            say(id, &format!("Erreur de synchronisation : {}", v.sync_error.clone().unwrap_or_default()));
                        }
                        // Au démarrage : messages non lus en attente.
                        if prev.is_none() && v.unread_messages > 0 {
                            let n = v.unread_messages;
                            say(id, &format!("Vous avez {n} message{} non lu{} de votre Nœud.",
                                if n > 1 { "s" } else { "" }, if n > 1 { "s" } else { "" }));
                        }
                        if prev.as_ref().is_some_and(|p| v.messages_received > p.messages_received) {
                            let text: String = v.last_message.clone().unwrap_or_default().chars().take(120).collect();
                            say(id, &format!("Nouveau message de votre Nœud : {text}"));
                        }
                        if v.reachable == Some(true) && id.offline_notified {
                            id.offline_notified = false;
                            say(id, "Votre Nœud est de nouveau joignable.");
                        }
                        log(&format!("état (identité {}) : {}", id.num, v.text));
                        id.last = Some(v.clone());
                    }
                    if let (Some(since), false) = (v.offline_since, id.offline_notified) {
                        if clock().saturating_sub(since) >= 600 {
                            id.offline_notified = true;
                            say(id, "Votre Nœud est injoignable depuis plus de 10 minutes. Vos modifications sont conservées localement.");
                        }
                    }
                }
                // Icône et infobulle : identité dans le pire état.
                let states: Vec<TrayState> = idents.iter().map(Ident::state).collect();
                let worst = s3m_connector::identities::worst(&states);
                // Texte : l'identité dans le pire état, et combien d'autres
                // demandent aussi attention.
                let others = s3m_connector::identities::needing_attention(&states).saturating_sub(1);
                let text = match idents.iter().find(|id| id.state() == worst) {
                    Some(id) => {
                        let t = id.last.as_ref().map(|v| v.text.clone()).unwrap_or_else(|| "démarrage…".into());
                        match (many, others) {
                            (false, _) => t,
                            (true, 0) => format!("{} : {t}", id.name()),
                            (true, n) => format!("{} : {t} (+{n} autre{})", id.name(), if n > 1 { "s" } else { "" }),
                        }
                    }
                    None => "démarrage…".into(),
                };
                if last_overall.as_ref() != Some(&(worst, text.clone())) {
                    status.set_text(if many { format!("{} identités — {text}", idents.len()) } else { text.clone() });
                    if let Some(t) = &tray {
                        let _ = t.set_icon(Some(icon(worst)));
                        let tip: String = format!("S3m — {text}").chars().take(120).collect();
                        let _ = t.set_tooltip(Some(tip));
                    }
                    last_overall = Some((worst, text));
                }
            }
            _ => {}
        }
    });
}
