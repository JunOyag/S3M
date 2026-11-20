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
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
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

/// Verrou d'instance unique : fichier ouvert en exclusivité.
/// Variable d'environnement du redémarrage « Changer de Nœud ».
const CHANGE_NODE_ENV: &str = "S3M_CHANGE_NODE";

/// Relance S3m sur l'assistant ; l'instance courante doit ensuite quitter.
fn restart_for_new_node() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe)
            .env(CHANGE_NODE_ENV, "1")
            .spawn();
    }
}

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
    Started(Arc<Shared>, String),
    Setup(String),
    ConfigReady(PathBuf),
    Failed(String),
}

fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn start_connector(
    rt: &tokio::runtime::Runtime,
    path: PathBuf,
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    rt.spawn(async move {
        let r = match Config::load(&path) {
            Err(e) => Err(e.to_string()),
            Ok(c) => daemon::start(c, Arc::new(clock))
                .await
                .map_err(|e| e.to_string()),
        };
        let _ = proxy.send_event(match r {
            Ok((sh, url)) => UserEvent::Started(sh, url),
            Err(e) => UserEvent::Failed(e),
        });
    });
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
    // Redémarrage demandé par « Changer de Nœud » : l'ancienne instance
    // libère le verrou en quittant.
    let changing = std::env::var_os(CHANGE_NODE_ENV).is_some();
    let mut lock = single_instance(&dir);
    for _ in 0..60 {
        if lock.is_some() || !changing {
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
    if changing {
        match s3m_connector::setup::set_aside_config(&dir, clock()) {
            Ok(()) => log("changement de Nœud : ancienne configuration mise de côté"),
            Err(e) => log(&format!("changement de Nœud : {e}")),
        }
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
    let open_drive = MenuItem::new("Ouvrir le lecteur", false, None);
    let open_dash = MenuItem::new("Ouvrir le tableau de bord", false, None);
    let sync = MenuItem::new("Synchroniser maintenant", false, None);
    let pause = MenuItem::new("Suspendre la synchronisation", false, None);
    let autostart = CheckMenuItem::new("Démarrer avec Windows", true, autostart_enabled(), None);
    let logs = MenuItem::new("Ouvrir les journaux", true, None);
    let change = MenuItem::new("Changer de Nœud…", true, None);
    let quit = MenuItem::new("Quitter S3m", true, None);
    let menu = Menu::new();
    let _ = menu.append_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &open_drive,
        &open_dash,
        &PredefinedMenuItem::separator(),
        &sync,
        &pause,
        &PredefinedMenuItem::separator(),
        &autostart,
        &change,
        &logs,
        &PredefinedMenuItem::separator(),
        &quit,
    ]);

    let cfg = config_path(&dir);
    if cfg.exists() {
        start_connector(&rt, cfg, proxy.clone());
    } else {
        let (proxy, dir) = (proxy.clone(), dir.clone());
        rt.spawn(async move {
            match serve_setup(dir).await {
                Err(e) => {
                    let _ = proxy.send_event(UserEvent::Failed(e));
                }
                Ok((url, done)) => {
                    let _ = proxy.send_event(UserEvent::Setup(url));
                    if let Ok(path) = done.await {
                        let _ = proxy.send_event(UserEvent::ConfigReady(path));
                    }
                }
            }
        });
    }

    let mut tray: Option<TrayIcon> = None;
    let mut shared: Option<Arc<Shared>> = None;
    let mut dash_url: Option<String> = None;
    let mut last: Option<TrayView> = None;
    let mut offline_notified = false;
    let mut after_setup = false;
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(2));
        match event {
            Event::NewEvents(StartCause::Init) => {
                tray = TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("S3m — démarrage…")
                    .with_icon(icon(TrayState::Starting))
                    .build()
                    .ok();
            }
            Event::UserEvent(UserEvent::Setup(url)) => {
                log("assistant de premier lancement");
                status.set_text("Configuration initiale à terminer");
                open_dash.set_text("Ouvrir l'assistant de configuration");
                open_dash.set_enabled(true);
                dash_url = Some(url.clone());
                open(&url);
                notify("Bienvenue ! Terminez la configuration dans la page qui vient de s'ouvrir.");
            }
            Event::UserEvent(UserEvent::ConfigReady(path)) => {
                log("configuration écrite");
                open_dash.set_text("Ouvrir le tableau de bord");
                after_setup = true;
                start_connector(&rt, path, proxy.clone());
            }
            Event::UserEvent(UserEvent::Started(sh, url)) => {
                log("Connecteur démarré");
                // Premier lancement : le tableau de bord suit l'assistant.
                if std::mem::take(&mut after_setup) {
                    open(&url);
                }
                dash_url = Some(url);
                shared = Some(sh);
                for item in [&open_dash, &sync, &pause] {
                    item.set_enabled(true);
                }
            }
            Event::UserEvent(UserEvent::Failed(e)) => {
                log(&format!("échec : {e}"));
                status.set_text("Erreur au démarrage (voir les journaux)");
                if let Some(t) = &tray {
                    let _ = t.set_icon(Some(icon(TrayState::Error)));
                    let _ = t.set_tooltip(Some(format!("S3m — {e}")));
                }
                notify(&format!("S3m n'a pas pu démarrer : {e}"));
            }
            Event::UserEvent(UserEvent::Menu(e)) => {
                if e.id == quit.id() {
                    log("arrêt demandé");
                    *flow = ControlFlow::Exit;
                } else if e.id == change.id() {
                    log("changement de Nœud demandé");
                    notify("S3m redémarre sur l'assistant : votre identité est conservée, l'ancienne configuration est mise de côté.");
                    restart_for_new_node();
                    *flow = ControlFlow::Exit;
                } else if e.id == logs.id() {
                    open(&dir.join("logs").display().to_string());
                } else if e.id == autostart.id() {
                    set_autostart(autostart.is_checked());
                    log(&format!("démarrage avec Windows : {}", autostart.is_checked()));
                } else if e.id == open_dash.id() {
                    if let Some(u) = &dash_url {
                        open(u);
                    }
                } else if e.id == open_drive.id() {
                    if let Some(m) = shared.as_ref().and_then(|s| s.config.mount_point.clone()) {
                        open(&format!("{m}\\"));
                    }
                } else if let Some(sh) = &shared {
                    if e.id == sync.id() {
                        let _g = rt.enter();
                        daemon::sync_now(sh);
                    } else if e.id == pause.id() {
                        let now = !sh.paused.load(Ordering::Relaxed);
                        sh.paused.store(now, Ordering::Relaxed);
                        pause.set_text(if now { "Reprendre la synchronisation" } else { "Suspendre la synchronisation" });
                        log(if now { "synchronisation suspendue" } else { "synchronisation reprise" });
                    }
                }
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                let Some(sh) = &shared else { return };
                if sh.change_node.load(Ordering::SeqCst) {
                    log("changement de Nœud demandé (tableau de bord)");
                    restart_for_new_node();
                    *flow = ControlFlow::Exit;
                    return;
                }
                let v = daemon::tray_view(sh);
                if last.as_ref() != Some(&v) {
                    status.set_text(&v.text);
                    open_drive.set_enabled(v.mounted);
                    if let Some(t) = &tray {
                        let _ = t.set_icon(Some(icon(v.state)));
                        let _ = t.set_tooltip(Some(format!("S3m — {}", v.text)));
                    }
                    // Notifications sur les transitions importantes.
                    let prev = last.clone();
                    if v.conflict && !prev.as_ref().is_some_and(|p| p.conflict) {
                        notify("Conflit de synchronisation : un autre appareil a modifié vos fichiers. Ouvrez le tableau de bord.");
                    }
                    if v.attached_quota.is_some() && prev.as_ref().is_some_and(|p| p.attached_quota.is_none()) {
                        notify("Rattachement automatique accepté par votre Nœud.");
                    }
                    if v.attach_error.is_some() && prev.as_ref().is_none_or(|p| p.attach_error != v.attach_error) {
                        notify(&format!("Rattachement refusé : {}", v.attach_error.clone().unwrap_or_default()));
                    }
                    if v.sync_error.is_some() && prev.as_ref().is_none_or(|p| p.sync_error.is_none()) {
                        notify(&format!("Erreur de synchronisation : {}", v.sync_error.clone().unwrap_or_default()));
                    }
                    if v.reachable == Some(true) && offline_notified {
                        offline_notified = false;
                        notify("Votre Nœud est de nouveau joignable.");
                    }
                    log(&format!("état : {}", v.text));
                    last = Some(v.clone());
                }
                if let (Some(since), false) = (v.offline_since, offline_notified) {
                    if clock().saturating_sub(since) >= 600 {
                        offline_notified = true;
                        notify("Votre Nœud est injoignable depuis plus de 10 minutes. Vos modifications sont conservées localement.");
                    }
                }
            }
            _ => {}
        }
    });
}
