use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use tauri::{Emitter, Manager};
use tauri_plugin_opener::OpenerExt;

struct TrayState {
    toggle_item: tauri::menu::MenuItem<tauri::Wry>,
}

#[derive(serde::Serialize)]
struct AgentStatus {
    enrolled: bool,
    tracking_active: bool,
    agent_id: String,
    public_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PermissionsStatus {
    pub requires_permissions: bool,
    pub accessibility: bool,
    pub screen_recording: bool,
    /// Input Monitoring (`kTCCServiceListenEvent`) — the grant rdev's HID event tap
    /// actually needs to capture global keys/clicks/scroll. Distinct from Accessibility.
    pub input_monitoring: bool,
    pub automation: bool,
}

/// Live, ground-truth capture health — reflects whether telemetry is *actually*
/// being captured right now, independent of the (cache-prone) TCC preflight checks.
#[derive(serde::Serialize)]
struct CaptureHealth {
    /// The global input event tap is alive (rdev::listen has not errored out).
    input_listener_alive: bool,
    /// An input event was observed within the last few seconds.
    input_recently_seen: bool,
    /// Milliseconds since the last observed input event (-1 if none yet).
    input_idle_ms: i64,
    /// The last screenshot attempt was a real capture (not a denied/placeholder fallback).
    screen_capture_ok: bool,
}

mod platform;

#[derive(serde::Serialize)]
struct TodayMetrics {
    average_focus: u32,
    active_minutes: u32,
    total_keystrokes: u32,
    total_clicks: u32,
    slot_scores: Vec<u32>,
    total_slots: u32,
    /// Slots that cleared the focus gate and bill 10 minutes each (ADR 0012).
    billable_slots: u32,
}

fn perform_toggle_tracking(app: &tauri::AppHandle) -> Result<bool, String> {
    let telemetry_state = app.state::<Arc<daemon::daemon::TelemetryState>>();
    let currently_enabled = telemetry_state.tracking_enabled.load(Ordering::Relaxed);
    let new_state = !currently_enabled;
    telemetry_state
        .tracking_enabled
        .store(new_state, Ordering::Relaxed);

    let new_text = if new_state {
        "Pause Tracking"
    } else {
        "Resume Tracking"
    };

    let tray_state = app.state::<TrayState>();
    let _ = tray_state.toggle_item.set_text(new_text);

    if let Some(tray) = app.tray_by_id("main_tray") {
        let active_icon_bytes = include_bytes!("../icons/32x32.png").as_slice();
        let active_icon =
            tauri::image::Image::from_bytes(active_icon_bytes).map_err(|e| e.to_string())?;
        let paused_icon =
            tauri::image::Image::from_bytes(include_bytes!("../icons/32x32_paused.png"))
                .map_err(|e| e.to_string())?;
        let new_icon = if new_state { active_icon } else { paused_icon };
        let _ = tray.set_icon(Some(new_icon));
    }

    let _ = app.emit("tracking-status-changed", new_state);

    Ok(new_state)
}

/// Tauri command: pair this device with the cloud. Generates the local keypair, exchanges
/// the pairing token + public key for the cloud agent id, and stores it.
#[tauri::command]
async fn enroll_agent(token: String) -> Result<String, String> {
    // 1. Generate the local keypair (private key kept on-device).
    let mut config = daemon::config::generate_enrollment_keys(&token);

    // 2. Exchange the token + public key for the cloud agent id.
    let base = daemon::sync::cloud_base_url();
    let agent_id = daemon::sync::enroll_with_cloud(&base, &token, &config.public_key).await?;
    config.agent_id = agent_id;

    // 3. Save config locally in ~/.tenby10/config.json.
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");
    daemon::config::save_config(config_path, &config)
        .map_err(|err| format!("Failed to save local configuration: {}", err))?;

    Ok(format!(
        "Enrolled Successfully!\n\nAgent ID: {}\nPublic Key: {}",
        config.agent_id, config.public_key
    ))
}

#[tauri::command]
async fn toggle_tracking(app: tauri::AppHandle) -> Result<bool, String> {
    perform_toggle_tracking(&app)
}

#[tauri::command]
async fn get_agent_status(
    state: tauri::State<'_, Arc<daemon::daemon::TelemetryState>>,
) -> Result<AgentStatus, String> {
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");

    let mut enrolled = false;
    let mut agent_id = String::new();
    let mut public_key = String::new();
    if config_path.exists() {
        if let Ok(config) = daemon::config::load_config(config_path) {
            enrolled = !config.agent_id.is_empty();
            agent_id = config.agent_id;
            public_key = config.public_key;
        }
    }
    let tracking_active = state.tracking_enabled.load(Ordering::Relaxed);
    Ok(AgentStatus {
        enrolled,
        tracking_active,
        agent_id,
        public_key,
    })
}

#[tauri::command]
async fn get_today_metrics(
    db: tauri::State<'_, Arc<daemon::db::Database>>,
) -> Result<TodayMetrics, String> {
    let db_clone = db.inner().clone();
    let metrics = tokio::task::spawn_blocking(move || db_clone.get_today_metrics())
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Database error: {}", e))?;

    Ok(TodayMetrics {
        average_focus: metrics.0,
        active_minutes: metrics.1,
        total_keystrokes: metrics.2,
        total_clicks: metrics.3,
        slot_scores: metrics.4,
        total_slots: metrics.5,
        billable_slots: metrics.6,
    })
}

#[tauri::command]
async fn open_dashboard(app: tauri::AppHandle) -> Result<(), String> {
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");
    let config = daemon::config::load_config(config_path).unwrap_or_default();
    let port = daemon::env::get_app_port(&config);

    app.opener()
        .open_path(format!("http://127.0.0.1:{}", port), None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_agent_config() -> Result<daemon::config::AgentConfig, String> {
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");
    daemon::config::load_config(config_path)
}

#[tauri::command]
async fn save_agent_config(new_config: daemon::config::AgentConfig) -> Result<(), String> {
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");
    daemon::config::save_config(config_path, &new_config)
}

#[tauri::command]
async fn check_permissions() -> Result<PermissionsStatus, String> {
    platform::check_permissions()
}

/// Ground-truth capture health, independent of the cache-prone TCC preflight checks.
/// This is what actually tells the user whether telemetry is being captured.
#[tauri::command]
async fn get_capture_health(
    state: tauri::State<'_, Arc<daemon::daemon::TelemetryState>>,
) -> Result<CaptureHealth, String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let last_ms = state.last_input_event_ms.load(Ordering::Relaxed);
    let input_idle_ms = if last_ms == 0 { -1 } else { now_ms - last_ms };

    Ok(CaptureHealth {
        input_listener_alive: state.input_listener_alive.load(Ordering::Relaxed),
        // Consider input "recently seen" if an event arrived in the last 5 seconds.
        input_recently_seen: (0..=5_000).contains(&input_idle_ms),
        input_idle_ms,
        screen_capture_ok: state.screen_capture_ok.load(Ordering::Relaxed),
    })
}

#[tauri::command]
async fn open_accessibility_settings(app: tauri::AppHandle) -> Result<(), String> {
    platform::open_accessibility_settings(&app)
}

#[tauri::command]
async fn open_input_monitoring_settings(app: tauri::AppHandle) -> Result<(), String> {
    platform::open_input_monitoring_settings(&app)
}

#[tauri::command]
async fn open_screen_recording_settings(app: tauri::AppHandle) -> Result<(), String> {
    platform::open_screen_recording_settings(&app)
}

#[tauri::command]
async fn open_automation_settings(app: tauri::AppHandle) -> Result<(), String> {
    platform::open_automation_settings(&app)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 0. Ensure single instance per environment
    let app_home = daemon::env::get_app_home();
    let mut lock_path = app_home.clone();
    lock_path.push("tenby10.lock");

    // Ensure directory exists
    let _ = std::fs::create_dir_all(&app_home);

    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("Failed to open lock file");

    use fs2::FileExt;
    if lock_file.try_lock_exclusive().is_err() {
        eprintln!("[ERROR] Another instance of tenby10 is already running in this environment.");
        // In a real app, we might want to focus the existing window here,
        // but for now, we just exit to prevent database corruption.
        std::process::exit(1);
    }

    // Keep lock_file alive for the duration of the process
    // We can do this by leaking it or moving it into the Tauri state
    Box::leak(Box::new(lock_file));

    // Bootstrap the background telemetry daemon

    let mut db_path = app_home.clone();
    db_path.push("tenby10.db");

    println!("Tauri starting Telemetry Core Database at {:?}", db_path);
    let db =
        Arc::new(daemon::db::Database::new(db_path).expect("Failed to initialize SQLite database"));

    // Start local web server dashboard
    let mut config_path = app_home.clone();
    config_path.push("config.json");
    let config = daemon::config::load_config(config_path).unwrap_or_default();
    let port = daemon::env::get_app_port(&config);
    daemon::dashboard::start_dashboard_server(db.clone(), port);

    let state = Arc::new(daemon::daemon::TelemetryState::new());

    // Start global keyboard/mouse listeners
    daemon::daemon::start_input_listener(state.clone());

    // Start daemon loop in a background thread so Tauri doesn't block the UI!
    let daemon_state = state.clone();
    let db_for_daemon = db.clone();
    thread::spawn(move || {
        daemon::daemon::start_daemon_loop(db_for_daemon, daemon_state);
    });

    // Start Tauri GUI app
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state.clone())
        .manage(db.clone())
        .invoke_handler(tauri::generate_handler![
            enroll_agent,
            toggle_tracking,
            get_agent_status,
            get_today_metrics,
            open_dashboard,
            get_agent_config,
            save_agent_config,
            check_permissions,
            get_capture_health,
            open_accessibility_settings,
            open_input_monitoring_settings,
            open_screen_recording_settings,
            open_automation_settings
        ])
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            // When the OS window regains focus, tell the frontend to refresh. The
            // WebView's setInterval is throttled by macOS App Nap while the window is
            // backgrounded, so metrics freeze until it is looked at again. This native
            // focus signal fires reliably where the DOM `window` focus event does not.
            tauri::WindowEvent::Focused(true) => {
                let _ = window.emit("window-focused", ());
            }
            _ => {}
        })
        .setup(|app| {
            let active_icon_bytes = include_bytes!("../icons/128x128.png").as_slice();

            let active_icon =
                tauri::image::Image::from_bytes(active_icon_bytes).expect("Failed to create icon");

            let tray_icon_bytes = include_bytes!("../icons/32x32.png").as_slice();
            let tray_icon = tauri::image::Image::from_bytes(tray_icon_bytes)
                .expect("Failed to create tray icon");

            let _paused_icon =
                tauri::image::Image::from_bytes(include_bytes!("../icons/32x32_paused.png"))
                    .expect("Failed to create paused icon");

            if daemon::env::is_dev() {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.set_title("tenby10 (Dev)");
                    let _ = window.set_icon(active_icon.clone());
                }
            }
            let title_suffix = if daemon::env::is_dev() { " (Dev)" } else { "" };
            let exit_suffix = if daemon::env::is_dev() { " (Dev)" } else { "" };

            let toggle_item = tauri::menu::MenuItem::with_id(
                app,
                "toggle_tracking",
                "Pause Tracking",
                true,
                None::<&str>,
            )?;
            let show_item = tauri::menu::MenuItem::with_id(
                app,
                "show_window",
                format!("Show Dashboard{}", title_suffix),
                true,
                None::<&str>,
            )?;
            let exit_item = tauri::menu::MenuItem::with_id(
                app,
                "exit",
                format!("Exit tenby10{}", exit_suffix),
                true,
                None::<&str>,
            )?;

            let tray_menu = tauri::menu::Menu::with_items(
                app,
                &[
                    &toggle_item,
                    &show_item,
                    &tauri::menu::PredefinedMenuItem::separator(app)?,
                    &exit_item,
                ],
            )?;

            app.manage(TrayState {
                toggle_item: toggle_item.clone(),
            });

            let _tray = tauri::tray::TrayIconBuilder::with_id("main_tray")
                .icon(tray_icon.clone())
                .menu(&tray_menu)
                .show_menu_on_left_click(true)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "toggle_tracking" => {
                        let _ = perform_toggle_tracking(app);
                    }
                    "show_window" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "exit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
