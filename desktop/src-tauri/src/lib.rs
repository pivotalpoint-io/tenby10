use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use tauri::{Emitter, Manager};

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
    /// Window titles are coming back with real values. On macOS a withheld Screen
    /// Recording grant blanks them (`kCGWindowName`), which no TCC preflight reports.
    window_titles_ok: bool,
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
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");

    // 1. Reuse the device's existing keypair on re-pair (first pair generates one). Rotating the
    //    key would orphan slots already signed under the old key, since the cloud validates
    //    signatures against the agent's registered key.
    let mut config = daemon::config::config_for_enrollment(config_path.clone(), &token);

    // 2. Exchange the token + public key for the cloud agent id.
    let base = daemon::sync::cloud_base_url();
    let agent_id = daemon::sync::enroll_with_cloud(&base, &token, &config.public_key).await?;
    config.agent_id = agent_id;

    // 3. Save config locally in ~/.tenby10/config.json.
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

/// Resize the main window when entering/leaving the in-window activity dashboard.
/// The dashboard renders as a view *inside* the existing window (no browser, no
/// second OS window); it just needs more room than the compact metrics home. When
/// `expand` is true the window grows to fit the 24×6 slot grid; on exit it snaps
/// back to the compact size and re-centers.
#[tauri::command]
async fn set_dashboard_mode(app: tauri::AppHandle, expand: bool) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let size = if expand {
            tauri::LogicalSize::new(1200.0, 840.0)
        } else {
            tauri::LogicalSize::new(800.0, 600.0)
        };
        window
            .set_size(tauri::Size::Logical(size))
            .map_err(|e| e.to_string())?;
        let _ = window.center();
    }
    Ok(())
}

/// Recent slot summaries for the dashboard (newest first).
#[tauri::command]
async fn dashboard_slots(
    db: tauri::State<'_, Arc<daemon::db::Database>>,
) -> Result<Vec<daemon::db::SlotSummaryView>, String> {
    let db_clone = db.inner().clone();
    tokio::task::spawn_blocking(move || db_clone.get_recent_slot_summaries(1000))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Database error: {}", e))
}

/// Slot windows that have raw minute logs but no aggregated summary yet
/// (i.e. the slot is still in progress / pending evaluation).
#[tauri::command]
async fn dashboard_pending_slots(
    db: tauri::State<'_, Arc<daemon::db::Database>>,
) -> Result<Vec<i64>, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let current_slot_start = now - (now % 600);

    let db_clone = db.inner().clone();
    tokio::task::spawn_blocking(move || db_clone.get_unaggregated_slots(current_slot_start))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Database error: {}", e))
}

/// The daily work notes (ADR 0019) covering `[from, to)`, latest revision per day,
/// withdrawn days omitted. Empty when the user has no AI configured — the dashboard
/// renders that as an invitation rather than an error.
#[tauri::command]
async fn dashboard_work_notes(
    db: tauri::State<'_, Arc<daemon::db::Database>>,
    from: i64,
    to: i64,
) -> Result<Vec<daemon::db::WorkSummary>, String> {
    let db_clone = db.inner().clone();
    tokio::task::spawn_blocking(move || db_clone.get_work_summaries(from, to))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Database error: {}", e))
}

/// Whether note generation is live right now: the user's own AI is configured and
/// notes are not opted out. Drives the dashboard's empty state, so the invitation
/// only appears to people who would actually gain something by acting on it.
#[tauri::command]
async fn work_notes_enabled() -> Result<bool, String> {
    let mut config_path = daemon::env::get_app_home();
    config_path.push("config.json");
    let config = daemon::config::load_config(config_path).unwrap_or_default();
    Ok(!config.disable_work_summaries && daemon::llm::get_llm_provider(&config).is_some())
}

/// Classified minute-by-minute activity for a single 10-minute slot.
#[tauri::command]
async fn dashboard_slot_details(
    db: tauri::State<'_, Arc<daemon::db::Database>>,
    start: i64,
) -> Result<Vec<daemon::db::SlotMinuteDetailView>, String> {
    let db_clone = db.inner().clone();
    tokio::task::spawn_blocking(move || db_clone.get_slot_minute_details(start))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Database error: {}", e))
}

/// Export minute logs as CSV via a native save dialog. Returns the saved path,
/// or `None` if the user cancelled the dialog.
#[tauri::command]
async fn export_dashboard_csv(
    app: tauri::AppHandle,
    db: tauri::State<'_, Arc<daemon::db::Database>>,
    range: String,
    start: Option<i64>,
    end: Option<i64>,
) -> Result<Option<String>, String> {
    let range_for_name = range.clone();
    let db_clone = db.inner().clone();
    let csv =
        tokio::task::spawn_blocking(move || db_clone.export_minute_logs_csv(&range, start, end))
            .await
            .map_err(|e| format!("Task join error: {}", e))?
            .map_err(|e| format!("Database error: {}", e))?;

    use tauri_plugin_dialog::DialogExt;
    let file_path = app
        .dialog()
        .file()
        .add_filter("CSV", &["csv"])
        .set_file_name(format!("tenby10_logs_{}.csv", range_for_name))
        .blocking_save_file();

    let Some(file_path) = file_path else {
        // User cancelled the save dialog.
        return Ok(None);
    };

    let path = file_path.into_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, csv).map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().to_string()))
}

#[tauri::command]
async fn get_agent_config() -> Result<daemon::config::AgentConfig, String> {
    let app_home = daemon::env::get_app_home();
    let mut config_path = app_home.clone();
    config_path.push("config.json");
    daemon::config::load_config(config_path)
}

/// The endpoint and model each provider actually calls when the user leaves
/// those settings blank. The UI reads them from here rather than carrying its
/// own copy, so the form can never advertise a model the daemon doesn't use.
#[derive(serde::Serialize)]
struct LlmProviderDefaults {
    provider: String,
    base_url: String,
    model: String,
}

#[tauri::command]
async fn get_llm_provider_defaults() -> Result<Vec<LlmProviderDefaults>, String> {
    Ok(["openai", "anthropic", "gemini"]
        .iter()
        .filter_map(|provider| {
            daemon::llm::provider_defaults(provider).map(|(base_url, model)| LlmProviderDefaults {
                provider: provider.to_string(),
                base_url: base_url.to_string(),
                model: model.to_string(),
            })
        })
        .collect())
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

    // Re-derive title health from a fresh window read rather than trusting the
    // cache-prone TCC preflight (issue #6). Reads window metadata only — no pixels
    // are captured anywhere in this process (ADR 0018). Internally throttled, so
    // polling every 10s is cheap; still off the UI thread as it touches the OS.
    let probe_state = state.inner().clone();
    let window_titles_ok =
        tauri::async_runtime::spawn_blocking(move || probe_state.refresh_window_title_health())
            .await
            .map_err(|err| format!("Window title health probe failed to run: {}", err))?;

    Ok(CaptureHealth {
        input_listener_alive: state.input_listener_alive.load(Ordering::Relaxed),
        // Consider input "recently seen" if an event arrived in the last 5 seconds.
        input_recently_seen: (0..=5_000).contains(&input_idle_ms),
        input_idle_ms,
        window_titles_ok,
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

    // No local HTTP server is started here (#40). The activity dashboard renders
    // inside the app window from `#[tauri::command]` IPC, so the Axum server no
    // longer backs any view — leaving it running would keep a loopback port open
    // that nothing consumes. The standalone `daemon` binary can still opt into it
    // for triage; see `daemon::dashboard::start_dashboard_server`.

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
        .plugin(tauri_plugin_dialog::init())
        .manage(state.clone())
        .manage(db.clone())
        .invoke_handler(tauri::generate_handler![
            enroll_agent,
            toggle_tracking,
            get_agent_status,
            get_today_metrics,
            set_dashboard_mode,
            dashboard_slots,
            dashboard_pending_slots,
            dashboard_slot_details,
            dashboard_work_notes,
            work_notes_enabled,
            export_dashboard_csv,
            get_agent_config,
            save_agent_config,
            get_llm_provider_defaults,
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
