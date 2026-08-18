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

/// Compact "home" size, in logical pixels. Must stay in step with the window
/// defaults *and* the `minWidth`/`minHeight` in `tauri.conf.json`.
const COMPACT_SIZE: (f64, f64) = (800.0, 600.0);
/// Preferred dashboard size, in logical pixels — enough for the 24×6 slot grid.
const DASHBOARD_SIZE: (f64, f64) = (1200.0, 840.0);
/// Breathing room kept between the window and the edges of the monitor work area,
/// so the expanded dashboard never looks wedged against the Dock or a screen edge.
const SCREEN_MARGIN: f64 = 24.0;

/// UI-only window preferences. Deliberately its own file rather than another field on
/// `config.json`, which belongs to the daemon and is read on the sync path.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct WindowPreferences {
    /// Preferred dashboard size in logical pixels, as the user last left it.
    #[serde(default)]
    dashboard: Option<(f64, f64)>,
}

fn window_preferences_path() -> std::path::PathBuf {
    let mut path = daemon::env::get_app_home();
    path.push("window.json");
    path
}

fn load_preferred_dashboard_size() -> Option<(f64, f64)> {
    let raw = std::fs::read_to_string(window_preferences_path()).ok()?;
    serde_json::from_str::<WindowPreferences>(&raw)
        .ok()?
        .dashboard
}

/// Best effort on purpose: a window preference is not worth failing navigation over,
/// and the built-in default is a perfectly good fallback.
fn save_preferred_dashboard_size(size: (f64, f64)) {
    if let Ok(raw) = serde_json::to_string_pretty(&WindowPreferences {
        dashboard: Some(size),
    }) {
        let _ = std::fs::write(window_preferences_path(), raw);
    }
}

#[derive(Default)]
struct DashboardWindowInner {
    /// Where the compact window sat before the dashboard expanded it, so leaving the
    /// dashboard puts it back exactly where the user had it.
    compact: Option<(tauri::PhysicalPosition<i32>, tauri::PhysicalSize<u32>)>,
    /// The inner size `resize_and_center` actually applied on the way in. Leaving the
    /// dashboard only records a new preference when the size differs from this —
    /// otherwise a size we clamped to fit a small screen would come back as the user's
    /// stated preference on every screen after it.
    applied: Option<tauri::PhysicalSize<u32>>,
    /// Preferred dashboard size in logical pixels, mirrored from `window.json`.
    preferred: Option<(f64, f64)>,
    /// Whether `preferred` has been read from disk yet this run.
    loaded: bool,
}

#[derive(Default)]
struct DashboardWindow(std::sync::Mutex<DashboardWindowInner>);

impl DashboardWindow {
    /// Poison-tolerant: a panic elsewhere should not permanently wedge navigation.
    fn lock(&self) -> std::sync::MutexGuard<'_, DashboardWindowInner> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Work out the inner size and outer position for a `target`-logical-pixel window
/// centred on a monitor work area. Pure geometry, all physical pixels, in tauri's
/// top-left-origin screen space — split out from `resize_and_center` so the unit
/// conversions and clamps can be tested without a live window.
///
/// The work area already excludes the menu bar and Dock, so clamping to it is what
/// keeps a 1200×840 dashboard usable on a 1280×800 display. `chrome` is the title
/// bar / frame thickness: `set_size` speaks inner size but `set_position` speaks
/// outer position, so it is the outer rect that has to be fitted and centred.
fn fit_centered(
    target: (f64, f64),
    scale: f64,
    chrome: (u32, u32),
    area_position: (i32, i32),
    area_size: (u32, u32),
) -> ((u32, u32), (i32, i32)) {
    let to_physical = |logical: f64| (logical * scale).round() as u32;
    let margin = to_physical(SCREEN_MARGIN) * 2;

    let available_w = area_size.0.saturating_sub(margin + chrome.0);
    let available_h = area_size.1.saturating_sub(margin + chrome.1);

    // Never go under the window's own minimum: the OS would refuse the shrink and the
    // centring maths would then be based on a size the window never actually took.
    let width = to_physical(target.0)
        .min(available_w)
        .max(to_physical(COMPACT_SIZE.0));
    let height = to_physical(target.1)
        .min(available_h)
        .max(to_physical(COMPACT_SIZE.1));

    let outer_w = (width + chrome.0) as i32;
    let outer_h = (height + chrome.1) as i32;
    let position = (
        area_position.0 + (area_size.0 as i32 - outer_w) / 2,
        area_position.1 + (area_size.1 as i32 - outer_h) / 2,
    );

    ((width, height), position)
}

/// Resize `window` to `target` logical pixels and centre it on the work area of the
/// monitor it is currently on.
///
/// The placement is computed here rather than delegated to `WebviewWindow::center`
/// on purpose. On macOS that call lands on `NSWindow.center`, which runs straight
/// away on the main thread while tao applies `set_size` *asynchronously* on the main
/// dispatch queue. So the window gets centred at its old size and only then grows —
/// and because `setContentSize:` pins the frame's bottom-left corner, it expands up
/// and to the right, ending up off-centre and often under the menu bar. (`NSWindow`
/// also centres above the vertical middle by design.) Issuing `set_size` and
/// `set_position` back to back keeps both on that same queue, in order, so the window
/// lands where we asked for it.
fn resize_and_center(
    window: &tauri::WebviewWindow,
    target: (f64, f64),
) -> Result<tauri::PhysicalSize<u32>, String> {
    let outer = window.outer_size().map_err(|e| e.to_string())?;
    let inner = window.inner_size().map_err(|e| e.to_string())?;
    let chrome = (
        outer.width.saturating_sub(inner.width),
        outer.height.saturating_sub(inner.height),
    );

    // `current_monitor` is what makes this behave on a multi-monitor desk: the window
    // expands on the screen it is already on, not always the primary.
    let monitor = window
        .current_monitor()
        .map_err(|e| e.to_string())?
        .or(window.primary_monitor().map_err(|e| e.to_string())?);

    let Some(monitor) = monitor else {
        // No monitor to fit against (headless / hot-unplugged): take the size as asked
        // and leave the window where it is rather than guessing at a position.
        let scale = window.scale_factor().map_err(|e| e.to_string())?;
        let size = tauri::PhysicalSize::new(
            (target.0 * scale).round() as u32,
            (target.1 * scale).round() as u32,
        );
        window
            .set_size(tauri::Size::Physical(size))
            .map_err(|e| e.to_string())?;
        return Ok(size);
    };

    let area = monitor.work_area();
    let ((width, height), (x, y)) = fit_centered(
        target,
        monitor.scale_factor(),
        chrome,
        (area.position.x, area.position.y),
        (area.size.width, area.size.height),
    );

    let size = tauri::PhysicalSize::new(width, height);
    window
        .set_size(tauri::Size::Physical(size))
        .map_err(|e| e.to_string())?;
    window
        .set_position(tauri::Position::Physical(tauri::PhysicalPosition::new(
            x, y,
        )))
        .map_err(|e| e.to_string())?;

    Ok(size)
}

/// Resize the main window when entering/leaving the in-window activity dashboard.
/// The dashboard renders as a view *inside* the existing window (no browser, no
/// second OS window); it just needs more room than the compact metrics home.
///
/// Entering expands to the user's preferred dashboard size — or the built-in default
/// the first time — clamped to the screen and centred. Leaving puts the window back
/// exactly where the compact view was, and records the dashboard size if the user
/// resized it by hand.
#[tauri::command]
async fn set_dashboard_mode(
    app: tauri::AppHandle,
    dashboard_window: tauri::State<'_, DashboardWindow>,
    expand: bool,
) -> Result<(), String> {
    let Some(window) = app.get_webview_window("main") else {
        return Ok(());
    };

    if expand {
        let target = {
            let mut state = dashboard_window.lock();
            if !state.loaded {
                state.preferred = load_preferred_dashboard_size();
                state.loaded = true;
            }
            if let (Ok(position), Ok(size)) = (window.outer_position(), window.inner_size()) {
                state.compact = Some((position, size));
            }
            state.preferred.unwrap_or(DASHBOARD_SIZE)
        };

        let applied = resize_and_center(&window, target)?;
        dashboard_window.lock().applied = Some(applied);
    } else {
        let (compact, applied) = {
            let mut state = dashboard_window.lock();
            (state.compact.take(), state.applied.take())
        };

        remember_hand_resize(&window, &dashboard_window, applied);

        match compact {
            // Same ordering rule as `resize_and_center`: size first, then position.
            Some((position, size)) => {
                window
                    .set_size(tauri::Size::Physical(size))
                    .map_err(|e| e.to_string())?;
                window
                    .set_position(tauri::Position::Physical(position))
                    .map_err(|e| e.to_string())?;
            }
            None => {
                resize_and_center(&window, COMPACT_SIZE)?;
            }
        }
    }

    Ok(())
}

/// Persist the dashboard size if the user dragged the window to a size of their own.
///
/// Comparing against `applied` — what `resize_and_center` actually set on the way in —
/// rather than against the default is the point: on a screen too small for the
/// preferred size we hand the window a clamped size, and saving *that* would quietly
/// shrink the dashboard everywhere from then on. A couple of pixels of slack absorbs
/// rounding through the logical/physical conversion.
fn remember_hand_resize(
    window: &tauri::WebviewWindow,
    dashboard_window: &DashboardWindow,
    applied: Option<tauri::PhysicalSize<u32>>,
) {
    let (Some(applied), Ok(current), Ok(scale)) =
        (applied, window.inner_size(), window.scale_factor())
    else {
        return;
    };

    let resized =
        applied.width.abs_diff(current.width) > 2 || applied.height.abs_diff(current.height) > 2;
    if !resized {
        return;
    }

    let preferred = (
        (current.width as f64 / scale).round(),
        (current.height as f64 / scale).round(),
    );

    let mut state = dashboard_window.lock();
    if state.preferred != Some(preferred) {
        state.preferred = Some(preferred);
        save_preferred_dashboard_size(preferred);
    }
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

/// How long a prompt may be before it can no longer be synced. The form reads it from
/// here rather than carrying its own copy, so the length it enforces can never drift from
/// the length `save_config` accepts.
#[tauri::command]
async fn get_max_prompt_bytes() -> Result<usize, String> {
    Ok(daemon::config::MAX_PROMPT_BYTES)
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
        .manage(DashboardWindow::default())
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
            get_max_prompt_bytes,
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

#[cfg(test)]
mod window_geometry_tests {
    use super::{fit_centered, COMPACT_SIZE, DASHBOARD_SIZE, SCREEN_MARGIN};

    /// Title bar thickness in physical pixels for a given scale factor.
    fn chrome(scale: f64) -> (u32, u32) {
        (0, (28.0 * scale) as u32)
    }

    /// The outer window must land fully inside the work area, and the gaps left and
    /// right (top and bottom) must match — that is what "centred" has to mean here.
    fn assert_centered_inside(
        (width, height): (u32, u32),
        (x, y): (i32, i32),
        chrome: (u32, u32),
        area_position: (i32, i32),
        area_size: (u32, u32),
    ) {
        let outer_w = (width + chrome.0) as i32;
        let outer_h = (height + chrome.1) as i32;

        let left = x - area_position.0;
        let right = (area_position.0 + area_size.0 as i32) - (x + outer_w);
        let top = y - area_position.1;
        let bottom = (area_position.1 + area_size.1 as i32) - (y + outer_h);

        assert!(
            left >= 0 && right >= 0,
            "overflows horizontally: {left}/{right}"
        );
        assert!(
            top >= 0 && bottom >= 0,
            "overflows vertically: {top}/{bottom}"
        );
        // Odd leftovers make one side a pixel wider; anything more is not centred.
        assert!(
            (left - right).abs() <= 1,
            "off-centre horizontally: {left}/{right}"
        );
        assert!(
            (top - bottom).abs() <= 1,
            "off-centre vertically: {top}/{bottom}"
        );
    }

    /// 14" MacBook Pro, 1512×982 logical at 2x, menu bar taken off the top. The
    /// dashboard fits at its full preferred size and sits dead centre.
    #[test]
    fn retina_laptop_keeps_the_preferred_size() {
        let area_position = (0, 74); // menu bar, physical
        let area_size = (3024, 1890);
        let (size, position) =
            fit_centered(DASHBOARD_SIZE, 2.0, chrome(2.0), area_position, area_size);

        assert_eq!(size, (2400, 1680), "1200x840 logical at 2x");
        assert_centered_inside(size, position, chrome(2.0), area_position, area_size);
    }

    /// 1280×800 at 1x — the case the old code got wrong. 840 points tall plus a title
    /// bar does not fit under the menu bar, so the height has to give.
    #[test]
    fn short_screen_clamps_height_instead_of_overflowing() {
        let area_position = (0, 25);
        let area_size = (1280, 775);
        let (size, position) =
            fit_centered(DASHBOARD_SIZE, 1.0, chrome(1.0), area_position, area_size);

        assert!(
            size.1 < DASHBOARD_SIZE.1 as u32,
            "height should be clamped, got {}",
            size.1
        );
        assert_eq!(size.0, DASHBOARD_SIZE.0 as u32, "width still fits");
        assert_centered_inside(size, position, chrome(1.0), area_position, area_size);

        // The margin is honoured, not eaten, when clamping.
        let gap = position.1 - area_position.1;
        assert!(gap >= SCREEN_MARGIN as i32, "margin collapsed: {gap}");
    }

    /// A work area too small even for the compact window: the clamp must not drive the
    /// request below `minWidth`/`minHeight`, which the OS would refuse anyway — that
    /// would leave the centring maths based on a size the window never took.
    #[test]
    fn never_requests_less_than_the_window_minimum() {
        let (size, _) = fit_centered(DASHBOARD_SIZE, 1.0, chrome(1.0), (0, 0), (700, 500));

        assert_eq!(size.0, COMPACT_SIZE.0 as u32);
        assert_eq!(size.1, COMPACT_SIZE.1 as u32);
    }

    /// Each axis clamps on its own: a wide-but-short work area gives up height only.
    #[test]
    fn clamps_each_axis_independently() {
        let (size, _) = fit_centered(DASHBOARD_SIZE, 1.0, chrome(1.0), (0, 0), (900, 640));

        assert_eq!(
            size.0, 852,
            "width follows the work area, still above the minimum"
        );
        assert_eq!(
            size.1, COMPACT_SIZE.1 as u32,
            "height bottoms out at the minimum"
        );
    }

    /// A monitor to the left of the primary has a negative origin. The window has to
    /// follow the work area rather than centring on the global origin.
    #[test]
    fn centers_on_a_secondary_monitor_with_negative_origin() {
        let area_position = (-2560, -140);
        let area_size = (2560, 1400);
        let (size, position) =
            fit_centered(DASHBOARD_SIZE, 1.0, chrome(1.0), area_position, area_size);

        assert!(
            position.0 < 0,
            "should stay on the left-hand monitor, got x={}",
            position.0
        );
        assert_centered_inside(size, position, chrome(1.0), area_position, area_size);
    }

    /// A remembered size from a roomier monitor must still be fitted to the screen the
    /// window is actually on, rather than reopening off the bottom of it.
    #[test]
    fn remembered_size_larger_than_the_screen_is_clamped() {
        let area_position = (0, 25);
        let area_size = (1440, 875);
        let remembered = (1900.0, 1200.0);
        let (size, position) = fit_centered(remembered, 1.0, chrome(1.0), area_position, area_size);

        assert!(size.0 < remembered.0 as u32 && size.1 < remembered.1 as u32);
        assert_centered_inside(size, position, chrome(1.0), area_position, area_size);
    }

    /// `window.json` is written by us but read back after upgrades, so it has to
    /// survive a missing field rather than throwing the preference away on a parse
    /// error and silently reverting to the default.
    #[test]
    fn window_preferences_round_trip() {
        let raw = serde_json::to_string(&super::WindowPreferences {
            dashboard: Some((1400.0, 900.0)),
        })
        .expect("serialises");
        let parsed: super::WindowPreferences = serde_json::from_str(&raw).expect("parses");
        assert_eq!(parsed.dashboard, Some((1400.0, 900.0)));

        let empty: super::WindowPreferences = serde_json::from_str("{}").expect("parses empty");
        assert_eq!(empty.dashboard, None);
    }

    /// Collapsing back to the compact size is the same computation, so it centres too.
    #[test]
    fn compact_size_is_centered_as_well() {
        let area_position = (0, 74);
        let area_size = (3024, 1890);
        let (size, position) =
            fit_centered(COMPACT_SIZE, 2.0, chrome(2.0), area_position, area_size);

        assert_eq!(size, (1600, 1200));
        assert_centered_inside(size, position, chrome(2.0), area_position, area_size);
    }
}
