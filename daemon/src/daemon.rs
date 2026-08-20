use crate::db::Database;
use std::collections::HashMap;

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Shared telemetry state for capturing inputs.
pub struct TelemetryState {
    pub keystroke_count: AtomicU32,
    pub mouse_click_count: AtomicU32,
    pub scroll_event_count: AtomicU32,
    pub mouse_distance: Mutex<f64>,
    pub last_mouse_pos: Mutex<Option<(f64, f64)>>,
    // For entropy analysis (Milestone 2)
    pub mouse_positions: Mutex<Vec<(f64, f64, i64)>>, // (x, y, timestamp_ms)
    pub keystroke_intervals: Mutex<Vec<i64>>,         // timing intervals in ms
    pub last_keystroke_time: Mutex<Option<Instant>>,
    pub tracking_enabled: AtomicBool,
    /// Ground-truth capture health (see [`crate`] docs / issue #61).
    /// True while the rdev input event tap is alive; set false if `listen` errors out.
    pub input_listener_alive: AtomicBool,
    /// Unix-ms timestamp of the last input event actually observed (0 = none yet).
    pub last_input_event_ms: AtomicI64,
    /// Whether window titles are actually readable right now (ADR 0018).
    ///
    /// On macOS `kCGWindowName` is silently withheld when Screen Recording is not
    /// granted, so titles arrive empty while the app name still resolves — the
    /// telemetry looks alive but every title is blank. This flag is derived from
    /// the real title stream, not from a TCC preflight (which caches a stale
    /// `true` after a revocation, issue #6).
    pub window_titles_ok: AtomicBool,
    /// Consecutive observations where a frontmost app was identified but its title
    /// came back empty. A single blank title is normal (some windows have none);
    /// a run of them is the redaction fingerprint. See [`TITLE_UNREADABLE_STRIKES`].
    pub empty_title_streak: AtomicU32,
    /// Unix-ms timestamp of the last title-readability observation (0 = none yet).
    /// Throttles [`TelemetryState::refresh_window_title_health`].
    pub last_title_check_ms: AtomicI64,
}

/// Rolling anti-automation window sizes (ADR 0002 addendum). Anti-automation
/// heuristics need to see across minutes to spot low-rate periodicity, so the
/// interval/position buffers are NOT cleared each minute — they keep the most
/// recent N samples and bound memory by trimming the oldest.
const KEY_INTERVAL_WINDOW: usize = 256;
const MOUSE_POSITION_WINDOW: usize = 512;

/// Minimum gap between title-readability probes. The settings UI polls capture
/// health every 10s; a probe is one cheap window-metadata read (no pixels), so
/// this simply avoids doing it on every poll.
const TITLE_PROBE_MIN_GAP_MS: i64 = 10_000;

/// Consecutive blank-title observations before titles are reported unreadable.
/// A single blank title is legitimate (some windows genuinely have none), but
/// under a withheld Screen Recording grant *every* title is blank, so a short
/// run separates the two without false-alarming on one odd window.
const TITLE_UNREADABLE_STRIKES: u32 = 3;

/// Whether a fresh title probe is due. Split out from the probe itself so the
/// throttle is unit-testable without a window server.
fn title_probe_due(last_check_ms: i64, now_ms: i64) -> bool {
    // Never checked yet, or the clock jumped backwards (sleep/timezone) — probe.
    last_check_ms == 0 || now_ms < last_check_ms || now_ms - last_check_ms >= TITLE_PROBE_MIN_GAP_MS
}

/// Current wall-clock time in Unix milliseconds.
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Keep only the most recent `max` elements of `v`, dropping the oldest.
fn trim_front<T>(v: &mut Vec<T>, max: usize) {
    if v.len() > max {
        let excess = v.len() - max;
        v.drain(0..excess);
    }
}

impl Default for TelemetryState {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryState {
    pub fn new() -> Self {
        TelemetryState {
            keystroke_count: AtomicU32::new(0),
            mouse_click_count: AtomicU32::new(0),
            scroll_event_count: AtomicU32::new(0),
            mouse_distance: Mutex::new(0.0),
            last_mouse_pos: Mutex::new(None),
            mouse_positions: Mutex::new(Vec::new()),
            keystroke_intervals: Mutex::new(Vec::new()),
            last_keystroke_time: Mutex::new(None),
            tracking_enabled: AtomicBool::new(true),
            // Start pessimistic: only flip true once the tap / capture actually works.
            input_listener_alive: AtomicBool::new(false),
            last_input_event_ms: AtomicI64::new(0),
            // Optimistic: titles are readable everywhere except a macOS machine
            // with the grant withheld, and the first observation lands seconds
            // after start — starting false would flash a false alarm every launch.
            window_titles_ok: AtomicBool::new(true),
            empty_title_streak: AtomicU32::new(0),
            last_title_check_ms: AtomicI64::new(0),
        }
    }

    /// Fold one title observation into the health signal.
    ///
    /// `identified_app` is false when no frontmost window could be read at all
    /// (an empty desktop, a fullscreen space in transition) — that says nothing
    /// about permissions, so it neither scores a strike nor clears the streak.
    pub fn record_title_observation(&self, identified_app: bool, title_present: bool, now_ms: i64) {
        self.last_title_check_ms.store(now_ms, Ordering::Relaxed);
        if !identified_app {
            return;
        }
        if title_present {
            self.empty_title_streak.store(0, Ordering::Relaxed);
            self.window_titles_ok.store(true, Ordering::Relaxed);
            return;
        }
        let streak = self.empty_title_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if streak >= TITLE_UNREADABLE_STRIKES {
            self.window_titles_ok.store(false, Ordering::Relaxed);
        }
    }

    /// Re-derive title-readability from a fresh window read, throttled to at most
    /// one probe per [`TITLE_PROBE_MIN_GAP_MS`]. Returns the freshest value known.
    ///
    /// Reads window metadata only — no pixels are captured anywhere in this
    /// process (ADR 0018). This is the ground-truth replacement for the old screen
    /// capture probe: it measures the thing the product actually consumes.
    pub fn refresh_window_title_health(&self) -> bool {
        let now_ms = now_unix_ms();
        if !title_probe_due(self.last_title_check_ms.load(Ordering::Relaxed), now_ms) {
            return self.window_titles_ok.load(Ordering::Relaxed);
        }
        let (identified_app, title_present) = probe_active_window_title();
        self.record_title_observation(identified_app, title_present, now_ms);
        self.window_titles_ok.load(Ordering::Relaxed)
    }

    /// Reset the per-minute counters for the next minute slot. The rolling
    /// anti-automation buffers (`mouse_positions`, `keystroke_intervals`)
    /// intentionally persist across minutes — see [`Self::clear_entropy_window`].
    pub fn reset_minute(&self) {
        self.keystroke_count.store(0, Ordering::Relaxed);
        self.mouse_click_count.store(0, Ordering::Relaxed);
        self.scroll_event_count.store(0, Ordering::Relaxed);
        *self.mouse_distance.lock().unwrap() = 0.0;
    }

    /// Record an inter-key interval into the rolling anti-automation window.
    fn record_key_interval(&self, delta_ms: i64) {
        let mut buf = self.keystroke_intervals.lock().unwrap();
        buf.push(delta_ms);
        trim_front(&mut buf, KEY_INTERVAL_WINDOW);
    }

    /// Record a cursor position into the rolling anti-automation window.
    fn record_mouse_position(&self, x: f64, y: f64, ts_ms: i64) {
        let mut buf = self.mouse_positions.lock().unwrap();
        buf.push((x, y, ts_ms));
        trim_front(&mut buf, MOUSE_POSITION_WINDOW);
    }

    /// Drop the rolling anti-automation history. Called when tracking is paused
    /// or the machine is locked/asleep so a resume starts from a clean window
    /// rather than stitching pre-gap samples to post-gap ones.
    pub fn clear_entropy_window(&self) {
        self.mouse_positions.lock().unwrap().clear();
        self.keystroke_intervals.lock().unwrap().clear();
    }
}

/// Query the active application name and window title.
pub fn get_active_window() -> (String, String) {
    let (app, title, _) = read_active_window();
    (app, title)
}

/// Read the frontmost window, returning `(app_name, title, raw_title_present)`.
///
/// The third element is the health signal that the app-name fallback below would
/// otherwise hide: on macOS a withheld Screen Recording grant makes
/// `kCGWindowName` come back empty while `kCGWindowOwnerName` still resolves, so
/// "we identified the app but got no title" is the fingerprint of redacted
/// titles rather than of a genuinely untitled window.
fn read_active_window() -> (String, String, bool) {
    match active_win_pos_rs::get_active_window() {
        Ok(window) => {
            let raw_title_present = !window.title.trim().is_empty();
            let app_name = if window.app_name.trim().is_empty() {
                "Unknown".to_string()
            } else {
                window.app_name
            };
            let title = if raw_title_present {
                window.title
            } else {
                app_name.clone() // Fallback to app name if title is empty
            };
            (app_name, title, raw_title_present)
        }
        Err(_) => ("Unknown".to_string(), "Unknown".to_string(), false),
    }
}

/// One title-readability observation: `(identified_app, title_present)`.
/// Window metadata only — nothing is captured or stored.
fn probe_active_window_title() -> (bool, bool) {
    let (app, _, raw_title_present) = read_active_window();
    (app != "Unknown", raw_title_present)
}

/// Start the global input event listener thread using rdev.
pub fn start_input_listener(state: Arc<TelemetryState>) {
    thread::spawn(move || {
        // Kept alive for the error path below; `state` itself is moved into the callback.
        let listener_state = state.clone();
        let callback = move |event: rdev::Event| {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;

            // Ground-truth signal: we received a real OS input event, so the tap is
            // genuinely alive and Input Monitoring is granted — regardless of what the
            // TCC preflight checks report. Record this even while tracking is paused.
            state.last_input_event_ms.store(now_ms, Ordering::Relaxed);
            state.input_listener_alive.store(true, Ordering::Relaxed);

            if !state.tracking_enabled.load(Ordering::Relaxed) {
                return;
            }

            match event.event_type {
                rdev::EventType::KeyPress(_) => {
                    state.keystroke_count.fetch_add(1, Ordering::Relaxed);

                    let mut last_time_opt = state.last_keystroke_time.lock().unwrap();
                    let now_inst = Instant::now();
                    if let Some(last_time) = *last_time_opt {
                        let delta = now_inst.duration_since(last_time).as_millis() as i64;
                        state.record_key_interval(delta);
                    }
                    *last_time_opt = Some(now_inst);
                }
                rdev::EventType::ButtonPress(_) => {
                    state.mouse_click_count.fetch_add(1, Ordering::Relaxed);
                }
                rdev::EventType::Wheel { .. } => {
                    state.scroll_event_count.fetch_add(1, Ordering::Relaxed);
                }
                rdev::EventType::MouseMove { x, y } => {
                    let mut last_pos_opt = state.last_mouse_pos.lock().unwrap();
                    if let Some((lx, ly)) = *last_pos_opt {
                        let dx = x - lx;
                        let dy = y - ly;
                        let dist = (dx * dx + dy * dy).sqrt();

                        let mut m_dist = state.mouse_distance.lock().unwrap();
                        *m_dist += dist;
                    }
                    *last_pos_opt = Some((x, y));

                    state.record_mouse_position(x, y, now_ms);
                }
                _ => {}
            }
        };

        // rdev::listen blocks on the CFRunLoop and only returns if the event tap
        // could not be created — which on macOS almost always means Input Monitoring
        // (kTCCServiceListenEvent) is NOT granted. Surface that as a hard health signal
        // instead of swallowing it into invisible GUI stderr.
        if let Err(error) = rdev::listen(callback) {
            listener_state
                .input_listener_alive
                .store(false, Ordering::Relaxed);
            eprintln!(
                "[Input Warning] Global input listener failed to start ({:?}). \
                 On macOS this usually means Input Monitoring permission is missing — \
                 keys/clicks/scroll will NOT be captured.",
                error
            );
        }
    });
}

/// Start the core background daemon aggregation loop.
pub fn start_daemon_loop(db: Arc<Database>, state: Arc<TelemetryState>) {
    println!("tenby10 Telemetry Daemon started.");

    let evaluator = crate::evaluator::ActivityEvaluator::new();
    let mut was_recently_active = false;

    // One-time cleanup for machines upgrading from a build that still captured
    // screens (ADR 0018).
    crate::env::purge_legacy_screenshots();

    // Run catch-up aggregation immediately at startup
    aggregate_pending_slots(&db);

    // Catch up on any missed work notes too, on a worker thread so a slow AI call
    // never delays the first telemetry minute.
    {
        let db_clone = db.clone();
        thread::spawn(move || generate_pending_summaries(&db_clone));
    }

    loop {
        // Run aggregation every 60 seconds
        thread::sleep(Duration::from_secs(60));

        if !state.tracking_enabled.load(Ordering::Relaxed) {
            state.reset_minute();
            state.clear_entropy_window();
            continue;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Scrape frontmost window (we need this early to check Windows lock state)
        let (active_app, active_title, raw_title_present) = read_active_window();

        let is_locked_mac = crate::sys_state::is_locked_or_asleep();
        let is_locked_win = active_app == "LockApp.exe" || active_app == "LogonUI.exe";

        if is_locked_mac || is_locked_win {
            println!(
                "[{}] System is locked or asleep. Skipping telemetry.",
                timestamp
            );
            state.reset_minute();
            state.clear_entropy_window();
            continue;
        }

        // Fold this minute's window read into title health for free — the UI's
        // 10s probe is the fast path, this keeps the signal fresh when no one is
        // watching the settings page.
        state.record_title_observation(active_app != "Unknown", raw_title_present, now_unix_ms());

        let keystroke_count = state.keystroke_count.load(Ordering::Relaxed);
        let mouse_click_count = state.mouse_click_count.load(Ordering::Relaxed);
        let scroll_event_count = state.scroll_event_count.load(Ordering::Relaxed);
        let mouse_distance = *state.mouse_distance.lock().unwrap();

        // Evaluate activity state using the evaluator
        let mouse_pos = state.mouse_positions.lock().unwrap().clone();
        let key_intervals = state.keystroke_intervals.lock().unwrap().clone();

        let mut config_path = crate::env::get_app_home();
        config_path.push("config.json");
        let config = crate::config::load_config(config_path).unwrap_or_default();

        let ctx = crate::evaluator::LiveEvaluationContext {
            keystroke_count,
            mouse_click_count,
            scroll_event_count,
            active_app: &active_app,
            active_title: &active_title,
            mouse_positions: &mouse_pos,
            key_intervals: &key_intervals,
            was_recently_active,
            distracting_apps: &config.distracting_apps,
            productive_apps: &config.productive_apps,
            meeting_apps: &config.meeting_apps,
        };

        let classification = evaluator.evaluate_minute(&ctx);

        // Input provenance (#87): surface synthetic (software-injected) input.
        // Detection is observe-only unless enforcement is enabled; the rule only
        // fires when the minute had input but NONE of it was genuine hardware.
        let (synthetic_events, genuine_events) = crate::provenance::take_counts();
        let all_injected = crate::provenance::all_input_injected(synthetic_events, genuine_events);
        if synthetic_events > 0 {
            println!(
                "[Provenance] Synthetic input this minute: {} synthetic vs {} genuine (all_injected={}, enforced={})",
                synthetic_events, genuine_events, all_injected, config.enforce_synthetic_detection
            );
        }

        let low_entropy = classification == crate::evaluator::ActivityClassification::Tampered
            || (config.enforce_synthetic_detection && all_injected);
        if low_entropy {
            println!("[WARNING] Anti-Cheat triggered: Input tampering detected!");
        }

        // (Removed categorized_app call since it's unused in the live log loop)

        // Update recently active flag for passive focus calculations
        was_recently_active = classification == crate::evaluator::ActivityClassification::Active;

        println!(
            "[{}] App: '{}' | Keys: {} | Clicks: {} | State: {:?}",
            timestamp, active_app, keystroke_count, mouse_click_count, classification
        );

        // Write to local database
        let db_res = db.insert_minute_log(
            timestamp,
            keystroke_count,
            mouse_click_count,
            scroll_event_count,
            mouse_distance,
            &active_app,
            &active_title,
            low_entropy,
        );

        if let Err(err) = db_res {
            eprintln!("Error saving telemetry log to database: {:?}", err);
        }

        // Trigger compilation of completed slots asynchronously
        let db_clone = db.clone();
        thread::spawn(move || {
            aggregate_pending_slots(&db_clone);
            // Off the same beat, and off the main thread: writing a note calls the
            // user's own AI over the network, which must never stall telemetry.
            generate_pending_summaries(&db_clone);
        });

        // Reset counts for the next minute segment
        state.reset_minute();
    }
}

/// How far back a first run will reach when writing missing work notes (ADR 0019).
/// Bounded on purpose: installing this on a months-old database must not spend the
/// user's own API budget summarizing history nobody asked for.
const SUMMARY_LOOKBACK_DAYS: i64 = 7;

/// Write the daily work note for any finished local day that doesn't have one yet
/// (ADR 0019).
///
/// Runs off the same 60-second loop as aggregation and requires nothing from the user:
/// notes exist because their AI is configured, which is what the AI is for. A day is
/// only summarized once it is over, and only once — so this is safe to call repeatedly.
pub fn generate_pending_summaries(db: &Database) {
    let mut config_path = crate::env::get_app_home();
    config_path.push("config.json");
    let config = crate::config::load_config(config_path).unwrap_or_default();

    if config.disable_work_summaries {
        return;
    }
    let Some(provider) = crate::llm::get_llm_provider(&config) else {
        // No AI configured: hours, categories and rules still work, there is just no
        // note. Nothing to warn about on every loop.
        return;
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pending = match db.days_needing_summary(now, SUMMARY_LOOKBACK_DAYS) {
        Ok(days) => days,
        Err(err) => {
            eprintln!("[Summary] Could not list days needing a note: {err:?}");
            return;
        }
    };

    let prompt = if config.summary_prompt.trim().is_empty() {
        crate::config::default_summary_prompt()
    } else {
        config.summary_prompt.clone()
    };
    let prompt_hash = crate::db::sha256_hex_pub(&prompt);

    for (day_start, day_end) in pending {
        let digest = match db.activity_digest(day_start, day_end) {
            Ok(lines) => lines,
            Err(err) => {
                eprintln!("[Summary] Could not read activity for {day_start}: {err:?}");
                continue;
            }
        };
        // A day with almost nothing in it has nothing worth describing, and asking a
        // model to describe it invites invention.
        if digest.len() < 3 {
            continue;
        }

        // Every line of the digest is built from a window title, which the focused
        // application wrote — so it goes to the model inside the untrusted fence
        // (#83), never as bare prose the model could read as part of its brief.
        let activity_text = crate::untrusted::fence(&digest.join("\n"));

        println!("[Summary] Writing the work note for the day starting {day_start}...");
        let note = match provider.write_note(&prompt, &activity_text) {
            Ok(text) => text,
            Err(err) => {
                // Left unwritten on purpose: the next loop retries, and a missing note
                // is honest where a fabricated one is not.
                eprintln!("[Summary] The AI could not write a note for {day_start}: {err}");
                continue;
            }
        };

        // The prompt asks the model never to quote a window title. This is where that
        // stops being a request (#83): the note is checked against the day's titles
        // before anything is signed, because what publishes from here reaches a client
        // with no review step in between. A refused note takes the same exit as an
        // unreachable AI — nothing written, retried next loop — and if the titles
        // can't be read there is no check to pass, so the day waits rather than
        // publishing unverified.
        let titles = match db.window_titles_in_period(day_start, day_end) {
            Ok(titles) => titles,
            Err(err) => {
                eprintln!(
                    "[Summary] Could not read the day's window titles to check the note for \
                     {day_start}, leaving the day unwritten: {err:?}"
                );
                continue;
            }
        };
        if crate::untrusted::note_quotes_a_title(&note, &titles) {
            // The offending text is not logged: it is the window title we are trying
            // to keep out of places it does not belong, and stdout is one of them.
            eprintln!(
                "[Summary] The note for {day_start} reproduced a window title verbatim, so it \
                 was discarded. The next pass will ask again."
            );
            continue;
        }

        // Keep the prompt that produced the note, so a reader can always see the rules
        // behind the words even after the user edits their prompt later.
        //
        // Nothing is signed until this lands. The note commits to this hash, the cloud won't
        // accept the note until it can serve the prompt behind it (#147), and only this local
        // copy can supply it — so a note signed now would stall the whole note chain at upload
        // and never be readable. Leaving the day unwritten costs one loop: the next pass
        // regenerates it.
        if let Err(err) = db.store_config_blob(&prompt_hash, &prompt) {
            eprintln!(
                "[Summary] Could not store the prompt behind the note for {day_start}, \
                 leaving the day unwritten for now: {err:?}"
            );
            continue;
        }

        let signer = if config.public_key.is_empty() || config.private_key.is_empty() {
            None
        } else {
            Some(crate::db::SlotSigner {
                public_key: &config.public_key,
                private_key: &config.private_key,
            })
        };

        match db.insert_work_summary(
            day_start,
            day_end,
            &note,
            now,
            &prompt_hash,
            signer.as_ref(),
        ) {
            Ok(_) => println!("[Summary] {day_start}: {note}"),
            Err(err) => eprintln!("[Summary] Could not store the note for {day_start}: {err:?}"),
        }
    }
}

/// Query database to compile any completed but un-aggregated 10-minute focus slots.
pub fn aggregate_pending_slots(db: &Database) {
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Aggregate slots that are older than 15 minutes (i.e., wait 5 minutes after the 10-minute slot ends)
    let max_slot_start = current_timestamp - 900;

    let pending_slots = match db.get_unaggregated_slots(max_slot_start) {
        Ok(slots) => slots,
        Err(err) => {
            eprintln!("Error querying pending slots: {:?}", err);
            return;
        }
    };

    if pending_slots.is_empty() {
        return;
    }

    println!(
        "[Aggregation] Found {} pending completed slots for aggregation.",
        pending_slots.len()
    );
    for slot_start in pending_slots {
        println!("[Aggregation] Compiling slot starting at {}...", slot_start);

        let mut config_path = crate::env::get_app_home();
        config_path.push("config.json");
        let config = crate::config::load_config(config_path).unwrap_or_default();

        aggregate_slot(db, &config, slot_start);
    }
}

/// ADR 0002 (addendum) / ADR 0012: a spoofable "meeting" window must not bill a
/// slot on zero interaction. At most this many *consecutive* no-input `Meeting`
/// minutes count as active; the streak resets on any real input, so a genuinely
/// interactive meeting stays fully credited. Kept below the ADR-0012 billable
/// gate (40% = 4 minutes) so a fully silent meeting slot cannot bill on its own.
const MEETING_NO_INPUT_STREAK_CAP: u32 = 3;

/// Upper bound (percent, fixed 10-minute denominator per ADR 0006) that the LLM
/// score may claim once meeting-spoof inflation is removed: minutes demoted for
/// exceeding the no-input meeting cap cannot be credited even by the LLM, so the
/// cap can't be bypassed by enabling BYOK/LLM mode. Non-meeting latitude (e.g.
/// crediting genuine passive reading) is preserved — only demoted minutes are
/// removed from the ceiling.
fn meeting_creditable_ceiling(total_minutes: u32, demoted_meeting_minutes: u32) -> u32 {
    let creditable = total_minutes.saturating_sub(demoted_meeting_minutes);
    ((creditable * 100) / 10).min(100)
}

pub fn aggregate_slot(db: &Database, config: &crate::config::AgentConfig, slot_start: i64) {
    let logs = match db.get_minute_logs_for_slot(slot_start) {
        Ok(logs) => logs,
        Err(err) => {
            eprintln!(
                "Error getting minute logs for slot {}: {:?}",
                slot_start, err
            );
            return;
        }
    };

    if logs.is_empty() {
        println!(
            "[Aggregation] No logs found for slot {}. Skipping.",
            slot_start
        );
        return;
    }

    let mut slot_active_segments = 0;
    let mut slot_idle_segments = 0;
    let mut slot_keystrokes = 0;
    let mut slot_clicks = 0;
    let mut slot_app_categories = HashMap::<String, u32>::new();

    let mut was_recently_active = false;
    let mut consecutive_silent_meeting = 0u32;
    let mut demoted_meeting_minutes = 0u32;
    let evaluator = crate::evaluator::ActivityEvaluator::new();

    for log in &logs {
        let ctx = crate::evaluator::StoredEvaluationContext {
            keystroke_count: log.keystroke_count,
            mouse_click_count: log.mouse_click_count,
            scroll_event_count: log.scroll_event_count,
            active_app: &log.active_app_name,
            active_title: &log.active_window_title,
            low_entropy: log.low_entropy,
            was_recently_active,
            distracting_apps: &config.distracting_apps,
            productive_apps: &config.productive_apps,
            meeting_apps: &config.meeting_apps,
        };

        let mut classification = evaluator.evaluate_stored_minute(&ctx);

        // ADR 0002 addendum: bound consecutive no-input Meeting minutes. A
        // `Meeting` classification only occurs with no input (any input
        // classifies `Active` earlier), so this streak measures uninterrupted
        // silence. Beyond the cap, demote to `Idle` so a spoofed, zero-input
        // "meeting" cannot bill a slot; any real input resets the streak.
        if classification == crate::evaluator::ActivityClassification::Meeting {
            consecutive_silent_meeting += 1;
            if consecutive_silent_meeting > MEETING_NO_INPUT_STREAK_CAP {
                classification = crate::evaluator::ActivityClassification::Idle;
                demoted_meeting_minutes += 1;
            }
        } else {
            consecutive_silent_meeting = 0;
        }

        let is_active = classification == crate::evaluator::ActivityClassification::Active
            || classification == crate::evaluator::ActivityClassification::PassiveReview
            || classification == crate::evaluator::ActivityClassification::Meeting;

        if is_active {
            slot_active_segments += 1;
        } else {
            slot_idle_segments += 1;
        }

        was_recently_active = classification == crate::evaluator::ActivityClassification::Active;

        slot_keystrokes += log.keystroke_count;
        slot_clicks += log.mouse_click_count;

        let category = match classification {
            crate::evaluator::ActivityClassification::Active
            | crate::evaluator::ActivityClassification::PassiveReview => "Productive",
            crate::evaluator::ActivityClassification::Meeting => "Meeting",
            crate::evaluator::ActivityClassification::Distracted => "Waste",
            crate::evaluator::ActivityClassification::Idle => "Inactive",
            crate::evaluator::ActivityClassification::Tampered => "Tampered",
        };
        *slot_app_categories.entry(category.to_string()).or_insert(0) += 1;
    }

    // Calculate contextual idle forgiveness
    let future_logs = db
        .get_minute_logs_for_slot(slot_start + 600)
        .unwrap_or_default();

    let mut trailing_idle_minutes = 0;
    for log in logs.iter().rev() {
        let has_input =
            log.keystroke_count > 0 || log.mouse_click_count > 0 || log.scroll_event_count > 0;
        if !has_input {
            trailing_idle_minutes += 1;
        } else {
            break;
        }
    }

    let mut leading_future_idle = 0;
    let mut found_future_active = false;
    for f_log in &future_logs {
        if f_log.timestamp >= slot_start + 900 {
            break;
        }
        // ADR 0011 addendum: only a *genuine* resumption rescues the pause. A
        // flagged (low-entropy / automated) minute does not count as real work
        // resuming, so it cannot unlock idle forgiveness.
        let genuine_input = (f_log.keystroke_count > 0
            || f_log.mouse_click_count > 0
            || f_log.scroll_event_count > 0)
            && !f_log.low_entropy;
        if !genuine_input {
            leading_future_idle += 1;
        } else {
            found_future_active = true;
            break;
        }
    }

    let mut forgiven_idle = 0;
    if found_future_active {
        let total_pause = trailing_idle_minutes + leading_future_idle;
        if total_pause > 0 && total_pause <= 5 {
            forgiven_idle = std::cmp::min(trailing_idle_minutes, slot_idle_segments);
            println!(
                "[Aggregation] Reconciling {} trailing idle minutes as Productive Reading (Total pause: {}m)",
                forgiven_idle, total_pause
            );
            if let Some(c) = slot_app_categories.get_mut("Inactive") {
                *c = c.saturating_sub(forgiven_idle);
            }
            *slot_app_categories
                .entry("Productive".to_string())
                .or_insert(0) += forgiven_idle;

            slot_active_segments += forgiven_idle;
            slot_idle_segments -= forgiven_idle;
        }
    }

    // Calculate focus score using a fixed 10-minute denominator (ADR 0006)
    let mut final_focus_score = (slot_active_segments * 100u32).checked_div(10).unwrap_or(0);

    // Cap at 100% to handle boundary noise or temporary overlaps
    if final_focus_score > 100 {
        final_focus_score = 100;
    }
    let mut final_reasoning: Option<String> = None;

    if config.engine_mode == "llm" {
        let purely_idle =
            slot_app_categories.get("Inactive").copied().unwrap_or(0) == (logs.len() as u32);

        if !purely_idle {
            let provider_opt = crate::llm::get_llm_provider(config);
            if let Some(provider) = provider_opt {
                let mut activity_lines = Vec::new();
                for log in &logs {
                    // App name and title are both written by whoever owns the
                    // window, so both are scrubbed and both ride inside the fence
                    // (#83). The counts are ours.
                    activity_lines.push(format!(
                        "App: '{}', Title: '{}', Keys: {}, Clicks: {}",
                        crate::untrusted::scrub(&log.active_app_name),
                        crate::untrusted::scrub(&log.active_window_title),
                        log.keystroke_count,
                        log.mouse_click_count
                    ));
                }
                let mut activity_text = crate::untrusted::fence(&activity_lines.join("\n"));

                if forgiven_idle > 0 {
                    // Appended after the closing marker on purpose: this sentence is
                    // the daemon speaking, and a fence is only worth having if what
                    // is inside it and what we said ourselves stay separable.
                    activity_text.push_str(&format!("\n\n[FUTURE CONTEXT]: The user paused for {} minutes at the end of this slot, but resumed working shortly after. This was a continuous Reading/Thinking session, so these minutes should not penalize the score.", forgiven_idle));
                }

                let default_prompt = crate::config::default_llm_prompt();
                let base_prompt = if config.llm_prompt.is_empty() {
                    &default_prompt
                } else {
                    &config.llm_prompt
                };

                let system_prompt = format!(
                    "Background: tenby10 is an activity and focus tracking daemon that aggregates user activity into 10-minute slots. \
                    It evaluates productive time, idle time, and wasted time based on window focus, keystrokes, and mouse movement.\n\
                    Local Configuration:\n\
                    - Productive Apps: {}\n\
                    - Meeting Apps: {}\n\
                    - Distracting Apps: {}\n\
                    \n{}",
                    config.productive_apps,
                    config.meeting_apps,
                    config.distracting_apps,
                    base_prompt
                );

                match provider.evaluate_slot(&system_prompt, &activity_text) {
                    Ok((score, reasoning)) => {
                        // Scale LLM score by logged segments / 10 (ADR 0006)
                        final_focus_score = (score * (logs.len() as u32)) / 10;
                        if final_focus_score > 100 {
                            final_focus_score = 100;
                        }
                        // ADR 0002 addendum: the no-input meeting cap must hold in
                        // LLM mode too — the LLM cannot credit minutes demoted for
                        // exceeding the streak cap, so a spoofed silent "meeting"
                        // can't be re-inflated by turning on BYOK scoring.
                        let ceiling =
                            meeting_creditable_ceiling(logs.len() as u32, demoted_meeting_minutes);
                        if final_focus_score > ceiling {
                            final_focus_score = ceiling;
                        }
                        // Every built-in provider already contains its reply, so this is
                        // the backstop, not the fix: `LlmProvider` is a public trait and
                        // this is the last point before the text is stored and signed
                        // (#95). `sanitize_reasoning` is idempotent, so applying it twice
                        // costs a scan and changes nothing.
                        final_reasoning = Some(crate::llm::sanitize_reasoning(&reasoning));
                    }
                    Err(e) => {
                        eprintln!("[LLM] Slot evaluation failed: {}", e);
                    }
                }
            }
        }
    }

    let app_categories_json = serde_json::to_string(&slot_app_categories).unwrap_or_default();

    // Self-sign the slot when the agent is enrolled (ADR 0014). Pre-enrollment
    // the keys are empty and the slot is written unsigned (tamper-evident only).
    let signer = if config.private_key.is_empty() || config.public_key.is_empty() {
        None
    } else {
        Some(crate::db::SlotSigner {
            public_key: &config.public_key,
            private_key: &config.private_key,
        })
    };

    // Bind the effective scoring config (auditing rules + AI prompt) into the
    // signed payload so every score is tied to the rubric that produced it (#62).
    // Compute both from the same blob so config_hash == sha256(blob), which the cloud verifies.
    let config_blob = config.effective_config_blob();
    let config_hash = crate::db::sha256_hex_pub(&config_blob);
    // Persist the blob keyed by hash so this slot (or an old one in the backlog) can be backfilled
    // to the cloud on demand later, even after the config changes (#80).
    if let Err(e) = db.store_config_blob(&config_hash, &config_blob) {
        eprintln!("[Config] could not persist config blob: {e}");
    }

    let slot_res = db.insert_slot_summary(
        slot_start,
        final_focus_score,
        slot_active_segments,
        slot_idle_segments,
        slot_keystrokes,
        slot_clicks,
        &app_categories_json,
        final_reasoning.as_deref(),
        &config_hash,
        signer.as_ref(),
    );

    if let Err(err) = slot_res {
        eprintln!(
            "Error saving slot summary for slot {}: {:?}",
            slot_start, err
        );
    } else {
        println!(
            "[Aggregation] Slot summary successfully compiled for slot {}. Focus Score: {}% | Active/Idle: {}/{}",
            slot_start, final_focus_score, slot_active_segments, slot_idle_segments
        );
    }

    // Upload any not-yet-synced signed slots (best-effort; #115). Skips when not enrolled. Each
    // slot carries its config_hash; if the cloud doesn't yet have that config it rejects the slot,
    // and sync backfills the config from the local store before retrying (#80) — no speculative
    // pre-upload, no local "already sent" cache to go stale.
    if !config.agent_id.is_empty() {
        let base = crate::sync::cloud_base_url();
        match crate::sync::sync_signed_slots(db, &config.agent_id, &base) {
            Ok(n) if n > 0 => println!("[Sync] Uploaded {n} slot(s) to the cloud."),
            Ok(_) => {}
            Err(e) => eprintln!("[Sync] {e}"),
        }

        // Work notes ride the same beat but their own chain, so a stalled note never
        // blocks an hour from syncing, or the reverse.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        match crate::sync::sync_work_summaries(db, &config.agent_id, &base, now) {
            Ok(n) if n > 0 => println!("[Sync] Uploaded {n} work note(s) to the cloud."),
            Ok(_) => {}
            Err(e) => eprintln!("[Sync] {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::db::Database;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::sync::atomic::{AtomicUsize, Ordering};
    static DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn test_title_probe_due_throttles_within_the_gap() {
        let now = 1_000_000_000_000;
        assert!(
            title_probe_due(0, now),
            "never checked -> probe immediately"
        );
        assert!(
            !title_probe_due(now - 1, now),
            "just checked -> do not re-probe"
        );
        assert!(
            !title_probe_due(now - (TITLE_PROBE_MIN_GAP_MS - 1), now),
            "inside the throttle window -> do not re-probe"
        );
        assert!(
            title_probe_due(now - TITLE_PROBE_MIN_GAP_MS, now),
            "at the gap -> probe"
        );
        assert!(
            title_probe_due(now - (TITLE_PROBE_MIN_GAP_MS * 20), now),
            "long past the gap -> probe"
        );
    }

    #[test]
    fn test_title_probe_due_survives_a_backwards_clock() {
        // Sleep/wake or a timezone change can move the wall clock backwards. A
        // naive `now - last >= gap` would then never fire again, freezing title
        // health at whatever it last read (issue #6, same trap as the old probe).
        let now = 1_000_000_000_000;
        assert!(
            title_probe_due(now + 60_000, now),
            "clock jumped backwards -> probe rather than latch"
        );
    }

    #[test]
    fn test_blank_titles_flag_unreadable_only_after_a_streak() {
        let state = TelemetryState::new();
        assert!(
            state.window_titles_ok.load(Ordering::Relaxed),
            "starts optimistic — titles read fine everywhere but a withheld grant"
        );

        // One or two blank titles are normal (some windows genuinely have none).
        for i in 1..TITLE_UNREADABLE_STRIKES {
            state.record_title_observation(true, false, 1_000 * i as i64);
            assert!(
                state.window_titles_ok.load(Ordering::Relaxed),
                "must not alarm on {i} blank title(s)"
            );
        }

        // A sustained run is the redaction fingerprint (macOS withholds
        // kCGWindowName while the app name still resolves).
        state.record_title_observation(true, false, 9_000);
        assert!(!state.window_titles_ok.load(Ordering::Relaxed));
        assert_eq!(state.last_title_check_ms.load(Ordering::Relaxed), 9_000);

        // One real title clears it immediately — a regained grant must not wait
        // out another streak before the UI goes green again.
        state.record_title_observation(true, true, 10_000);
        assert!(state.window_titles_ok.load(Ordering::Relaxed));
        assert_eq!(state.empty_title_streak.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_unidentified_window_is_not_evidence_either_way() {
        // No frontmost window at all (empty desktop, space transition) says
        // nothing about permissions: it must neither strike nor clear.
        let state = TelemetryState::new();
        state.record_title_observation(true, false, 1_000);
        let streak_before = state.empty_title_streak.load(Ordering::Relaxed);

        for i in 0..TITLE_UNREADABLE_STRIKES * 3 {
            state.record_title_observation(false, false, 2_000 + i as i64);
        }

        assert!(
            state.window_titles_ok.load(Ordering::Relaxed),
            "an unreadable window must never flag titles as redacted"
        );
        assert_eq!(
            state.empty_title_streak.load(Ordering::Relaxed),
            streak_before,
            "the streak is untouched by observations that identified no app"
        );
    }

    fn create_test_db() -> Database {
        let count = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/tenby10_daemon_test_{}_{}.db",
            timestamp, count
        ));
        Database::new(path).unwrap()
    }

    #[test]
    fn test_aggregate_static_mode() {
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();
        config.distracting_apps = "youtube,twitter".to_string();

        // Insert a few logs for slot 600 (10:10:00 to 10:20:00 roughly)
        for i in 0..10 {
            db.insert_minute_log(
                600 + i * 60,
                100, // keystrokes
                10,  // clicks
                0,   // scrolls
                0.0, // mouse movement
                "Terminal",
                "vim main.rs",
                false, // not low entropy
            )
            .unwrap();
        }

        // Aggregate slot 600
        aggregate_slot(&db, &config, 600);

        // Verify aggregation
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT focus_score, active_segments, idle_segments, llm_reasoning FROM slot_summaries WHERE slot_start = 600").unwrap();
        let mut rows = stmt.query([]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let focus_score: u32 = row.get(0).unwrap();
            let active_segments: u32 = row.get(1).unwrap();
            let idle_segments: u32 = row.get(2).unwrap();

            assert_eq!(focus_score, 100); // 10 productive segments / 10 = 100%
            assert_eq!(active_segments, 10);
            assert_eq!(idle_segments, 0);
        } else {
            panic!("Slot summary not found in database");
        }
    }

    #[test]
    fn test_aggregate_llm_mode_fallback() {
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "llm".to_string();
        // Missing provider and API key so LLM factory returns None, forcing a graceful fallback to 0 score without crashing.

        for i in 0..10 {
            db.insert_minute_log(
                600 + i * 60,
                0,   // no keys
                0,   // no clicks -> idle
                0,   // scrolls
                0.0, // mouse movement
                "Terminal",
                "vim main.rs",
                true, // low entropy
            )
            .unwrap();
        }

        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT focus_score FROM slot_summaries WHERE slot_start = 600")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let focus_score: u32 = row.get(0).unwrap();
            // Since LLM fails/returns None, it leaves `final_focus_score` at its default initial value of 0.
            // Wait, does it? Let's check: final_focus_score is initialized to 0. It tries LLM, it fails, so it remains 0.
            assert_eq!(focus_score, 0);
        } else {
            panic!("Slot summary not found in database");
        }
    }

    #[test]
    fn test_aggregate_partial_slot_adr0006() {
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        // Insert only 4 logs for slot 600
        for i in 0..4 {
            db.insert_minute_log(
                600 + i * 60,
                100,
                10,
                0,
                0.0,
                "Terminal",
                "vim main.rs",
                false,
            )
            .unwrap();
        }

        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT focus_score, active_segments FROM slot_summaries WHERE slot_start = 600",
            )
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let focus_score: u32 = row.get(0).unwrap();
            let active_segments: u32 = row.get(1).unwrap();

            assert_eq!(active_segments, 4);
            assert_eq!(focus_score, 40); // 4 segments / 10 denominator = 40%
        } else {
            panic!("Slot summary not found");
        }
    }

    #[test]
    fn test_aggregate_contextual_idle_forgiveness_approved() {
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        // 8 minutes of active work in slot 600
        for i in 0..8 {
            db.insert_minute_log(
                600 + i * 60,
                100,
                10,
                0,
                0.0,
                "Terminal",
                "vim main.rs",
                false,
            )
            .unwrap();
        }

        // 2 minutes of trailing idle in slot 600
        for i in 8..10 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "Terminal", "vim main.rs", false)
                .unwrap();
        }

        // 2 minutes of idle at start of slot 1200 (future)
        for i in 0..2 {
            db.insert_minute_log(
                1200 + i * 60,
                0,
                0,
                0,
                0.0,
                "Terminal",
                "vim main.rs",
                false,
            )
            .unwrap();
        }
        // Then user resumes work at minute 2 of future slot
        db.insert_minute_log(
            1200 + 2 * 60,
            100,
            10,
            0,
            0.0,
            "Terminal",
            "vim main.rs",
            false,
        )
        .unwrap();

        // Total pause is 2 + 2 = 4 minutes (<= 5). Trailing 2 minutes in slot 600 should be forgiven!
        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT focus_score, active_segments, idle_segments FROM slot_summaries WHERE slot_start = 600").unwrap();
        let mut rows = stmt.query([]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let focus_score: u32 = row.get(0).unwrap();
            let active_segments: u32 = row.get(1).unwrap();
            let idle_segments: u32 = row.get(2).unwrap();

            assert_eq!(active_segments, 10);
            assert_eq!(idle_segments, 0);
            assert_eq!(focus_score, 100); // 8 active + 1 grace + 1 forgiven = 10
        } else {
            panic!("Slot summary not found");
        }
    }

    #[test]
    fn test_aggregate_contextual_idle_forgiveness_rejected() {
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        // 7 minutes of active work in slot 600
        for i in 0..7 {
            db.insert_minute_log(
                600 + i * 60,
                100,
                10,
                0,
                0.0,
                "Terminal",
                "vim main.rs",
                false,
            )
            .unwrap();
        }

        // 3 minutes of trailing idle in slot 600
        for i in 7..10 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "Terminal", "vim main.rs", false)
                .unwrap();
        }

        // 3 minutes of idle at start of slot 1200 (future)
        for i in 0..3 {
            db.insert_minute_log(
                1200 + i * 60,
                0,
                0,
                0,
                0.0,
                "Terminal",
                "vim main.rs",
                false,
            )
            .unwrap();
        }
        // Then user resumes work at minute 3 of future slot
        db.insert_minute_log(
            1200 + 3 * 60,
            100,
            10,
            0,
            0.0,
            "Terminal",
            "vim main.rs",
            false,
        )
        .unwrap();

        // Total pause is 3 + 3 = 6 minutes (> 5). Trailing 3 minutes in slot 600 should NOT be forgiven!
        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT focus_score, active_segments, idle_segments FROM slot_summaries WHERE slot_start = 600").unwrap();
        let mut rows = stmt.query([]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let focus_score: u32 = row.get(0).unwrap();
            let active_segments: u32 = row.get(1).unwrap();
            let idle_segments: u32 = row.get(2).unwrap();

            assert_eq!(active_segments, 8);
            assert_eq!(idle_segments, 2);
            assert_eq!(focus_score, 80); // 7 active + 1 grace = 8 segments / 10 = 80%
        } else {
            panic!("Slot summary not found");
        }
    }

    #[test]
    fn test_aggregate_silent_meeting_is_capped() {
        // A window whose title/app matches a meeting keyword but receives zero
        // input for the whole slot must not bill (ADR 0002 addendum). Only
        // MEETING_NO_INPUT_STREAK_CAP minutes count; the rest demote to Idle.
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        for i in 0..10 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "zoom", "Zoom Meeting", false)
                .unwrap();
        }

        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT focus_score, active_segments, idle_segments FROM slot_summaries WHERE slot_start = 600")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        let row = rows.next().unwrap().expect("slot summary");
        let focus_score: u32 = row.get(0).unwrap();
        let active_segments: u32 = row.get(1).unwrap();
        let idle_segments: u32 = row.get(2).unwrap();

        assert_eq!(active_segments, MEETING_NO_INPUT_STREAK_CAP);
        assert_eq!(idle_segments, 10 - MEETING_NO_INPUT_STREAK_CAP);
        assert_eq!(focus_score, 30);
        assert!(
            focus_score < crate::db::BILLABLE_FOCUS_THRESHOLD,
            "a silent meeting slot must fall below the billable gate"
        );
    }

    #[test]
    fn test_aggregate_interactive_meeting_is_fully_credited() {
        // A genuine meeting where the user interacts periodically never trips the
        // streak cap (input resets it), so it stays fully credited.
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        for i in 0..10 {
            let has_input = i % 4 == 0; // input at minutes 0, 4, 8
            let (keys, clicks) = if has_input { (100, 10) } else { (0, 0) };
            db.insert_minute_log(
                600 + i * 60,
                keys,
                clicks,
                0,
                0.0,
                "zoom",
                "Zoom Meeting",
                false,
            )
            .unwrap();
        }

        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT focus_score, active_segments FROM slot_summaries WHERE slot_start = 600",
            )
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        let row = rows.next().unwrap().expect("slot summary");
        let focus_score: u32 = row.get(0).unwrap();
        let active_segments: u32 = row.get(1).unwrap();

        assert_eq!(active_segments, 10);
        assert_eq!(focus_score, 100);
    }

    #[test]
    fn test_aggregate_idle_forgiveness_rejects_tampered_resumption() {
        // Idle forgiveness must only trigger on a *genuine* resumption. A
        // low-entropy (automated) tap after the pause does not rescue the slot
        // (ADR 0011 addendum).
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        // 8 minutes of genuine active work, then 2 trailing idle in slot 600.
        // Uses a neutral (non-productive) app so the trailing idle minutes are
        // plain Idle, not PassiveReview — isolating the forgiveness behavior.
        for i in 0..8 {
            db.insert_minute_log(600 + i * 60, 100, 10, 0, 0.0, "GenericApp", "task", false)
                .unwrap();
        }
        for i in 8..10 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "GenericApp", "task", false)
                .unwrap();
        }

        // Future slot: 2 idle minutes, then a TAMPERED tap (low_entropy = true).
        for i in 0..2 {
            db.insert_minute_log(1200 + i * 60, 0, 0, 0, 0.0, "GenericApp", "task", false)
                .unwrap();
        }
        db.insert_minute_log(1200 + 2 * 60, 100, 10, 0, 0.0, "GenericApp", "task", true)
            .unwrap();

        aggregate_slot(&db, &config, 600);

        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT focus_score, active_segments, idle_segments FROM slot_summaries WHERE slot_start = 600")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        let row = rows.next().unwrap().expect("slot summary");
        let focus_score: u32 = row.get(0).unwrap();
        let active_segments: u32 = row.get(1).unwrap();
        let idle_segments: u32 = row.get(2).unwrap();

        // Forgiveness rejected: the 2 trailing idle minutes are NOT reclassified.
        assert_eq!(active_segments, 8);
        assert_eq!(idle_segments, 2);
        assert_eq!(focus_score, 80);
    }

    /// Read (active_segments, idle_segments, focus_score) for a slot.
    fn read_slot(db: &Database, slot_start: i64) -> (u32, u32, u32) {
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT active_segments, idle_segments, focus_score FROM slot_summaries WHERE slot_start = ?1")
            .unwrap();
        let mut rows = stmt.query([slot_start]).unwrap();
        let row = rows.next().unwrap().expect("slot summary");
        (
            row.get(0).unwrap(),
            row.get(1).unwrap(),
            row.get(2).unwrap(),
        )
    }

    fn insert_silent_meeting(db: &Database, slot_start: i64, minutes: i64) {
        for i in 0..minutes {
            db.insert_minute_log(
                slot_start + i * 60,
                0,
                0,
                0,
                0.0,
                "zoom",
                "Zoom Meeting",
                false,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_aggregate_meeting_cap_boundary_off_by_one() {
        // Exactly CAP silent minutes are all credited; the CAP+1th is the first
        // demoted. Pins the `> CAP` boundary.
        let cap = MEETING_NO_INPUT_STREAK_CAP as i64;
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        let db_at = Arc::new(create_test_db());
        insert_silent_meeting(&db_at, 600, cap); // exactly CAP minutes
        aggregate_slot(&db_at, &config, 600);
        let (active, idle, _) = read_slot(&db_at, 600);
        assert_eq!(
            active, MEETING_NO_INPUT_STREAK_CAP,
            "all CAP minutes credited"
        );
        assert_eq!(idle, 0, "none demoted at exactly CAP");

        let db_over = Arc::new(create_test_db());
        insert_silent_meeting(&db_over, 600, cap + 1); // one over CAP
        aggregate_slot(&db_over, &config, 600);
        let (active, idle, _) = read_slot(&db_over, 600);
        assert_eq!(
            active, MEETING_NO_INPUT_STREAK_CAP,
            "still only CAP credited"
        );
        assert_eq!(idle, 1, "the CAP+1th minute is demoted");
    }

    #[test]
    fn test_aggregate_meeting_streak_resets_and_recovers() {
        // 5 silent meeting, 1 real input, 4 silent meeting. The input must reset
        // the streak so the second silent run is credited fresh (not stuck demoted).
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        for i in 0..5 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "zoom", "Zoom Meeting", false)
                .unwrap();
        }
        db.insert_minute_log(600 + 5 * 60, 100, 10, 0, 0.0, "zoom", "Zoom Meeting", false)
            .unwrap();
        for i in 6..10 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "zoom", "Zoom Meeting", false)
                .unwrap();
        }

        aggregate_slot(&db, &config, 600);
        let (active, idle, focus) = read_slot(&db, 600);
        // run1: 3 credited + 2 demoted; input: 1; run2: 3 credited + 1 demoted.
        assert_eq!(active, 7);
        assert_eq!(idle, 3);
        assert_eq!(focus, 70);
    }

    #[test]
    fn test_aggregate_meeting_slot_bills_with_genuine_input() {
        // Corroboration: one genuine input at the start of an otherwise-silent
        // meeting keeps the slot billable (>= gate), where a fully silent meeting
        // slot (see test_aggregate_silent_meeting_is_capped) would not.
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();

        db.insert_minute_log(600, 100, 10, 0, 0.0, "zoom", "Zoom Meeting", false)
            .unwrap();
        for i in 1..10 {
            db.insert_minute_log(600 + i * 60, 0, 0, 0, 0.0, "zoom", "Zoom Meeting", false)
                .unwrap();
        }

        aggregate_slot(&db, &config, 600);
        let (active, _idle, focus) = read_slot(&db, 600);
        // 1 active input + 3 credited meeting = 4 active = 40%.
        assert_eq!(active, 4);
        assert_eq!(focus, 40);
        assert!(
            focus >= crate::db::BILLABLE_FOCUS_THRESHOLD,
            "one genuine interaction should keep a real meeting billable"
        );
    }

    #[test]
    fn test_meeting_creditable_ceiling() {
        // No demotions -> LLM is unconstrained.
        assert_eq!(meeting_creditable_ceiling(10, 0), 100);
        // A fully silent 10-min meeting demotes 7 -> ceiling matches the static 30%.
        assert_eq!(meeting_creditable_ceiling(10, 7), 30);
        // Partial slots and full demotion.
        assert_eq!(meeting_creditable_ceiling(4, 1), 30);
        assert_eq!(meeting_creditable_ceiling(10, 10), 0);
        // Saturating: never underflows.
        assert_eq!(meeting_creditable_ceiling(3, 5), 0);
    }

    // --- (A) End-to-end: cheating does not pay. ---

    #[test]
    fn test_tampered_slot_does_not_bill() {
        // Heavy input every minute, but every minute flagged as automated
        // (low_entropy = true). The slot must score 0 and fall below the billable
        // gate — proving detection is wired through classification INTO billing,
        // not just that the entropy function returns a boolean.
        let db = Arc::new(create_test_db());
        let mut config = AgentConfig::default();
        config.engine_mode = "static".to_string();
        for i in 0..10 {
            db.insert_minute_log(
                600 + i * 60,
                100,
                10,
                0,
                0.0,
                "Terminal",
                "vim main.rs",
                true,
            )
            .unwrap();
        }

        aggregate_slot(&db, &config, 600);
        let (active, idle, focus) = read_slot(&db, 600);
        assert_eq!(active, 0, "tampered minutes are never active");
        assert_eq!(idle, 10);
        assert_eq!(focus, 0);
        assert!(
            focus < crate::db::BILLABLE_FOCUS_THRESHOLD,
            "a fully tampered slot must not bill"
        );
    }

    // --- (B) Rolling anti-automation window machinery (the #85 fix). ---

    #[test]
    fn test_trim_front_caps_to_max_and_drops_oldest() {
        let mut v: Vec<i64> = (0..10).collect();
        trim_front(&mut v, 4);
        assert_eq!(
            v,
            vec![6, 7, 8, 9],
            "keeps the most recent, drops the oldest"
        );
        let mut under = vec![1, 2];
        trim_front(&mut under, 4);
        assert_eq!(under, vec![1, 2], "no-op below the cap");
    }

    #[test]
    fn test_reset_minute_preserves_window_but_clear_empties() {
        let state = TelemetryState::new();
        state.record_key_interval(100);
        state.record_key_interval(120);
        state.record_mouse_position(1.0, 2.0, 10);

        // A per-minute reset must NOT wipe the rolling anti-automation window,
        // otherwise low-rate automation could never accumulate.
        state.reset_minute();
        assert_eq!(state.keystroke_intervals.lock().unwrap().len(), 2);
        assert_eq!(state.mouse_positions.lock().unwrap().len(), 1);

        // An explicit clear (pause/lock) does empty it.
        state.clear_entropy_window();
        assert!(state.keystroke_intervals.lock().unwrap().is_empty());
        assert!(state.mouse_positions.lock().unwrap().is_empty());
    }

    #[test]
    fn test_low_rate_macro_accumulates_across_minutes() {
        // The #85 fix, at the state level: a ~1-key/min macro records one interval
        // per simulated minute with a per-minute reset between each. The window
        // must retain them across minutes so the accumulated series is flagged —
        // the old per-minute buffer would clear after each minute and never see it.
        let state = TelemetryState::new();
        for i in 0..7 {
            state.record_key_interval(60_000 + (i as i64 % 3) * 100);
            state.reset_minute();
        }
        let intervals = state.keystroke_intervals.lock().unwrap().clone();
        assert_eq!(intervals.len(), 7, "samples survive the minute boundaries");
        assert!(
            crate::entropy::is_keyboard_macro(&intervals),
            "the accumulated 1/min series is flagged"
        );
    }

    #[test]
    fn test_record_key_interval_trims_to_window() {
        let state = TelemetryState::new();
        for i in 0..(KEY_INTERVAL_WINDOW + 50) {
            state.record_key_interval(i as i64);
        }
        let buf = state.keystroke_intervals.lock().unwrap();
        assert_eq!(buf.len(), KEY_INTERVAL_WINDOW, "capped to the window size");
        assert_eq!(*buf.first().unwrap(), 50, "oldest samples dropped");
    }
}
