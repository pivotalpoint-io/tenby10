use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, Result, params};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

/// Minimum focus score (0–100) for a 10-minute slot to be billable (ADR 0012).
/// Slots below this are "red" and contribute 0 billable minutes; at or above it
/// they are orange/green and bill the full 10 minutes. Reuses the timeline's
/// green/orange/red band boundary.
pub const BILLABLE_FOCUS_THRESHOLD: u32 = 40;

/// Version of the slot signing/hashing scheme (ADR 0014). Bumped when the
/// canonical payload format changes so old rows still verify under their scheme.
/// v2 (#62) binds the effective-config hash into the payload; v1 rows omit it.
pub const LEDGER_SCHEME_VERSION: u32 = 2;

/// Material needed to self-sign a slot summary (ADR 0014). Sourced from the
/// enrolled agent's config; both keys are hex-encoded Ed25519. When absent
/// (agent not yet enrolled) slots are written unsigned — tamper-evident via the
/// hash chain only, never carrying a "Verified" claim.
pub struct SlotSigner<'a> {
    pub public_key: &'a str,
    pub private_key: &'a str,
}

/// A signed slot row ready to upload to the cloud (#115). `app_categories` is the exact
/// JSON string that was signed; `llm_reasoning` is kept local — only its SHA-256 is sent.
pub struct SignedSlot {
    pub slot_start: i64,
    pub focus_score: u32,
    pub active_segments: u32,
    pub idle_segments: u32,
    pub total_keystrokes: u32,
    pub total_clicks: u32,
    pub app_categories: String,
    pub llm_reasoning: Option<String>,
    pub hash: String,
    pub parent_hash: String,
    pub signature: String,
    pub scheme_version: u32,
    /// SHA-256 of the effective-config blob in force for this slot (v2+; "" for v1).
    pub config_hash: String,
}

/// SHA-256 of a string as lowercase hex — matches the canonical payload's field folding.
pub fn sha256_hex_pub(data: &str) -> String {
    sha256_hex(data)
}

/// Lowercase-hex encode a byte slice.
fn to_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a lowercase/uppercase hex string. Returns `None` on malformed input.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// SHA-256 of a string, lowercase hex.
fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    // sha2 0.11 returns a `hybrid-array` `Array` from `finalize()`, which no
    // longer implements `LowerHex`; hex-encode the bytes directly instead.
    to_hex_bytes(&hasher.finalize())
}

/// Deterministic byte-string that is both hashed (chain link) and signed for a
/// slot (ADR 0014). Every stored field is covered. Variable-length text fields
/// (`app_categories`, `llm_reasoning`) are folded to fixed-width SHA-256 hex so
/// the `|` delimiter can never be injected by their contents. An empty
/// `signing_pubkey` denotes an unsigned/local row.
#[allow(clippy::too_many_arguments)]
fn canonical_slot_payload(
    scheme_version: u32,
    slot_start: i64,
    focus_score: u32,
    active_segments: u32,
    idle_segments: u32,
    total_keystrokes: u32,
    total_clicks: u32,
    app_categories_json: &str,
    llm_reasoning: Option<&str>,
    parent_hash: &str,
    signing_pubkey: &str,
    config_hash: &str,
) -> String {
    // v2 (#62) inserts the effective-config hash before the parent link so every
    // score is bound to the rubric that produced it. v1 rows keep the old format.
    if scheme_version >= 2 {
        format!(
            "tenby10-slot|v{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            scheme_version,
            signing_pubkey,
            slot_start,
            focus_score,
            active_segments,
            idle_segments,
            total_keystrokes,
            total_clicks,
            sha256_hex(app_categories_json),
            sha256_hex(llm_reasoning.unwrap_or("")),
            config_hash,
            parent_hash,
        )
    } else {
        format!(
            "tenby10-slot|v{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            scheme_version,
            signing_pubkey,
            slot_start,
            focus_score,
            active_segments,
            idle_segments,
            total_keystrokes,
            total_clicks,
            sha256_hex(app_categories_json),
            sha256_hex(llm_reasoning.unwrap_or("")),
            parent_hash,
        )
    }
}

/// Verify an Ed25519 slot signature. `Ok(true)`/`Ok(false)` on a well-formed
/// key+sig; `Err` when the key or signature bytes are malformed.
fn verify_slot_signature(
    payload: &str,
    sig_hex: &str,
    pubkey_hex: &str,
) -> std::result::Result<bool, String> {
    let pk_bytes: [u8; 32] = from_hex(pubkey_hex)
        .ok_or("malformed pubkey hex")?
        .try_into()
        .map_err(|_| "pubkey is not 32 bytes")?;
    let sig_bytes: [u8; 64] = from_hex(sig_hex)
        .ok_or("malformed signature hex")?
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| e.to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(vk.verify(payload.as_bytes(), &sig).is_ok())
}

/// Aggregated "today" metrics returned by [`Database::get_today_metrics`]:
/// `(avg_focus, active_minutes, total_keystrokes, total_clicks,
/// per_slot_focus_scores, logged_slot_count, billable_slot_count)`.
///
/// Every time value is slot-granular so it reconstructs by counting 10-minute
/// slots: `active_minutes / 10 == logged_slot_count == per_slot_focus_scores.len()`,
/// and `billable_slot_count * 10` is the billable minutes. A slot is "logged" only
/// if it holds at least one productive minute (`focus_score > 0`); fully-idle slots
/// are excluded from every aggregate. `avg_focus` averages over logged slots only.
pub type TodayMetrics = (u32, u32, u32, u32, Vec<u32>, u32, u32);

pub struct Database {
    pub conn: Mutex<Connection>,
}

impl Database {
    /// Create a new Database instance at the specified file path.
    /// Creates parent directories if they don't exist.
    pub fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|err| {
                eprintln!("Warning: Failed to create database directory: {}", err);
            });
        }
        let conn = Connection::open(db_path)?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.init_tables()?;
        Ok(db)
    }

    /// Initialize tables for minute logs and 10-minute slot summaries.
    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS minute_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL UNIQUE,
                keystroke_count INTEGER NOT NULL,
                mouse_click_count INTEGER NOT NULL,
                scroll_event_count INTEGER NOT NULL DEFAULT 0,
                mouse_movement_distance REAL NOT NULL,
                active_app_name TEXT NOT NULL,
                active_window_title TEXT NOT NULL,
                low_entropy INTEGER NOT NULL
            )",
            [],
        )?;

        // Deduplication migration: ensure timestamp is UNIQUE if it wasn't before
        // We create a temporary table, copy unique logs, then replace the original
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS minute_logs_temp AS 
             SELECT * FROM minute_logs GROUP BY timestamp",
            [],
        );
        let _ = conn.execute("DROP TABLE minute_logs", []);
        let _ = conn.execute("ALTER TABLE minute_logs_temp RENAME TO minute_logs", []);
        let _ = conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_minute_logs_timestamp ON minute_logs(timestamp)",
            [],
        );

        conn.execute(
            "CREATE TABLE IF NOT EXISTS slot_summaries (
                slot_start INTEGER PRIMARY KEY,
                focus_score INTEGER NOT NULL,
                active_segments INTEGER NOT NULL,
                idle_segments INTEGER NOT NULL,
                total_keystrokes INTEGER NOT NULL,
                total_clicks INTEGER NOT NULL,
                app_categories TEXT NOT NULL,
                hash TEXT NOT NULL,
                parent_hash TEXT NOT NULL,
                llm_reasoning TEXT,
                signature TEXT,
                signing_pubkey TEXT,
                scheme_version INTEGER NOT NULL DEFAULT 1,
                config_hash TEXT NOT NULL DEFAULT ''
            )",
            [],
        )?;

        // Ensure migration for existing databases
        let _ = conn.execute(
            "ALTER TABLE slot_summaries ADD COLUMN llm_reasoning TEXT",
            [],
        );
        // ADR 0014: self-signature columns (nullable so pre-signing rows survive).
        let _ = conn.execute("ALTER TABLE slot_summaries ADD COLUMN signature TEXT", []);
        let _ = conn.execute(
            "ALTER TABLE slot_summaries ADD COLUMN signing_pubkey TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE slot_summaries ADD COLUMN scheme_version INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE minute_logs ADD COLUMN scroll_event_count INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Uploaded-to-cloud marker (#115). 0 = not yet synced.
        let _ = conn.execute(
            "ALTER TABLE slot_summaries ADD COLUMN synced INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Config-in-ledger (#62): effective-config hash bound into v2 signed payloads.
        let _ = conn.execute(
            "ALTER TABLE slot_summaries ADD COLUMN config_hash TEXT NOT NULL DEFAULT ''",
            [],
        );
        // Tracks which effective-config blobs have already been uploaded to the cloud (#62),
        // so each distinct config is sent once (on change) rather than every sync.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS synced_configs (config_hash TEXT PRIMARY KEY)",
            [],
        )?;

        Ok(())
    }

    /// Insert a telemetry log row for a 1-minute window.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_minute_log(
        &self,
        timestamp: i64,
        keystroke_count: u32,
        mouse_click_count: u32,
        scroll_event_count: u32,
        mouse_movement_distance: f64,
        active_app: &str,
        active_title: &str,
        low_entropy: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO minute_logs (
                timestamp, keystroke_count, mouse_click_count, scroll_event_count, mouse_movement_distance, active_app_name, active_window_title, low_entropy
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                timestamp,
                keystroke_count,
                mouse_click_count,
                scroll_event_count,
                mouse_movement_distance,
                active_app,
                active_title,
                if low_entropy { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    /// Fetch the last parent hash in the slot summaries table.
    /// Returns an empty string if no slots exist yet.
    /// Fetch up to `limit` signed slots that have not yet been uploaded, oldest first.
    /// Only signed rows are returned — unsigned/local rows are never sent to the cloud.
    pub fn get_unsynced_signed_slots(&self, limit: u32) -> Result<Vec<SignedSlot>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT slot_start, focus_score, active_segments, idle_segments, total_keystrokes, \
             total_clicks, app_categories, llm_reasoning, hash, parent_hash, signature, scheme_version, config_hash \
             FROM slot_summaries \
             WHERE signature IS NOT NULL AND synced = 0 \
             ORDER BY slot_start ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(SignedSlot {
                slot_start: r.get(0)?,
                focus_score: r.get(1)?,
                active_segments: r.get(2)?,
                idle_segments: r.get(3)?,
                total_keystrokes: r.get(4)?,
                total_clicks: r.get(5)?,
                app_categories: r.get(6)?,
                llm_reasoning: r.get(7)?,
                hash: r.get(8)?,
                parent_hash: r.get(9)?,
                signature: r.get(10)?,
                scheme_version: r.get(11)?,
                config_hash: r.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Whether an effective-config blob with this hash has already been uploaded (#62).
    pub fn is_config_uploaded(&self, config_hash: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM synced_configs WHERE config_hash = ?1")?;
        let mut rows = stmt.query(params![config_hash])?;
        Ok(rows.next()?.is_some())
    }

    /// Record that the cloud accepted a config blob, so it is not re-uploaded.
    pub fn mark_config_uploaded(&self, config_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO synced_configs (config_hash) VALUES (?1)",
            params![config_hash],
        )?;
        Ok(())
    }

    /// Mark a slot as uploaded so it is not sent again.
    pub fn mark_slot_synced(&self, slot_start: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE slot_summaries SET synced = 1 WHERE slot_start = ?1",
            params![slot_start],
        )?;
        Ok(())
    }

    pub fn get_latest_slot_hash(&self) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT hash FROM slot_summaries ORDER BY slot_start DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            row.get(0)
        } else {
            Ok(String::new())
        }
    }

    /// Insert a slot summary, generating the parent link, a full-payload SHA-256
    /// chain hash, and — when `signer` is present — an Ed25519 self-signature over
    /// the canonical payload (ADR 0014). The hash now covers **every** stored
    /// field, so editing any of them breaks the chain.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_slot_summary(
        &self,
        slot_start: i64,
        focus_score: u32,
        active_segments: u32,
        idle_segments: u32,
        total_keystrokes: u32,
        total_clicks: u32,
        app_categories_json: &str,
        llm_reasoning: Option<&str>,
        config_hash: &str,
        signer: Option<&SlotSigner>,
    ) -> Result<()> {
        let parent_hash = self.get_latest_slot_hash()?;

        let signing_pubkey = signer.map(|s| s.public_key).unwrap_or("");

        let payload = canonical_slot_payload(
            LEDGER_SCHEME_VERSION,
            slot_start,
            focus_score,
            active_segments,
            idle_segments,
            total_keystrokes,
            total_clicks,
            app_categories_json,
            llm_reasoning,
            &parent_hash,
            signing_pubkey,
            config_hash,
        );

        let hash = sha256_hex(&payload);

        // Self-sign when enrolled. A malformed key leaves the row unsigned
        // (tamper-evident via the hash chain only) rather than failing the write.
        let signature: Option<String> = signer.and_then(|s| {
            let bytes = from_hex(s.private_key)?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            let sk = SigningKey::from_bytes(&arr);
            Some(to_hex_bytes(&sk.sign(payload.as_bytes()).to_bytes()))
        });
        // Only record the signing key when we actually produced a signature.
        let stored_pubkey: Option<&str> = signature.as_ref().map(|_| signing_pubkey);

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO slot_summaries (
                slot_start, focus_score, active_segments, idle_segments, total_keystrokes, total_clicks, app_categories, hash, parent_hash, llm_reasoning, signature, signing_pubkey, scheme_version, config_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                slot_start,
                focus_score,
                active_segments,
                idle_segments,
                total_keystrokes,
                total_clicks,
                app_categories_json,
                hash,
                parent_hash,
                llm_reasoning,
                signature,
                stored_pubkey,
                LEDGER_SCHEME_VERSION,
                config_hash
            ],
        )?;
        Ok(())
    }

    /// Aggregate today's (local time) metrics as a slot-countable model: focus is
    /// averaged over logged slots, and active time is `logged_slots * 10` so it can
    /// be reconstructed by counting 10-minute slots. See [`TodayMetrics`].
    pub fn get_today_metrics(&self) -> Result<TodayMetrics, rusqlite::Error> {
        let local_today = chrono::Local::now().date_naive();
        let start_of_day_local = local_today.and_hms_opt(0, 0, 0).unwrap();
        let start_of_day_timestamp = start_of_day_local
            .and_local_timezone(chrono::Local)
            .unwrap()
            .timestamp();

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT focus_score, total_keystrokes, total_clicks
             FROM slot_summaries
             WHERE slot_start >= ?1
             ORDER BY slot_start ASC",
        )?;

        let mut rows = stmt.query(params![start_of_day_timestamp])?;

        let mut sum_focus = 0.0;
        let mut keystrokes = 0;
        let mut clicks = 0;
        let mut logged_scores = Vec::new();
        let mut billable_count = 0;

        while let Some(row) = rows.next()? {
            let focus_score: u32 = row.get(0)?;
            let k: u32 = row.get(1)?;
            let c: u32 = row.get(2)?;

            // Total inputs count activity from every slot, logged or not.
            keystrokes += k;
            clicks += c;

            // A slot is "logged" only if it holds at least one productive minute
            // (focus_score > 0). Fully-idle slots are dropped so that every headline
            // number reconstructs by counting 10-minute slots.
            if focus_score == 0 {
                continue;
            }

            sum_focus += focus_score as f64;
            logged_scores.push(focus_score);
            // A slot bills only if it cleared the focus gate (ADR 0012).
            if focus_score >= BILLABLE_FOCUS_THRESHOLD {
                billable_count += 1;
            }
        }

        let logged_count = logged_scores.len() as u32;
        let avg_focus = if logged_count > 0 {
            (sum_focus / (logged_count as f64)).round() as u32
        } else {
            0
        };
        // Slot-granular active time (the ADR 0012 unit): one logged 10-minute slot
        // contributes 10 minutes, so `active_minutes / 10 == logged_count`.
        let active_mins = logged_count * 10;

        Ok((
            avg_focus,
            active_mins,
            keystrokes,
            clicks,
            logged_scores,
            logged_count,
            billable_count,
        ))
    }

    /// Verify the slot ledger (ADR 0014). Checks, per slot in order:
    /// 1. the parent link is intact,
    /// 2. the full-payload SHA-256 recomputes (covers every stored field), and
    /// 3. any self-signature verifies — and, when `expected_pubkey` is non-empty,
    ///    was produced by that exact enrolled key (blocks a third party without
    ///    the keychain key from forging a row for this identity).
    ///
    /// Unsigned rows (pre-enrollment / legacy) pass 1–2 only: that is
    /// tamper-evidence, not the self-asserted authorship a signature adds. Since
    /// the signer holds the key, this remains local self-verification; proving a
    /// ledger to a counterparty who does not trust the signer is out of scope for
    /// this client.
    ///
    /// Returns `Ok(Ok(()))` if valid, or `Ok(Err(String))` with details if tampered.
    pub fn verify_ledger_integrity(&self, expected_pubkey: &str) -> Result<Result<(), String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT slot_start, focus_score, active_segments, idle_segments, total_keystrokes, total_clicks, app_categories, hash, parent_hash, llm_reasoning, signature, signing_pubkey, scheme_version, config_hash
             FROM slot_summaries ORDER BY slot_start ASC",
        )?;
        let mut rows = stmt.query([])?;

        let mut expected_parent_hash = String::new();

        while let Some(row) = rows.next()? {
            let slot_start: i64 = row.get(0)?;
            let focus_score: u32 = row.get(1)?;
            let active_segments: u32 = row.get(2)?;
            let idle_segments: u32 = row.get(3)?;
            let total_keystrokes: u32 = row.get(4)?;
            let total_clicks: u32 = row.get(5)?;
            let app_categories: String = row.get(6)?;
            let hash: String = row.get(7)?;
            let parent_hash: String = row.get(8)?;
            let llm_reasoning: Option<String> = row.get(9)?;
            let signature: Option<String> = row.get(10)?;
            let signing_pubkey: Option<String> = row.get(11)?;
            let scheme_version: u32 = row.get(12).unwrap_or(1);
            let config_hash: String = row.get(13).unwrap_or_default();

            // 1. Verify parent_hash links correctly
            if parent_hash != expected_parent_hash {
                return Ok(Err(format!(
                    "Hash chain link broken at slot {}. Expected parent hash '{}', found '{}'.",
                    slot_start, expected_parent_hash, parent_hash
                )));
            }

            // 2. Re-compute the full-payload hash and verify match
            let row_pubkey = signing_pubkey.as_deref().unwrap_or("");
            let payload = canonical_slot_payload(
                scheme_version,
                slot_start,
                focus_score,
                active_segments,
                idle_segments,
                total_keystrokes,
                total_clicks,
                &app_categories,
                llm_reasoning.as_deref(),
                &parent_hash,
                row_pubkey,
                &config_hash,
            );
            let computed_hash = sha256_hex(&payload);

            if hash != computed_hash {
                return Ok(Err(format!(
                    "Data tampering detected at slot {}. Computed hash '{}' does not match stored hash '{}'.",
                    slot_start, computed_hash, hash
                )));
            }

            // 3. Signature check (only for signed rows)
            if let Some(sig_hex) = signature.as_deref() {
                if !expected_pubkey.is_empty() && row_pubkey != expected_pubkey {
                    return Ok(Err(format!(
                        "Slot {} signed by unexpected key '{}' (enrolled key is '{}').",
                        slot_start, row_pubkey, expected_pubkey
                    )));
                }
                match verify_slot_signature(&payload, sig_hex, row_pubkey) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(Err(format!(
                            "Signature verification failed at slot {}.",
                            slot_start
                        )));
                    }
                    Err(e) => {
                        return Ok(Err(format!(
                            "Malformed signature or key at slot {}: {}.",
                            slot_start, e
                        )));
                    }
                }
            }

            // Move the chain forward
            expected_parent_hash = hash;
        }

        Ok(Ok(()))
    }

    /// Returns all completed 10-minute slot start timestamps (multiples of 600)
    /// that are strictly less than the current slot start timestamp and do not yet
    /// have an entry in the slot_summaries table.
    pub fn get_unaggregated_slots(&self, max_slot_start: i64) -> Result<Vec<i64>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT (timestamp - (timestamp % 600)) AS slot_start 
             FROM minute_logs 
             WHERE (timestamp - (timestamp % 600)) <= ?1
             AND (timestamp - (timestamp % 600)) NOT IN (SELECT slot_start FROM slot_summaries)
             ORDER BY slot_start ASC",
        )?;
        let rows = stmt.query_map(params![max_slot_start], |row| row.get::<_, i64>(0))?;

        let mut slots = Vec::new();
        for slot in rows.flatten() {
            slots.push(slot);
        }
        Ok(slots)
    }

    /// Retrieve all raw minute logs within the specified slot window [slot_start, slot_start + 600).
    pub fn get_minute_logs_for_slot(&self, slot_start: i64) -> Result<Vec<MinuteLogData>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT timestamp, keystroke_count, mouse_click_count, scroll_event_count, active_app_name, active_window_title, low_entropy 
             FROM minute_logs 
             WHERE timestamp >= ?1 AND timestamp < ?2
             ORDER BY timestamp ASC"
        )?;
        let rows = stmt.query_map(params![slot_start, slot_start + 600], |row| {
            let low_entropy_int: i32 = row.get(6)?;
            Ok(MinuteLogData {
                timestamp: row.get(0)?,
                keystroke_count: row.get(1)?,
                mouse_click_count: row.get(2)?,
                scroll_event_count: row.get(3)?,
                active_app_name: row.get(4)?,
                active_window_title: row.get(5)?,
                low_entropy: low_entropy_int != 0,
            })
        })?;

        let mut logs = Vec::new();
        for log in rows.flatten() {
            logs.push(log);
        }
        Ok(logs)
    }

    /// Fetch the most recent slot summaries (newest first) for the dashboard.
    pub fn get_recent_slot_summaries(&self, limit: u32) -> Result<Vec<SlotSummaryView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT slot_start, focus_score, active_segments, idle_segments, total_keystrokes, total_clicks, app_categories, hash, parent_hash, llm_reasoning
             FROM slot_summaries ORDER BY slot_start DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            let categories_str: String = row.get(6)?;
            let categories_json: serde_json::Value =
                serde_json::from_str(&categories_str).unwrap_or(serde_json::json!({}));

            Ok(SlotSummaryView {
                slot_start: row.get(0)?,
                focus_score: row.get(1)?,
                active_segments: row.get(2)?,
                idle_segments: row.get(3)?,
                total_keystrokes: row.get(4)?,
                total_clicks: row.get(5)?,
                app_categories: categories_json,
                hash: row.get(7)?,
                parent_hash: row.get(8)?,
                llm_reasoning: row.get(9).unwrap_or(None),
            })
        })?;

        let mut slots = Vec::new();
        for slot in rows.flatten() {
            slots.push(slot);
        }
        Ok(slots)
    }

    /// Fetch the minute-by-minute logs for a slot and classify each one into a
    /// display `state`, mirroring the evaluator used by the aggregation pipeline.
    pub fn get_slot_minute_details(&self, slot_start: i64) -> Result<Vec<SlotMinuteDetailView>> {
        let raw = self.get_minute_logs_for_slot(slot_start)?;

        let mut config_path = crate::env::get_app_home();
        config_path.push("config.json");
        let config = crate::config::load_config(config_path).unwrap_or_default();
        let evaluator = crate::evaluator::ActivityEvaluator::new();

        let mut list = Vec::new();
        for item in raw {
            let classification =
                evaluator.evaluate_stored_minute(&crate::evaluator::StoredEvaluationContext {
                    keystroke_count: item.keystroke_count,
                    mouse_click_count: item.mouse_click_count,
                    scroll_event_count: item.scroll_event_count,
                    active_app: &item.active_app_name,
                    active_title: &item.active_window_title,
                    low_entropy: item.low_entropy,
                    was_recently_active: false,
                    distracting_apps: &config.distracting_apps,
                    productive_apps: &config.productive_apps,
                    meeting_apps: &config.meeting_apps,
                });
            let state = match classification {
                crate::evaluator::ActivityClassification::Active
                | crate::evaluator::ActivityClassification::PassiveReview => "Productive",
                crate::evaluator::ActivityClassification::Meeting => "Meeting",
                crate::evaluator::ActivityClassification::Distracted => "Waste",
                crate::evaluator::ActivityClassification::Idle => "Inactive",
                crate::evaluator::ActivityClassification::Tampered => "Tampered",
            };
            list.push(SlotMinuteDetailView {
                timestamp: item.timestamp,
                keystroke_count: item.keystroke_count,
                mouse_click_count: item.mouse_click_count,
                scroll_event_count: item.scroll_event_count,
                active_app_name: item.active_app_name,
                active_window_title: item.active_window_title,
                low_entropy: item.low_entropy,
                state: state.to_string(),
            });
        }
        Ok(list)
    }

    /// Build a CSV export of raw minute logs over the given range. `range` is one
    /// of "24h" (default), "7d", "30d", "all", or "custom" (which uses the
    /// inclusive `start`/`end` unix timestamps).
    pub fn export_minute_logs_csv(
        &self,
        range: &str,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<String> {
        let conn = self.conn.lock().unwrap();

        let mut sql = "SELECT timestamp, active_app_name, active_window_title, keystroke_count, mouse_click_count, scroll_event_count, mouse_movement_distance, low_entropy, strftime('%Y/%m/%d %H:%M', timestamp, 'unixepoch', 'localtime')
             FROM minute_logs".to_string();

        match range {
            "7d" => {
                sql.push_str(" WHERE timestamp > strftime('%s', 'now') - 604800");
            }
            "30d" => {
                sql.push_str(" WHERE timestamp > strftime('%s', 'now') - 2592000");
            }
            "all" => {}
            "custom" => {
                let start = start.unwrap_or(0);
                let end = end.unwrap_or(i64::MAX);
                sql.push_str(&format!(
                    " WHERE timestamp >= {} AND timestamp <= {}",
                    start, end
                ));
            }
            _ => {
                sql.push_str(" WHERE timestamp > strftime('%s', 'now') - 86400");
            }
        }

        sql.push_str(" ORDER BY timestamp ASC");

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let timestamp: i64 = row.get(0)?;
            let app: String = row.get(1)?;
            let title: String = row.get(2)?;
            let keys: i32 = row.get(3)?;
            let clicks: i32 = row.get(4)?;
            let scroll: i32 = row.get(5)?;
            let dist: f64 = row.get(6)?;
            let low_entropy: bool = row.get(7)?;
            let datetime: String = row.get(8)?;
            Ok(format!(
                "{},\"{}\",\"{}\",{},{},{},{},{},{}",
                datetime,
                app.replace('"', "\"\""),
                title.replace('"', "\"\""),
                keys,
                clicks,
                scroll,
                dist,
                low_entropy,
                timestamp
            ))
        })?;

        let mut lines = Vec::new();
        lines.push(String::from("datetime,app_name,window_title,keystroke_count,mouse_click_count,scroll_event_count,mouse_movement_distance,low_entropy,epoch_timestamp"));
        for line in rows.flatten() {
            lines.push(line);
        }
        Ok(lines.join("\n"))
    }
}

pub struct MinuteLogData {
    pub timestamp: i64,
    pub keystroke_count: u32,
    pub mouse_click_count: u32,
    pub scroll_event_count: u32,
    pub active_app_name: String,
    pub active_window_title: String,
    pub low_entropy: bool,
}

/// A single 10-minute slot summary as shown in the activity dashboard.
/// Shared by the native Tauri commands and the (legacy) HTTP dashboard so both
/// surfaces read identical data from one query.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SlotSummaryView {
    pub slot_start: i64,
    pub focus_score: u32,
    pub active_segments: u32,
    pub idle_segments: u32,
    pub total_keystrokes: u32,
    pub total_clicks: u32,
    pub app_categories: serde_json::Value,
    pub hash: String,
    pub parent_hash: String,
    pub llm_reasoning: Option<String>,
}

/// A minute-by-minute activity row within a slot, with its classified `state`
/// ("Productive" / "Meeting" / "Waste" / "Inactive" / "Tampered").
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SlotMinuteDetailView {
    pub timestamp: i64,
    pub keystroke_count: u32,
    pub mouse_click_count: u32,
    pub scroll_event_count: u32,
    pub active_app_name: String,
    pub active_window_title: String,
    pub low_entropy: bool,
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_db() -> Database {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("/tmp/tenby10_test_{}.db", timestamp));
        Database::new(path).unwrap()
    }

    #[test]
    fn test_unsigned_hash_chain_verifies_and_detects_edit() {
        let db = create_test_db();

        db.insert_slot_summary(
            1000,
            85,
            8,
            2,
            150,
            20,
            "{\"coding\": 10}",
            Some("Good"),
            "",
            None,
        )
        .unwrap();
        db.insert_slot_summary(
            1600,
            90,
            9,
            1,
            200,
            30,
            "{\"coding\": 10}",
            Some("Great"),
            "",
            None,
        )
        .unwrap();

        let latest_hash = db.get_latest_slot_hash().unwrap();
        assert!(!latest_hash.is_empty(), "Hash should not be empty");

        // Unsigned chain is internally consistent.
        assert!(db.verify_ledger_integrity("").unwrap().is_ok());

        // Editing a field the OLD hash ignored (idle_segments) is now caught,
        // because the hash covers the full payload.
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE slot_summaries SET idle_segments = 99 WHERE slot_start = 1000",
                [],
            )
            .unwrap();
        assert!(
            db.verify_ledger_integrity("").unwrap().is_err(),
            "a naive field edit must break the chain"
        );
    }

    #[test]
    fn test_v2_payload_binds_config_hash() {
        let mk = |scheme: u32, cfg: &str| {
            canonical_slot_payload(
                scheme, 1000, 80, 8, 2, 100, 10, "{}", None, "parent", "pub", cfg,
            )
        };
        // v2 folds the config hash into the signed payload, so changing it changes
        // the bytes that are hashed and signed.
        assert_ne!(mk(2, "cfgA"), mk(2, "cfgB"));
        assert!(mk(2, "cfgA").contains("cfgA"));
        // v1 rows omit the config hash entirely (back-compat): the arg is ignored.
        assert!(!mk(1, "cfgA").contains("cfgA"));
    }

    #[test]
    fn test_v2_canonical_vector_matches_cloud() {
        // Cross-language alignment vector (#62). The cloud verifier's
        // canonicalSlotPayload() (cloud/src/lib/ledger.ts) MUST produce this exact
        // string for the same inputs, or signatures won't verify. The same literal
        // is asserted in the cloud's ledger.test.ts — keep both in lock-step.
        let got = canonical_slot_payload(
            2,
            1000,
            80,
            8,
            2,
            100,
            10,
            "{}",
            None,
            "PARENT",
            "PUBKEY",
            "CONFIGHASH",
        );
        let expected = "tenby10-slot|v2|PUBKEY|1000|80|8|2|100|10|\
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a|\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|CONFIGHASH|PARENT";
        assert_eq!(got, expected);
    }

    #[test]
    fn test_unsigned_row_recompute_is_not_detected() {
        // Honest limitation (ADR 0014): with no signature, an attacker who
        // recomputes the hash after editing defeats a purely-local chain. This
        // test locks that intended scope so we don't over-claim.
        let db = create_test_db();
        db.insert_slot_summary(1000, 50, 5, 5, 10, 2, "{}", None, "", None)
            .unwrap();

        let forged = canonical_slot_payload(
            LEDGER_SCHEME_VERSION,
            1000,
            100, // inflated focus
            5,
            5,
            10,
            2,
            "{}",
            None,
            "", // parent_hash of first row
            "", // unsigned
            "", // config_hash
        );
        let forged_hash = sha256_hex(&forged);
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE slot_summaries SET focus_score = 100, hash = ?1 WHERE slot_start = 1000",
                params![forged_hash],
            )
            .unwrap();

        assert!(
            db.verify_ledger_integrity("").unwrap().is_ok(),
            "unsigned recompute is intentionally not detectable — this is why signing exists"
        );
    }

    #[test]
    fn test_signed_slot_roundtrip_and_wrong_key_rejected() {
        let db = create_test_db();
        let keys = crate::config::generate_enrollment_keys("tok");
        let signer = SlotSigner {
            public_key: &keys.public_key,
            private_key: &keys.private_key,
        };

        db.insert_slot_summary(1000, 80, 8, 2, 100, 10, "{}", Some("r"), "", Some(&signer))
            .unwrap();
        db.insert_slot_summary(1600, 90, 9, 1, 120, 12, "{}", None, "", Some(&signer))
            .unwrap();

        // Valid signatures verify against the enrolled key.
        assert!(
            db.verify_ledger_integrity(&keys.public_key)
                .unwrap()
                .is_ok()
        );

        // A different enrolled identity must be rejected.
        let other = crate::config::generate_enrollment_keys("tok2");
        assert!(
            db.verify_ledger_integrity(&other.public_key)
                .unwrap()
                .is_err(),
            "a slot signed by a different key must not verify for this identity"
        );
    }

    #[test]
    fn test_signature_defeats_the_recompute_attack() {
        // The core #84 property: even if an attacker fixes the hash after editing
        // a field (the attack that beats the unsigned chain), they cannot re-sign
        // without the private key, so the signature check catches it.
        let db = create_test_db();
        let keys = crate::config::generate_enrollment_keys("tok");
        let signer = SlotSigner {
            public_key: &keys.public_key,
            private_key: &keys.private_key,
        };
        db.insert_slot_summary(1000, 50, 5, 5, 10, 2, "{}", None, "", Some(&signer))
            .unwrap();

        // Attacker inflates focus and recomputes a matching hash (leaving the
        // now-stale signature in place — they lack the key to forge a new one).
        let forged = canonical_slot_payload(
            LEDGER_SCHEME_VERSION,
            1000,
            100,
            5,
            5,
            10,
            2,
            "{}",
            None,
            "",
            &keys.public_key,
            "",
        );
        let forged_hash = sha256_hex(&forged);
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE slot_summaries SET focus_score = 100, hash = ?1 WHERE slot_start = 1000",
                params![forged_hash],
            )
            .unwrap();

        let result = db.verify_ledger_integrity(&keys.public_key).unwrap();
        assert!(
            result.is_err(),
            "signature must reject a re-hashed but un-re-signed row"
        );
    }

    #[test]
    fn test_billable_slots_gate() {
        let db = create_test_db();

        // Slot timestamps must land in "today" so get_today_metrics picks them up.
        let today_midnight = chrono::Local::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_local_timezone(chrono::Local)
            .unwrap()
            .timestamp();

        // Red slot: below the gate -> not billable.
        db.insert_slot_summary(
            today_midnight,
            BILLABLE_FOCUS_THRESHOLD - 10,
            3,
            7,
            10,
            2,
            "{}",
            None,
            "",
            None,
        )
        .unwrap();
        // Orange slot: exactly at the gate -> billable.
        db.insert_slot_summary(
            today_midnight + 600,
            BILLABLE_FOCUS_THRESHOLD,
            4,
            6,
            40,
            5,
            "{}",
            None,
            "",
            None,
        )
        .unwrap();
        // Green slot: well above the gate -> billable.
        db.insert_slot_summary(
            today_midnight + 1200,
            90,
            9,
            1,
            200,
            30,
            "{}",
            None,
            "",
            None,
        )
        .unwrap();
        // Fully-idle slot (focus_score 0): NOT logged, excluded from every aggregate.
        db.insert_slot_summary(today_midnight + 1800, 0, 0, 10, 0, 0, "{}", None, "", None)
            .unwrap();

        let (avg, active, _k, _c, scores, logged_slots, billable_slots) =
            db.get_today_metrics().unwrap();

        assert_eq!(logged_slots, 3, "only slots with focus > 0 are logged");
        assert_eq!(
            billable_slots, 2,
            "only slots at/above the gate are billable"
        );
        assert_eq!(scores.len(), 3, "timeline shows exactly the logged slots");
        // Countability contract: active minutes reconstruct from the slot count.
        assert_eq!(
            active,
            logged_slots * 10,
            "active time is logged slots x 10"
        );
        assert_eq!(active, 30, "3 logged 10-minute slots == 30 minutes");
        // Focus averages over logged slots only (30 + 40 + 90) / 3 == 53.
        assert_eq!(avg, 53, "focus averages over logged slots, idle excluded");
    }

    #[test]
    fn test_get_recent_slot_summaries_shape_and_order() {
        let db = create_test_db();

        db.insert_slot_summary(
            1000,
            30,
            3,
            7,
            50,
            5,
            "{\"coding\": 8}",
            Some("focused work"),
            "",
            None,
        )
        .unwrap();
        db.insert_slot_summary(1600, 85, 9, 1, 200, 30, "{\"coding\": 10}", None, "", None)
            .unwrap();

        let slots = db.get_recent_slot_summaries(1000).unwrap();
        assert_eq!(slots.len(), 2);
        // Newest first.
        assert_eq!(slots[0].slot_start, 1600);
        assert_eq!(slots[1].slot_start, 1000);
        // app_categories is parsed into JSON, not a raw string.
        assert_eq!(slots[1].app_categories["coding"], 8);
        assert_eq!(slots[1].llm_reasoning.as_deref(), Some("focused work"));
        // The LIMIT is honoured.
        assert_eq!(db.get_recent_slot_summaries(1).unwrap().len(), 1);
    }

    #[test]
    fn test_get_slot_minute_details_classifies_state() {
        let db = create_test_db();
        let slot_start = 600;

        // A productive minute (keystrokes in a neutral app) ...
        db.insert_minute_log(slot_start + 60, 120, 5, 2, 300.0, "Code", "main.rs", false)
            .unwrap();
        // ... and a fully idle minute (no input at all).
        db.insert_minute_log(slot_start + 120, 0, 0, 0, 0.0, "Finder", "", false)
            .unwrap();

        let details = db.get_slot_minute_details(slot_start).unwrap();
        assert_eq!(
            details.len(),
            2,
            "both minute logs in the window are returned"
        );
        // Rows are ordered by timestamp ascending and carry a classified state.
        assert_eq!(details[0].active_app_name, "Code");
        assert_eq!(details[0].state, "Productive");
        assert_eq!(details[1].state, "Inactive");
    }

    #[test]
    fn test_export_minute_logs_csv_header_and_rows() {
        let db = create_test_db();
        db.insert_minute_log(1000, 10, 2, 1, 42.5, "Code", "a\"b", false)
            .unwrap();

        let csv = db.export_minute_logs_csv("all", None, None).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("datetime,app_name,window_title"));
        assert_eq!(lines.len(), 2, "header + one data row");
        // Embedded quotes are CSV-escaped by doubling.
        assert!(lines[1].contains("\"a\"\"b\""));
        assert!(lines[1].ends_with(",1000"));

        // A window that excludes the row yields just the header.
        let empty = db
            .export_minute_logs_csv("custom", Some(2000), Some(3000))
            .unwrap();
        assert_eq!(empty.lines().count(), 1);
    }
}
