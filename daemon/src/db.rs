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

/// Aggregation semantics **v1** (ADR 0017 = ADR 0012 + ADR 0013), as a pure function over
/// per-slot focus scores so it is the single, golden-vector-tested definition. The cloud verifier
/// mirrors this exactly (`tenby10-cloud/src/lib/aggregation.ts`) and both CIs assert the same
/// fixture, so the two can't silently drift.
///   - logged  = slots with `focus_score > 0` (fully-idle dropped)
///   - billable = logged slots with `focus_score >= 40`
///   - focus_avg = mean focus over logged slots
///   - billable_minutes = billable × 10 (ADR 0007)
#[derive(Debug, PartialEq, Eq)]
pub struct AggregatesV1 {
    pub logged: u32,
    pub billable: u32,
    pub focus_avg: u32,
    pub billable_minutes: u32,
}

pub fn aggregate_v1(focus_scores: &[u32]) -> AggregatesV1 {
    let logged: Vec<u32> = focus_scores.iter().copied().filter(|&f| f > 0).collect();
    let logged_count = logged.len() as u32;
    let billable = logged
        .iter()
        .filter(|&&f| f >= BILLABLE_FOCUS_THRESHOLD)
        .count() as u32;
    let focus_avg = if logged_count > 0 {
        (logged.iter().map(|&f| f as f64).sum::<f64>() / logged_count as f64).round() as u32
    } else {
        0
    };
    AggregatesV1 {
        logged: logged_count,
        billable,
        focus_avg,
        billable_minutes: billable * 10,
    }
}

/// Version of the slot signing/hashing scheme (ADR 0014). Bumped when the
/// canonical payload format changes so old rows still verify under their scheme.
/// v2 (#62) binds the effective-config hash into the payload; v1 rows omit it.
/// v3 (#50) additionally bound a screenshot evidence count.
/// v4 (ADR 0018) drops that field again — screenshots no longer exist — so its
/// payload is the v2 shape under a new version number. v3 is *not* removed: rows
/// signed under it must keep verifying byte-for-byte, forever.
pub const LEDGER_SCHEME_VERSION: u32 = 4;

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
    /// Blurred screenshots backing this slot (v3+; 0 on older rows).
    pub screenshot_count: u32,
}

/// The signable fields of a stored slot, read back for re-chaining in [`Database::reseal_from`].
struct StoredSlotRow {
    slot_start: i64,
    focus_score: u32,
    active_segments: u32,
    idle_segments: u32,
    total_keystrokes: u32,
    total_clicks: u32,
    app_categories: String,
    llm_reasoning: Option<String>,
    config_hash: String,
    scheme_version: u32,
    screenshot_count: u32,
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
    screenshot_count: u32,
) -> String {
    // v3 (#50) bound how many blurred screenshots backed the slot. ADR 0018 removed
    // the screenshot subsystem, so v4 returns to the v2 field set — but v3 rows keep
    // hashing exactly as they were signed. Hence an exact match, not `>= 3`.
    if scheme_version == 3 {
        return format!(
            "tenby10-slot|v{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
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
            screenshot_count,
            parent_hash,
        );
    }
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
                config_hash TEXT NOT NULL DEFAULT '',
                screenshot_count INTEGER NOT NULL DEFAULT 0
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
        // Screenshot evidence (#50). Existing rows default to 0 — which is also the
        // truth for them, since capture never worked before v0.2.5 (#47).
        let _ = conn.execute(
            "ALTER TABLE slot_summaries ADD COLUMN screenshot_count INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // The effective-config blob for every hash we've scored a slot under, so any slot can be
        // backfilled to the cloud on demand — even after the config later changes (#80). The cloud
        // rejects a slot whose config it lacks; we look the blob up here and upload it, then retry.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config_blobs (config_hash TEXT PRIMARY KEY, blob TEXT NOT NULL)",
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
             total_clicks, app_categories, llm_reasoning, hash, parent_hash, signature, scheme_version, config_hash, screenshot_count \
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
                screenshot_count: r.get(13)?,
            })
        })?;
        rows.collect()
    }

    /// Persist the effective-config blob for a hash so any slot referencing it can be backfilled to
    /// the cloud on demand, even after the config later changes (#80). Idempotent; keyed by the
    /// content hash, so re-storing the same (hash, blob) is a no-op.
    pub fn store_config_blob(&self, config_hash: &str, blob: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO config_blobs (config_hash, blob) VALUES (?1, ?2)",
            params![config_hash, blob],
        )?;
        Ok(())
    }

    /// The stored effective-config blob for a hash, or `None` if we never scored a slot under it.
    pub fn get_config_blob(&self, config_hash: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT blob FROM config_blobs WHERE config_hash = ?1")?;
        let mut rows = stmt.query(params![config_hash])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// One-shot recovery (#19): re-base the ledger suffix `slot_start >= from` into a fresh chain
    /// under the current key so it can finally sync, and neutralize the orphaned prefix.
    ///
    /// Why this exists: slots captured before enrollment (unsigned) or under a rotated key leave a
    /// chain that doesn't start at genesis and/or isn't signed by the agent's registered key. The
    /// cloud requires a contiguous chain from `parent_hash=""` under that key, and the client
    /// uploads oldest-first and stops at the first rejection — so the whole ledger is stuck.
    ///
    /// What it does, in one transaction:
    ///   1. Marks every slot *before* `from` as `synced` so the orphaned prefix can't block the
    ///      oldest-first sync (those slots are abandoned, never uploaded).
    ///   2. Re-chains the `>= from` window in `slot_start` order: the first slot gets
    ///      `parent_hash=""`, every slot is re-hashed with `signer`'s public key folded into the
    ///      canonical payload (matching [`canonical_slot_payload`]) and re-signed, and `synced`
    ///      is reset to 0 so the normal sync sends them.
    ///
    /// The stored metrics/timestamps are untouched — only the chain links, signature, and signing
    /// key are rewritten. Returns the number of slots resealed. **Only safe before the current key
    /// has ever successfully synced**, since it rewrites history the cloud would otherwise pin.
    pub fn reseal_from(&self, from: i64, signer: &SlotSigner) -> Result<usize> {
        let sk_bytes: [u8; 32] = from_hex(signer.private_key)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                rusqlite::Error::InvalidParameterName("signer private_key is not 32 bytes".into())
            })?;
        let sk = SigningKey::from_bytes(&sk_bytes);

        let conn = self.conn.lock().unwrap();
        conn.execute_batch("BEGIN")?;

        // 1. Abandon the orphaned prefix so it can never poison the oldest-first sync.
        conn.execute(
            "UPDATE slot_summaries SET synced = 1 WHERE slot_start < ?1",
            params![from],
        )?;

        // 2. Load the window in chain order, then re-chain + re-sign it from genesis.
        let rows: Vec<StoredSlotRow> = {
            let mut stmt = conn.prepare(
                "SELECT slot_start, focus_score, active_segments, idle_segments, total_keystrokes,
                        total_clicks, app_categories, llm_reasoning, config_hash, scheme_version,
                        screenshot_count
                 FROM slot_summaries WHERE slot_start >= ?1 ORDER BY slot_start ASC",
            )?;
            let mapped = stmt.query_map(params![from], |r| {
                Ok(StoredSlotRow {
                    slot_start: r.get(0)?,
                    focus_score: r.get(1)?,
                    active_segments: r.get(2)?,
                    idle_segments: r.get(3)?,
                    total_keystrokes: r.get(4)?,
                    total_clicks: r.get(5)?,
                    app_categories: r.get(6)?,
                    llm_reasoning: r.get(7)?,
                    config_hash: r.get(8)?,
                    scheme_version: r.get(9)?,
                    screenshot_count: r.get(10)?,
                })
            })?;
            mapped.collect::<Result<_>>()?
        };

        let mut parent = String::new();
        for row in &rows {
            let payload = canonical_slot_payload(
                row.scheme_version,
                row.slot_start,
                row.focus_score,
                row.active_segments,
                row.idle_segments,
                row.total_keystrokes,
                row.total_clicks,
                &row.app_categories,
                row.llm_reasoning.as_deref(),
                &parent,
                signer.public_key,
                &row.config_hash,
                row.screenshot_count,
            );
            let hash = sha256_hex(&payload);
            let signature = to_hex_bytes(&sk.sign(payload.as_bytes()).to_bytes());
            conn.execute(
                "UPDATE slot_summaries
                 SET hash = ?1, parent_hash = ?2, signature = ?3, signing_pubkey = ?4, synced = 0
                 WHERE slot_start = ?5",
                params![hash, parent, signature, signer.public_key, row.slot_start],
            )?;
            parent = hash;
        }

        conn.execute_batch("COMMIT")?;
        Ok(rows.len())
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

        // v4 carries no screenshot count (ADR 0018); the column stays 0 on new rows
        // and keeps its historical value on v3 rows so those still verify.
        let screenshot_count = 0u32;

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
            screenshot_count,
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
                slot_start, focus_score, active_segments, idle_segments, total_keystrokes, total_clicks, app_categories, hash, parent_hash, llm_reasoning, signature, signing_pubkey, scheme_version, config_hash, screenshot_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                config_hash,
                screenshot_count
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

        // Total inputs count activity from every slot, logged or not. The logged / billable /
        // focus definitions all come from the shared v1 aggregator, so they can't drift from the
        // cloud verifier or the golden vectors (ADR 0017).
        let mut keystrokes = 0;
        let mut clicks = 0;
        let mut all_focus = Vec::new();

        while let Some(row) = rows.next()? {
            let focus_score: u32 = row.get(0)?;
            let k: u32 = row.get(1)?;
            let c: u32 = row.get(2)?;
            keystrokes += k;
            clicks += c;
            all_focus.push(focus_score);
        }

        let agg = aggregate_v1(&all_focus);
        // Per-slot focus values for logged (focus > 0) slots — the timeline/histogram input.
        let logged_scores: Vec<u32> = all_focus.into_iter().filter(|&f| f > 0).collect();
        // Slot-granular active time (ADR 0013): one logged 10-minute slot contributes 10 minutes,
        // so `active_minutes / 10 == logged_count`.
        let active_mins = agg.logged * 10;

        Ok((
            agg.focus_avg,
            active_mins,
            keystrokes,
            clicks,
            logged_scores,
            agg.logged,
            agg.billable,
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
            "SELECT slot_start, focus_score, active_segments, idle_segments, total_keystrokes, total_clicks, app_categories, hash, parent_hash, llm_reasoning, signature, signing_pubkey, scheme_version, config_hash, screenshot_count
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
            // v1/v2 rows predate the column; their canonical form ignores it anyway.
            let screenshot_count: u32 = row.get(14).unwrap_or(0);

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
                screenshot_count,
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
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A unique test-DB path per call: process id + a monotonic counter. A nanosecond timestamp
    /// (the previous scheme) could collide under parallel test execution — two tests then shared
    /// one SQLite file and one test's slots leaked into another's, flaking `reseal_from` counts.
    fn create_test_db() -> Database {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let path = PathBuf::from(format!("/tmp/tenby10_test_{unique}.db"));
        let _ = std::fs::remove_file(&path); // clear any stale file (pid reuse across runs)
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
                scheme, 1000, 80, 8, 2, 100, 10, "{}", None, "parent", "pub", cfg, 0,
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
            // v2 never carried this field. Passing a non-zero value must not change
            // the v2 string, or every already-signed v2 row would stop verifying.
            7,
        );
        let expected = "tenby10-slot|v2|PUBKEY|1000|80|8|2|100|10|\
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a|\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|CONFIGHASH|PARENT";
        assert_eq!(got, expected);
    }

    #[test]
    fn test_v3_canonical_vector_matches_cloud() {
        // Cross-language alignment vector (#50), reproduced in the doc comment on the
        // cloud's canonicalSlotPayload(). Keep both in lock-step.
        let got = canonical_slot_payload(
            3,
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
            1,
        );
        let expected = "tenby10-slot|v3|PUBKEY|1000|80|8|2|100|10|\
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a|\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|CONFIGHASH|1|PARENT";
        assert_eq!(got, expected);
    }

    #[test]
    fn test_v4_canonical_vector_matches_cloud() {
        // Cross-language alignment vector (ADR 0018), reproduced in the doc comment
        // on the cloud's canonicalSlotPayload(). Keep both in lock-step.
        //
        // v4 is the v2 field set under a new version number: the screenshot count
        // v3 appended is gone, because screenshots are gone.
        let got = canonical_slot_payload(
            4,
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
            0,
        );
        let expected = "tenby10-slot|v4|PUBKEY|1000|80|8|2|100|10|\
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a|\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|CONFIGHASH|PARENT";
        assert_eq!(got, expected);
    }

    #[test]
    fn test_v4_ignores_any_screenshot_count() {
        // The field is dead in v4: whatever is passed must not reach the payload,
        // so a stale non-zero value can never change a v4 hash.
        let zero = canonical_slot_payload(
            4,
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
            0,
        );
        let nonzero = canonical_slot_payload(
            4,
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
            7,
        );
        assert_eq!(zero, nonzero);
    }

    #[test]
    fn test_v3_rows_still_verify_after_the_v4_bump() {
        // Removing a feature must never invalidate history: a row signed under v3
        // keeps its own payload shape (count included) even though new rows are v4.
        let v3 = canonical_slot_payload(
            3,
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
            1,
        );
        assert!(
            v3.contains("|CONFIGHASH|1|PARENT"),
            "v3 keeps its count field"
        );
        assert!(v3.starts_with("tenby10-slot|v3|"));
    }

    #[test]
    fn test_v3_evidence_count_is_covered_by_the_signature() {
        // The point of binding the count: a slot with no screen evidence must not
        // hash identically to one with evidence, or the field would be cosmetic and
        // freely forgeable after signing.
        let with = canonical_slot_payload(
            3,
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
            1,
        );
        let without = canonical_slot_payload(
            3,
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
            0,
        );
        assert_ne!(with, without, "evidence count must be covered by the hash");
        assert!(without.contains("|CONFIGHASH|0|PARENT"));
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
            0,
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
            0,
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
    fn test_aggregation_vectors() {
        // Golden vectors (ADR 0017), mirrored byte-for-byte in tenby10-cloud
        // (src/lib/__fixtures__/aggregation-vectors.v1.json). Both CIs assert the same fixture, so
        // any drift between the Rust and TS implementations of v1 turns one of them red — the
        // guard rail the #78/#81 mismatches lacked.
        #[derive(serde::Deserialize)]
        struct Expected {
            logged: u32,
            billable: u32,
            focus_avg: u32,
            billable_minutes: u32,
        }
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            focus_scores: Vec<u32>,
            expected: Expected,
        }
        #[derive(serde::Deserialize)]
        struct Vectors {
            aggregation_version: u32,
            cases: Vec<Case>,
        }

        let raw = include_str!("testdata/aggregation-vectors.v1.json");
        let v: Vectors = serde_json::from_str(raw).expect("golden fixture parses");
        assert_eq!(v.aggregation_version, crate::config::AGGREGATION_VERSION);
        for c in v.cases {
            let got = aggregate_v1(&c.focus_scores);
            assert_eq!(got.logged, c.expected.logged, "logged mismatch: {}", c.name);
            assert_eq!(
                got.billable, c.expected.billable,
                "billable mismatch: {}",
                c.name
            );
            assert_eq!(
                got.focus_avg, c.expected.focus_avg,
                "focus_avg mismatch: {}",
                c.name
            );
            assert_eq!(
                got.billable_minutes, c.expected.billable_minutes,
                "billable_minutes mismatch: {}",
                c.name
            );
        }
    }

    #[test]
    fn test_config_blob_store_roundtrip() {
        let db = create_test_db();
        // Unknown hash -> None (the cloud would 428, and there'd be nothing to backfill).
        assert_eq!(db.get_config_blob("deadbeef").unwrap(), None);

        let blob = "{\"config_scheme\":2,\"aggregation_version\":1}";
        db.store_config_blob("deadbeef", blob).unwrap();
        assert_eq!(
            db.get_config_blob("deadbeef").unwrap().as_deref(),
            Some(blob)
        );

        // Idempotent: re-storing the same hash keeps the blob and does not error.
        db.store_config_blob("deadbeef", blob).unwrap();
        assert_eq!(
            db.get_config_blob("deadbeef").unwrap().as_deref(),
            Some(blob)
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

    /// Read a stored slot's chain columns for assertions: (parent_hash, hash, signature, pubkey, synced).
    fn slot_chain_cols(db: &Database, slot_start: i64) -> (String, String, String, String, i64) {
        let conn = db.conn.lock().unwrap();
        conn.query_row(
            "SELECT parent_hash, hash, signature, signing_pubkey, synced FROM slot_summaries WHERE slot_start = ?1",
            params![slot_start],
            |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(3)?.unwrap_or_default(), r.get(4)?)),
        )
        .unwrap()
    }

    #[test]
    fn test_reseal_from_genesis_rechains_and_resigns_whole_ledger() {
        let db = create_test_db();
        let old = crate::config::generate_enrollment_keys("old");
        let old_signer = SlotSigner {
            public_key: &old.public_key,
            private_key: &old.private_key,
        };
        // A chain signed under the OLD key (as after a re-pair that rotated the key).
        db.insert_slot_summary(
            1000,
            80,
            8,
            2,
            100,
            10,
            "{\"coding\":10}",
            Some("a"),
            "cfg",
            Some(&old_signer),
        )
        .unwrap();
        db.insert_slot_summary(
            1600,
            90,
            9,
            1,
            120,
            12,
            "{\"coding\":10}",
            Some("b"),
            "cfg",
            Some(&old_signer),
        )
        .unwrap();

        let new = crate::config::generate_enrollment_keys("new");
        let new_signer = SlotSigner {
            public_key: &new.public_key,
            private_key: &new.private_key,
        };
        // Reseal everything (from 0) under the new key: the whole ledger must now verify for it.
        let n = db.reseal_from(0, &new_signer).unwrap();
        assert_eq!(n, 2);
        assert!(
            db.verify_ledger_integrity(&new.public_key).unwrap().is_ok(),
            "resealed ledger must verify under the new key"
        );
        assert!(
            db.verify_ledger_integrity(&old.public_key)
                .unwrap()
                .is_err(),
            "it must no longer verify under the old key"
        );
        // First slot is genesis; both are unsynced and signed by the new key.
        let (p0, h0, _, k0, s0) = slot_chain_cols(&db, 1000);
        let (p1, _, _, k1, s1) = slot_chain_cols(&db, 1600);
        assert_eq!(p0, "", "first slot re-based to genesis");
        assert_eq!(p1, h0, "chain links forward");
        assert_eq!(k0, new.public_key);
        assert_eq!(k1, new.public_key);
        assert_eq!(
            (s0, s1),
            (0, 0),
            "resealed slots are marked unsynced for upload"
        );
    }

    #[test]
    fn test_reseal_from_window_skips_and_neutralizes_prefix() {
        let db = create_test_db();
        let key = crate::config::generate_enrollment_keys("k");
        let signer = SlotSigner {
            public_key: &key.public_key,
            private_key: &key.private_key,
        };
        // Orphaned prefix (unsigned) + an in-window suffix.
        db.insert_slot_summary(1000, 50, 5, 5, 10, 1, "{}", None, "cfg", None)
            .unwrap();
        db.insert_slot_summary(1600, 60, 6, 4, 20, 2, "{}", None, "cfg", None)
            .unwrap();
        db.insert_slot_summary(2000, 80, 8, 2, 30, 3, "{}", None, "cfg", None)
            .unwrap();
        db.insert_slot_summary(2600, 90, 9, 1, 40, 4, "{}", None, "cfg", None)
            .unwrap();

        let n = db.reseal_from(2000, &signer).unwrap();
        assert_eq!(n, 2, "only the window is resealed");

        // Prefix is abandoned (marked synced so it can't block the oldest-first sync).
        assert_eq!(slot_chain_cols(&db, 1000).4, 1);
        assert_eq!(slot_chain_cols(&db, 1600).4, 1);

        // Window is a fresh genesis chain, signed and valid under the current key.
        let (p2000, h2000, sig2000, k2000, s2000) = slot_chain_cols(&db, 2000);
        let (p2600, _, _, _, s2600) = slot_chain_cols(&db, 2600);
        assert_eq!(p2000, "", "window starts at genesis");
        assert_eq!(p2600, h2000, "window chains forward");
        assert_eq!(k2000, key.public_key);
        assert_eq!((s2000, s2600), (0, 0));

        // The re-signature is authentic: hash == sha256(canonical) and the signature verifies.
        let canonical = canonical_slot_payload(
            LEDGER_SCHEME_VERSION,
            2000,
            80,
            8,
            2,
            30,
            3,
            "{}",
            None,
            &p2000,
            &key.public_key,
            "cfg",
            0,
        );
        assert_eq!(
            sha256_hex(&canonical),
            h2000,
            "hash recomputes from the resealed canonical"
        );
        assert!(
            verify_slot_signature(&canonical, &sig2000, &key.public_key).unwrap(),
            "resealed signature verifies under the current key"
        );
    }
}
