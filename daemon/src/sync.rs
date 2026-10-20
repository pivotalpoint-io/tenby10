//! Cloud enrollment and slot upload (#115).
//!
//! Two HTTP steps talk to the portal:
//!   1. [`enroll_with_cloud`] exchanges the pairing token + public key for an agent id.
//!   2. [`sync_signed_slots`] uploads signed slots in chain order.
//!
//! Only signed slots are uploaded, and the AI reasoning text never leaves the device —
//! only its SHA-256 (`reasoning_hash`) is sent.

use crate::db::{Database, sha256_hex_pub};

/// Production portal base URL; override with `TENBY10_CLOUD_URL` for local runs.
const DEFAULT_CLOUD_URL: &str = "https://tenby10.pivotalpoint.io";

/// The portal base URL, honouring the `TENBY10_CLOUD_URL` override.
pub fn cloud_base_url() -> String {
    resolve_cloud_base_url(std::env::var("TENBY10_CLOUD_URL").ok().as_deref())
}

/// Pure form of [`cloud_base_url`], so the fallback is testable without mutating process
/// environment from a test (the same shape as `env::debug_http_enabled_from`).
///
/// The override runs through [`crate::llm::validate_base_url`] — the check already written
/// for the LLM endpoint, reused rather than rewritten, because the two carry the same class
/// of data. What goes to this URL is signed slots, work-note prose and, at enrollment, the
/// pairing token, so it gets the same rule: https everywhere, plain http only for loopback.
/// Loopback matters — running the portal locally against `http://localhost:3000` is how cloud
/// development works, and that stays exactly as it was.
///
/// Setting an environment variable already implies code execution as this user, so this is a
/// guard rail rather than a boundary: it catches a stale export or a typo'd host, not an
/// attacker who is already inside. A rejected value falls back to production instead of
/// failing the sync, because refusing to run would be a worse answer than uploading to the
/// place the records were always meant to go — but it says so loudly, since a developer who
/// set the variable on purpose needs to know it was ignored.
fn resolve_cloud_base_url(override_value: Option<&str>) -> String {
    let Some(raw) = override_value.map(str::trim).filter(|v| !v.is_empty()) else {
        return DEFAULT_CLOUD_URL.to_string();
    };
    match crate::llm::validate_base_url(raw) {
        Ok(()) => raw.to_string(),
        Err(err) => {
            eprintln!(
                "[WARN] Ignoring TENBY10_CLOUD_URL={raw}: {err}. Signed slots, work notes and \
                 the enrollment token travel to this URL. Using {DEFAULT_CLOUD_URL} instead."
            );
            DEFAULT_CLOUD_URL.to_string()
        }
    }
}

/// Exchange the pairing token + hex public key for the cloud agent id.
/// `POST {base}/api/v1/enroll` with `{ token, publicKey }` → `{ agentId }`.
pub async fn enroll_with_cloud(
    base_url: &str,
    token: &str,
    public_key_hex: &str,
) -> Result<String, String> {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/api/v1/enroll"))
        .json(&serde_json::json!({ "token": token, "publicKey": public_key_hex }))
        .send()
        .await
        .map_err(|e| format!("enrollment request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("enrollment rejected: HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("could not read enrollment response: {e}"))?;
    body.get("agentId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "enrollment response had no agentId".to_string())
}

/// The ingest endpoints reply 428 when a blob a record references isn't stored server-side yet:
/// a slot's effective config (#80), or a note's prompt (#147).
const PRECONDITION_REQUIRED: u16 = 428;

/// HTTP 409: the record contradicts one the cloud already holds.
const CONFLICT: u16 = 409;

/// Upload the blob for `config_hash` from the local store so the cloud can resolve a record that
/// references it. `/api/v1/config` is a plain sha256-keyed blob store, so it carries both kinds of
/// blob we have to make resolvable: the effective config a slot was scored under (#80) and the
/// prompt a work note was written with (#147). The server authenticates with
/// `sha256(blob) == config_hash` and stores it idempotently. Errors if we have no local blob for
/// the hash — which shouldn't happen, since both are persisted before the record that names them.
fn upload_config(
    db: &Database,
    agent_id: &str,
    base_url: &str,
    config_hash: &str,
) -> Result<(), String> {
    let blob = db
        .get_config_blob(config_hash)
        .map_err(|e| format!("config-blob db read failed: {e}"))?
        .ok_or_else(|| format!("no local config blob for {config_hash}"))?;

    let resp = reqwest::blocking::Client::new()
        .post(format!("{base_url}/api/v1/config"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "config_hash": config_hash,
            "config_blob": blob,
        }))
        .send()
        .map_err(|e| format!("config upload request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("config upload rejected: HTTP {}", resp.status()));
    }
    Ok(())
}

/// Build the ADR-0014 slot upload payload. Only the SHA-256 of `llm_reasoning` is sent.
fn slot_payload(agent_id: &str, slot: &crate::db::SignedSlot) -> serde_json::Value {
    serde_json::json!({
        "agent_id": agent_id,
        "scheme_version": slot.scheme_version,
        "slot_start": slot.slot_start,
        "metrics": {
            "focus_score": slot.focus_score,
            "active_segments": slot.active_segments,
            "idle_segments": slot.idle_segments,
            "total_keystrokes": slot.total_keystrokes,
            "total_clicks": slot.total_clicks,
            "app_categories": slot.app_categories,
        },
        "reasoning_hash": sha256_hex_pub(slot.llm_reasoning.as_deref().unwrap_or("")),
        "config_hash": slot.config_hash,
        // Still sent because an unsynced v3 row must upload with the count it was
        // signed under, or the cloud cannot re-derive its canonical string. v4 rows
        // (ADR 0018) carry 0 here and the cloud ignores the field for them.
        "screenshot_count": slot.screenshot_count,
        "ledger": { "hash": slot.hash, "parent_hash": slot.parent_hash },
        "signature": slot.signature,
    })
}

/// Upload not-yet-synced signed slots, oldest first, marking each on success. Stops at the first
/// rejection (the chain must land in order). Returns the number uploaded this call.
///
/// If the cloud rejects a slot because it doesn't yet hold the referenced config (428), we upload
/// that config from the local store and retry the slot once (#80). Config presence is therefore
/// guaranteed before a slot lands — a verified link can never reference a rubric/version the cloud
/// can't resolve — with no speculative pre-upload and no local "already sent" cache to go stale.
///
/// With `signer`, unsent slots that still link to a slot recorded before pairing are first
/// re-linked onto the shared record ([`Database::relink_unsent_slots`], #180), so the first
/// upload starts where the cloud's record for the key starts.
pub fn sync_signed_slots(
    db: &Database,
    agent_id: &str,
    base_url: &str,
    signer: Option<&crate::db::SlotSigner>,
) -> Result<usize, String> {
    if agent_id.is_empty() {
        return Ok(0);
    }
    if let Some(signer) = signer {
        match db.relink_unsent_slots(signer) {
            Ok(n) if n > 0 => println!("[Sync] Re-linked {n} unsent slot(s) to the shared record."),
            Ok(_) => {}
            Err(e) => eprintln!("[Sync] could not re-link unsent slots: {e}"),
        }
    }
    let slots = db
        .get_unsynced_signed_slots(100)
        .map_err(|e| format!("could not read unsynced slots: {e}"))?;

    let client = reqwest::blocking::Client::new();
    let url = format!("{base_url}/api/v1/slots");
    let mut uploaded = 0usize;

    for slot in slots {
        let payload = slot_payload(agent_id, &slot);
        let mut resp = client
            .post(&url)
            .json(&payload)
            .send()
            .map_err(|e| format!("slot upload request failed: {e}"))?;

        if resp.status().as_u16() == PRECONDITION_REQUIRED {
            upload_config(db, agent_id, base_url, &slot.config_hash)?;
            resp = client
                .post(&url)
                .json(&payload)
                .send()
                .map_err(|e| format!("slot re-upload after config backfill failed: {e}"))?;
        }

        if !resp.status().is_success() {
            return Err(format!(
                "slot {} rejected: HTTP {} — stopping this sync",
                slot.slot_start,
                resp.status()
            ));
        }
        db.mark_slot_synced(slot.slot_start)
            .map_err(|e| format!("could not mark slot {} synced: {e}", slot.slot_start))?;
        uploaded += 1;
    }
    Ok(uploaded)
}

/// How long a note sits on the worker's machine before it can travel (ADR 0019).
///
/// This is the correction window. There is no approval step and nothing waits on the
/// worker, so what protects them from a bad note reaching a client is time: the note
/// appears in their own dashboard first, and they can revise or withdraw it. Twelve
/// hours means a note written at the close of one day leaves around the middle of the
/// next — after an ordinary person has had a morning to look.
pub const SUMMARY_CORRECTION_WINDOW_SECS: i64 = 12 * 3600;

/// How long past its correction window an unsent note counts as held up (#176).
///
/// A note normally uploads within minutes of clearing the window. A day of slack keeps
/// an ordinary offline evening or a closed lid from raising the dashboard notice, while
/// still surfacing a stall the day after it starts.
pub const NOTE_UPLOAD_OVERDUE_SECS: i64 = 24 * 3600;

fn summary_payload(agent_id: &str, note: &crate::db::WorkSummary) -> serde_json::Value {
    serde_json::json!({
        "agent_id": agent_id,
        "scheme_version": note.scheme_version,
        "period_start": note.period_start,
        "period_end": note.period_end,
        "generated_at": note.generated_at,
        "revision": note.revision,
        // The text itself travels: it exists to be read by whoever receives a link.
        // Its SHA-256 is inside the signature, so what lands is provably what was signed.
        "summary_text": note.summary_text,
        "prompt_hash": note.prompt_hash,
        "ledger": { "hash": note.hash, "parent_hash": note.parent_hash },
        "signature": note.signature,
    })
}

fn withdrawal_payload(agent_id: &str, record: &crate::db::WorkSummary) -> serde_json::Value {
    serde_json::json!({
        "agent_id": agent_id,
        "scheme_version": record.scheme_version,
        "period_start": record.period_start,
        // The withdrawal's own moment; `generated_at` is when the decision was taken.
        "withdrawn_at": record.generated_at,
        "ledger": { "hash": record.hash, "parent_hash": record.parent_hash },
        "signature": record.signature,
    })
}

/// Upload work notes that have cleared the correction window, oldest first (ADR 0019),
/// and withdrawals as soon as they exist.
///
/// Stops at the first rejection, like slots: notes are a hash chain too, and a gap would
/// break every record behind it. Withdrawn notes are never uploaded — withdrawing before
/// the window closes means the note simply never travels — but the *withdrawal record*
/// always is, because a note that already left needs taking back.
///
/// A note rejected because the cloud lacks its prompt (428) is retried once after uploading
/// that prompt, so the words and the rules behind them always arrive together (#147).
///
/// A note refused because the cloud already holds a different note for that day and
/// revision (409 `summary_conflict`) is a second note this machine wrote for a day it had
/// already uploaded. With `signer` set, it is removed and the unsent records behind it are
/// re-chained ([`Database::drop_unsent_duplicate_note`]), and they upload on the next sync
/// (#176).
pub fn sync_work_summaries(
    db: &Database,
    agent_id: &str,
    base_url: &str,
    now_ts: i64,
    signer: Option<&crate::db::SlotSigner>,
) -> Result<usize, String> {
    if agent_id.is_empty() {
        return Ok(0);
    }
    // A chain held up by notes from before pairing heals before anything is offered
    // (#179). Cheap when the chain is whole: one read of the links, nothing written.
    if let Some(signer) = signer {
        match db.relink_summary_chain(signer) {
            Ok(0) => {}
            Ok(n) => println!(
                "[Sync] Re-linked {n} unsent work note record(s) behind notes kept on this \
                 machine. They upload as their correction window ends."
            ),
            Err(e) => return Err(format!("could not re-link the work note chain: {e}")),
        }
    }
    let notes = db
        .get_unsynced_summaries(now_ts, SUMMARY_CORRECTION_WINDOW_SECS, 50)
        .map_err(|e| format!("could not read unsynced work notes: {e}"))?;

    let client = reqwest::blocking::Client::new();
    let notes_url = format!("{base_url}/api/v1/summaries");
    let withdrawals_url = format!("{base_url}/api/v1/summaries/withdraw");
    let mut uploaded = 0usize;

    for record in notes {
        let is_withdrawal = record.kind == "withdrawal";
        let (url, payload) = if is_withdrawal {
            (&withdrawals_url, withdrawal_payload(agent_id, &record))
        } else {
            (&notes_url, summary_payload(agent_id, &record))
        };

        let mut resp = client
            .post(url)
            .json(&payload)
            .send()
            .map_err(|e| format!("work note upload request failed: {e}"))?;

        // The cloud won't take a note until it holds the prompt that wrote it, so a recipient
        // can always read the rules behind the words (#147). Backfill the prompt from the local
        // blob store and retry once — the same shape as a slot's config (#80), and for the same
        // reason: presence cloud-side is decided cloud-side, never from a local "already sent"
        // marker. Withdrawals name no prompt, so they never take this path.
        if resp.status().as_u16() == PRECONDITION_REQUIRED && !is_withdrawal {
            upload_config(db, agent_id, base_url, &record.prompt_hash)?;
            resp = client
                .post(url)
                .json(&payload)
                .send()
                .map_err(|e| format!("note re-upload after prompt backfill failed: {e}"))?;
        }

        if resp.status().as_u16() == CONFLICT && !is_withdrawal {
            let code = resp
                .json::<serde_json::Value>()
                .ok()
                .and_then(|body| body.get("error")?.as_str().map(str::to_owned));
            if code.as_deref() == Some("summary_conflict") {
                return match signer.map(|s| db.drop_unsent_duplicate_note(record.id, s)) {
                    Some(Ok(Some(rechained))) => {
                        println!(
                            "[Sync] The cloud already holds the note for {}, so the second \
                             note this machine wrote for that day was removed and {rechained} \
                             unsent record(s) behind it were re-chained. They upload next sync.",
                            record.period_start
                        );
                        Ok(uploaded)
                    }
                    Some(Err(e)) => Err(format!(
                        "could not re-chain the notes after {}: {e}",
                        record.period_start
                    )),
                    _ => Err(format!(
                        "work note for {} rejected: the cloud holds a different note for that \
                         day — stopping this sync",
                        record.period_start
                    )),
                };
            }
            return Err(format!(
                "work note for {} rejected: HTTP 409 — stopping this sync",
                record.period_start
            ));
        }

        if !resp.status().is_success() {
            return Err(format!(
                "{} for {} rejected: HTTP {} — stopping this sync",
                if is_withdrawal {
                    "withdrawal"
                } else {
                    "work note"
                },
                record.period_start,
                resp.status()
            ));
        }
        db.mark_summary_synced(record.id)
            .map_err(|e| format!("could not mark record {} synced: {e}", record.id))?;
        uploaded += 1;
    }
    Ok(uploaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read one whole HTTP request and return its body, so the client never sees a reset
    /// mid-send.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap();
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf);
            if let Some(head_end) = text.find("\r\n\r\n") {
                let length = text[..head_end]
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= head_end + 4 + length {
                    return text[head_end + 4..].to_string();
                }
            }
            if n == 0 {
                return String::new();
            }
        }
    }

    fn reply(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        use std::io::Write;
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).unwrap();
    }

    /// Serve exactly one HTTP request on loopback with a fixed status and JSON body, and
    /// return the base URL. Enough to drive one upload attempt without a cloud.
    fn one_shot_server(status: &'static str, body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            reply(&mut stream, status, body);
        });
        format!("http://{addr}")
    }

    /// Stand in for the cloud's slot ledger for a newly paired key: accept a slot only when
    /// its parent is the current head, which starts at genesis, as `ingestSlot` does.
    /// Serves `requests` uploads and returns the base URL.
    fn ledger_server(requests: usize) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut head = String::new();
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let slot: serde_json::Value =
                    serde_json::from_str(&read_request(&mut stream)).unwrap();
                if slot["ledger"]["parent_hash"] == head.as_str() {
                    head = slot["ledger"]["hash"].as_str().unwrap().to_string();
                    reply(&mut stream, "200 OK", r#"{"accepted":true}"#);
                } else {
                    reply(&mut stream, "409 Conflict", r#"{"error":"chain_broken"}"#);
                }
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn test_hours_tracked_before_pairing_do_not_hold_up_hours_after_pairing() {
        // Tracking runs before pairing (#180). A database from the previous build has its
        // first signed slot linked to one of those slots, and one new slot is signed under
        // this build. Sync re-links the unsent slots, and the cloud accepts all of them.
        let path =
            std::env::temp_dir().join(format!("tenby10_sync_pairing_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Database::new(path.clone()).unwrap();
        let keys = crate::config::generate_enrollment_keys("tok");
        let signer = crate::db::SlotSigner {
            public_key: &keys.public_key,
            private_key: &keys.private_key,
        };
        db.insert_slot_summary(1000, 70, 7, 3, 50, 5, "{}", None, "cfg", None)
            .unwrap();
        db.insert_signed_slot_linked_to_latest(1600, 80, &signer);
        db.insert_signed_slot_linked_to_latest(2200, 90, &signer);
        db.insert_slot_summary(2800, 85, 8, 2, 90, 9, "{}", None, "cfg", Some(&signer))
            .unwrap();

        let base = ledger_server(3);
        let uploaded = sync_signed_slots(&db, "agent", &base, Some(&signer)).unwrap();
        assert_eq!(uploaded, 3, "every hour signed after pairing uploads");
        assert!(db.get_unsynced_signed_slots(100).unwrap().is_empty());
        assert!(
            db.verify_ledger_integrity(&keys.public_key)
                .unwrap()
                .is_ok()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_conflicting_duplicate_note_is_set_aside_and_the_chain_recovers() {
        // The cloud refuses a second original for a day it already holds (#176). Sync
        // removes that local duplicate and re-chains what was behind it, so the next sync
        // starts from the cloud's head instead of retrying the same refusal forever.
        let path =
            std::env::temp_dir().join(format!("tenby10_sync_conflict_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Database::new(path.clone()).unwrap();
        let keys = crate::config::generate_enrollment_keys("tok");
        let signer = crate::db::SlotSigner {
            public_key: &keys.public_key,
            private_key: &keys.private_key,
        };

        let kept = db.append_note_unchecked(86_400, "Day one.", 200_000, &signer);
        db.mark_summary_synced(kept).unwrap();
        let duplicate = db.append_note_unchecked(86_400, "Day one, again.", 200_060, &signer);
        db.insert_work_summary(172_800, 259_200, "Day two.", 300_000, "ph", Some(&signer))
            .unwrap();

        let base = one_shot_server(
            "409 Conflict",
            r#"{"error":"summary_conflict","message":"A different note already exists."}"#,
        );
        let now = 1_000_000;
        let uploaded = sync_work_summaries(&db, "agent", &base, now, Some(&signer)).unwrap();
        assert_eq!(uploaded, 0);

        let queue = db.get_unsynced_summaries(now, 0, 50).unwrap();
        assert!(
            queue.iter().all(|n| n.id != duplicate),
            "the duplicate is no longer queued"
        );
        let head_in_cloud = queue.first().map(|n| n.parent_hash.clone());
        let kept_hash = {
            let all = db.get_work_summaries(0, 400_000).unwrap();
            all.iter().find(|n| n.id == kept).unwrap().hash.clone()
        };
        assert_eq!(
            head_in_cloud,
            Some(kept_hash),
            "the next upload links to the cloud's head"
        );
        assert!(db.verify_summary_chain(&keys.public_key).unwrap().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_sync_relinks_a_chain_held_up_by_a_note_from_before_pairing() {
        // #179: before the first upload, a chain whose first signed note links to a note
        // from before pairing is re-linked, so the cloud is offered a chain from its start.
        let path =
            std::env::temp_dir().join(format!("tenby10_sync_paired_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Database::new(path.clone()).unwrap();
        let keys = crate::config::generate_enrollment_keys("tok");
        let signer = crate::db::SlotSigner {
            public_key: &keys.public_key,
            private_key: &keys.private_key,
        };

        db.insert_work_summary(86_400, 172_800, "Day one.", 200_000, "ph", None)
            .unwrap();
        let unsigned_hash = db.get_work_summaries(0, 400_000).unwrap()[0].hash.clone();
        db.append_note_linked_to(172_800, "Day two.", 300_000, &signer, &unsigned_hash);

        // The reply does not matter here: what is checked is what the sync offered.
        let base = one_shot_server("409 Conflict", r#"{"error":"chain_broken"}"#);
        let now = 1_000_000;
        assert!(sync_work_summaries(&db, "agent", &base, now, Some(&signer)).is_err());

        let queue = db.get_unsynced_summaries(now, 0, 50).unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(
            queue[0].parent_hash, "",
            "the first signed note starts the chain"
        );
        assert!(db.verify_summary_chain(&keys.public_key).unwrap().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_other_conflicts_stop_the_sync_and_change_nothing() {
        let path =
            std::env::temp_dir().join(format!("tenby10_sync_chain_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Database::new(path.clone()).unwrap();
        let keys = crate::config::generate_enrollment_keys("tok");
        let signer = crate::db::SlotSigner {
            public_key: &keys.public_key,
            private_key: &keys.private_key,
        };
        let kept = db.append_note_unchecked(86_400, "Day one.", 200_000, &signer);
        db.mark_summary_synced(kept).unwrap();
        db.append_note_unchecked(86_400, "Day one, again.", 200_060, &signer);

        let base = one_shot_server("409 Conflict", r#"{"error":"chain_broken"}"#);
        let err = sync_work_summaries(&db, "agent", &base, 1_000_000, Some(&signer)).unwrap_err();
        assert!(err.contains("409"), "{err}");
        assert_eq!(
            db.get_unsynced_summaries(1_000_000, 0, 50).unwrap().len(),
            1
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_cloud_url_override_is_validated_before_it_is_used() {
        // Unset, or set to nothing, is production.
        assert_eq!(resolve_cloud_base_url(None), DEFAULT_CLOUD_URL);
        assert_eq!(resolve_cloud_base_url(Some("   ")), DEFAULT_CLOUD_URL);

        // A real override still works, whitespace and all.
        assert_eq!(
            resolve_cloud_base_url(Some("  https://staging.example.com  ")),
            "https://staging.example.com"
        );

        // Local cloud development runs the portal on loopback over plain http. That is
        // the workflow this must not break, and it is the one place http is safe.
        assert_eq!(
            resolve_cloud_base_url(Some("http://localhost:3000")),
            "http://localhost:3000"
        );
        assert_eq!(
            resolve_cloud_base_url(Some("http://127.0.0.1:3000")),
            "http://127.0.0.1:3000"
        );

        // Everything else falls back to production rather than sending signed slots,
        // work notes and the enrollment token somewhere else — in the clear, for the
        // http cases.
        assert_eq!(
            resolve_cloud_base_url(Some("http://cloud.example.com")),
            DEFAULT_CLOUD_URL
        );
        assert_eq!(
            resolve_cloud_base_url(Some("ftp://cloud.example.com")),
            DEFAULT_CLOUD_URL
        );
        assert_eq!(resolve_cloud_base_url(Some("not a url")), DEFAULT_CLOUD_URL);
        // A hostname that merely starts with "localhost" is a remote host.
        assert_eq!(
            resolve_cloud_base_url(Some("http://localhost.example.com")),
            DEFAULT_CLOUD_URL
        );
    }
}
