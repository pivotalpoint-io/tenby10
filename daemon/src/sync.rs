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
    std::env::var("TENBY10_CLOUD_URL").unwrap_or_else(|_| DEFAULT_CLOUD_URL.to_string())
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

/// The slots endpoint replies 428 when the referenced config isn't stored server-side yet (#80).
const PRECONDITION_REQUIRED: u16 = 428;

/// Upload the effective-config blob for `config_hash` from the local store so the cloud can
/// interpret slots that reference it (#80). The server authenticates it with
/// `sha256(blob) == config_hash` and stores it idempotently. Errors if we have no local blob for
/// the hash — which shouldn't happen, since every config we score under is persisted.
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
pub fn sync_signed_slots(db: &Database, agent_id: &str, base_url: &str) -> Result<usize, String> {
    if agent_id.is_empty() {
        return Ok(0);
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

/// Upload work notes that have cleared the correction window, oldest first (ADR 0019).
///
/// Stops at the first rejection, like slots: notes are a hash chain too, and a gap would
/// break every note behind it. Withdrawn notes are never uploaded — withdrawing before
/// the window closes means the note simply never travels.
pub fn sync_work_summaries(
    db: &Database,
    agent_id: &str,
    base_url: &str,
    now_ts: i64,
) -> Result<usize, String> {
    if agent_id.is_empty() {
        return Ok(0);
    }
    let notes = db
        .get_unsynced_summaries(now_ts, SUMMARY_CORRECTION_WINDOW_SECS, 50)
        .map_err(|e| format!("could not read unsynced work notes: {e}"))?;

    let client = reqwest::blocking::Client::new();
    let url = format!("{base_url}/api/v1/summaries");
    let mut uploaded = 0usize;

    for note in notes {
        let resp = client
            .post(&url)
            .json(&summary_payload(agent_id, &note))
            .send()
            .map_err(|e| format!("work note upload request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!(
                "work note for {} rejected: HTTP {} — stopping this sync",
                note.period_start,
                resp.status()
            ));
        }
        db.mark_summary_synced(note.id)
            .map_err(|e| format!("could not mark work note {} synced: {e}", note.id))?;
        uploaded += 1;
    }
    Ok(uploaded)
}
