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

/// Upload the effective-config blob to the cloud once per distinct config (#62), so the
/// verified page can show the rubric behind each score. The config hash is already bound into
/// the signed slots, so the server authenticates it with `sha256(blob) == config_hash`.
/// No-op when already uploaded, unenrolled, or the hash is empty.
pub fn upload_config_if_needed(
    db: &Database,
    agent_id: &str,
    base_url: &str,
    config_blob: &str,
    config_hash: &str,
) -> Result<bool, String> {
    if agent_id.is_empty() || config_hash.is_empty() {
        return Ok(false);
    }
    if db
        .is_config_uploaded(config_hash)
        .map_err(|e| format!("config-sync db read failed: {e}"))?
    {
        return Ok(false);
    }

    let resp = reqwest::blocking::Client::new()
        .post(format!("{base_url}/api/v1/config"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "config_hash": config_hash,
            "config_blob": config_blob,
        }))
        .send()
        .map_err(|e| format!("config upload request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("config upload rejected: HTTP {}", resp.status()));
    }
    db.mark_config_uploaded(config_hash)
        .map_err(|e| format!("could not mark config uploaded: {e}"))?;
    Ok(true)
}

/// Upload not-yet-synced signed slots, oldest first, marking each on success. Stops at the
/// first rejection (the chain must land in order). Returns the number uploaded this call.
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
        let payload = serde_json::json!({
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
            "ledger": { "hash": slot.hash, "parent_hash": slot.parent_hash },
            "signature": slot.signature,
        });

        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .map_err(|e| format!("slot upload request failed: {e}"))?;

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
