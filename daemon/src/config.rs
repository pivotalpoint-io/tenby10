use ed25519_dalek::SigningKey;
use keyring::Entry;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub fn default_productive_apps() -> String {
    "vscode, cursor, xcode, figma, notion, terminal, iterm2, chrome, safari, firefox, arc, webstorm, intellij, pycharm, goland, eclipse, android studio, final cut, premiere, photoshop, illustrator".to_string()
}

pub fn default_engine_mode() -> String {
    "static".to_string()
}

pub fn default_meeting_apps() -> String {
    "zoom, meet, teams, webex, slack | huddle".to_string()
}

pub fn default_llm_prompt() -> String {
    "You are an AI productivity auditor. \
    Review the following 10-minute activity log (containing apps, window titles, keystrokes, and clicks). \
    Evaluate the user's focus on a scale of 0 to 100. \
    - Engineering, designing, writing, and active research are highly productive (80-100). \
    - Social media, entertainment, and casual browsing are distracted (0-30). \
    - A meeting with genuine engagement (e.g. Zoom, Teams) is productive; do NOT grant full focus to a completely inactive window merely because its title mentions a meeting app. \
    Output ONLY a JSON object with two fields: 'score' (integer) and 'reasoning' (1-2 sentences).".to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub agent_id: String,
    pub enrollment_token: String,
    pub public_key: String,
    pub private_key: String,
    #[serde(default)]
    pub distracting_apps: String,
    #[serde(default = "default_productive_apps")]
    pub productive_apps: String,
    #[serde(default = "default_meeting_apps")]
    pub meeting_apps: String,
    #[serde(default = "default_engine_mode")]
    pub engine_mode: String,
    #[serde(default)]
    pub llm_provider: String,
    #[serde(default)]
    pub llm_api_key: String,
    #[serde(default = "default_llm_prompt")]
    pub llm_prompt: String,
    #[serde(default)]
    pub send_screenshots: bool,
    #[serde(default)]
    pub dashboard_port: Option<u16>,
    /// Enforce synthetic-input detection (#87): mark a minute tampered when its
    /// input was entirely software-injected. Default off — detection is observe-
    /// only until on-device red-team calibration (#96), since a bad field read or
    /// a legit auto-typer could otherwise flag a real user.
    #[serde(default)]
    pub enforce_synthetic_detection: bool,
}

/// The scoring configuration that actually determines a slot's score — the
/// "auditing rules" (app lists + engine + synthetic-detection) and the AI
/// auditor prompt. Serialized in a fixed field order so the JSON blob is
/// byte-deterministic; its SHA-256 is bound into every signed slot
/// (config-in-ledger, #62) and the exact blob is uploaded to the cloud when it
/// changes. Secrets and identifiers are deliberately excluded.
#[derive(serde::Serialize)]
pub struct EffectiveConfig<'a> {
    pub config_scheme: u32,
    /// Which aggregation-semantics version scores/aggregates these slots (ADR 0017). Lets any
    /// out-of-process consumer (the cloud verifier) interpret the derived numbers — billable,
    /// logged, focus % — under the exact rules that produced them, instead of guessing.
    pub aggregation_version: u32,
    pub engine_mode: &'a str,
    pub distracting_apps: &'a str,
    pub productive_apps: &'a str,
    pub meeting_apps: &'a str,
    pub llm_prompt: &'a str,
    pub enforce_synthetic_detection: bool,
}

/// Versions the effective-config serialization independently of the ledger scheme.
/// Scheme 2 (ADR 0017) adds `aggregation_version`; scheme-1 blobs are read as aggregation v1.
pub const EFFECTIVE_CONFIG_SCHEME: u32 = 2;

/// Aggregation-semantics version these slots are scored/aggregated under (ADR 0017). Bump only
/// alongside a new `aggregate_v*` in `db.rs` and a new golden vector — never edit v1 in place.
pub const AGGREGATION_VERSION: u32 = 1;

impl AgentConfig {
    /// Canonical JSON blob of the effective scoring config (fixed field order,
    /// no whitespace). This is the exact string uploaded to the cloud, so the
    /// cloud verifies it with a plain `sha256(bytes) == config_hash` — no
    /// re-canonicalization on the server.
    pub fn effective_config_blob(&self) -> String {
        serde_json::to_string(&EffectiveConfig {
            config_scheme: EFFECTIVE_CONFIG_SCHEME,
            aggregation_version: AGGREGATION_VERSION,
            engine_mode: &self.engine_mode,
            distracting_apps: &self.distracting_apps,
            productive_apps: &self.productive_apps,
            meeting_apps: &self.meeting_apps,
            llm_prompt: &self.llm_prompt,
            enforce_synthetic_detection: self.enforce_synthetic_detection,
        })
        .unwrap_or_default()
    }

    /// SHA-256 (lowercase hex) of [`Self::effective_config_blob`]. Bound into the
    /// signed slot payload so every score is cryptographically tied to the rubric
    /// that produced it.
    pub fn effective_config_hash(&self) -> String {
        crate::db::sha256_hex_pub(&self.effective_config_blob())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            enrollment_token: String::new(),
            public_key: String::new(),
            private_key: String::new(),
            distracting_apps: String::new(),
            productive_apps: default_productive_apps(),
            meeting_apps: default_meeting_apps(),
            engine_mode: default_engine_mode(),
            llm_provider: String::new(),
            llm_api_key: String::new(),
            llm_prompt: default_llm_prompt(),
            send_screenshots: false,
            dashboard_port: None,
            enforce_synthetic_detection: false,
        }
    }
}

/// Simple hex encoder.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// --- OS keychain-backed secret storage ---
//
// The Ed25519 signing key and the BYOK LLM API key are secrets. They are kept
// in the OS keychain (macOS Keychain / Windows Credential Manager via the
// `keyring` crate) and are *never* written to `~/.tenby10/config.json`. See
// AUDIT.md gap G2 and specs/ENG_SPEC.md §5.2.

/// Keychain account name for the Ed25519 signing key.
const KR_PRIVATE_KEY: &str = "private_key";
/// Keychain account name for the BYOK LLM API key.
const KR_LLM_API_KEY: &str = "llm_api_key";

/// Keychain service name, namespaced by dev/prod so the two environments never
/// share stored secrets (mirrors the `~/.tenby10` vs `~/.tenby10_dev` split).
fn keyring_service() -> String {
    if crate::env::is_dev() {
        "tenby10-dev".to_string()
    } else {
        "tenby10".to_string()
    }
}

/// Write a secret to the OS keychain. An empty value *deletes* any existing
/// entry, so clearing a key in the UI actually removes it from the keychain
/// rather than leaving a stale secret behind.
fn store_secret(account: &str, value: &str) -> Result<(), String> {
    let entry = Entry::new(&keyring_service(), account)
        .map_err(|err| format!("Failed to open keychain entry '{}': {}", account, err))?;
    if value.is_empty() {
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(format!(
                "Failed to clear keychain entry '{}': {}",
                account, err
            )),
        }
    } else {
        entry
            .set_password(value)
            .map_err(|err| format!("Failed to write keychain entry '{}': {}", account, err))
    }
}

/// Read a secret from the OS keychain. Returns an empty string when no entry
/// exists (so a missing secret behaves the same as an unset field).
fn load_secret(account: &str) -> Result<String, String> {
    let entry = Entry::new(&keyring_service(), account)
        .map_err(|err| format!("Failed to open keychain entry '{}': {}", account, err))?;
    match entry.get_password() {
        Ok(secret) => Ok(secret),
        Err(keyring::Error::NoEntry) => Ok(String::new()),
        Err(err) => Err(format!(
            "Failed to read keychain entry '{}': {}",
            account, err
        )),
    }
}

/// Load configuration from path. Returns default config if not found.
///
/// Non-secret fields come from `config.json`; the `private_key` and
/// `llm_api_key` secrets are overlaid from the OS keychain. Legacy config files
/// that still hold plaintext secrets are transparently migrated into the
/// keychain and rewritten without them.
pub fn load_config(config_path: PathBuf) -> Result<AgentConfig, String> {
    if !config_path.exists() {
        return Ok(AgentConfig::default());
    }
    let data = fs::read_to_string(&config_path)
        .map_err(|err| format!("Failed to read config file: {}", err))?;
    let mut config: AgentConfig = serde_json::from_str(&data)
        .map_err(|err| format!("Failed to parse config file: {}", err))?;

    // Detect any legacy plaintext secrets still present in the file so we can
    // migrate them into the keychain below.
    let legacy_private_key = !config.private_key.is_empty();
    let legacy_llm_api_key = !config.llm_api_key.is_empty();

    // Overlay secrets from the OS keychain. A legacy plaintext value already in
    // the file takes precedence (it is what we migrate).
    if config.private_key.is_empty() {
        config.private_key = load_secret(KR_PRIVATE_KEY)?;
    }
    if config.llm_api_key.is_empty() {
        config.llm_api_key = load_secret(KR_LLM_API_KEY)?;
    }

    // Apply defaults if fields are empty
    if config.productive_apps.is_empty() {
        config.productive_apps = default_productive_apps();
    }
    if config.meeting_apps.is_empty() {
        config.meeting_apps = default_meeting_apps();
    }
    if config.engine_mode.is_empty() {
        config.engine_mode = default_engine_mode();
    }
    if config.llm_prompt.is_empty() {
        config.llm_prompt = default_llm_prompt();
    }

    // One-time migration: move plaintext secrets from config.json into the OS
    // keychain and rewrite the file without them. Best-effort — a keychain
    // failure here must not break loading, since the in-memory secrets are
    // still usable for this run.
    if (legacy_private_key || legacy_llm_api_key)
        && let Err(err) = save_config(config_path, &config)
    {
        eprintln!(
            "[WARN] Failed to migrate plaintext secrets to keychain: {}",
            err
        );
    }

    Ok(config)
}

/// Save configuration to path.
///
/// Secrets (`private_key`, `llm_api_key`) are written to the OS keychain; a
/// sanitized copy of the config — with those fields blanked — is written to
/// `config.json` so no secret ever lands in plaintext on disk.
pub fn save_config(config_path: PathBuf, config: &AgentConfig) -> Result<(), String> {
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create config directory: {}", err))?;
    }

    // Persist secrets to the OS keychain first.
    store_secret(KR_PRIVATE_KEY, &config.private_key)?;
    store_secret(KR_LLM_API_KEY, &config.llm_api_key)?;

    // Serialize a sanitized copy so secrets never touch config.json.
    let mut on_disk = config.clone();
    on_disk.private_key = String::new();
    on_disk.llm_api_key = String::new();

    let data = serde_json::to_string_pretty(&on_disk)
        .map_err(|err| format!("Failed to serialize config: {}", err))?;
    fs::write(config_path, data).map_err(|err| format!("Failed to write config file: {}", err))?;
    Ok(())
}

/// Generate new cryptographic keys and return updated AgentConfig.
pub fn generate_enrollment_keys(enrollment_token: &str) -> AgentConfig {
    // ed25519-dalek 3.0 and rand 0.10 pull different `rand_core` versions, so no
    // rand RNG satisfies `SigningKey::generate`'s `CryptoRng` bound directly.
    // Instead fill the 32-byte secret from the thread CSPRNG (auto-seeded from
    // the OS, cryptographically secure, and infallible via the `Rng` trait's
    // `fill_bytes` — unlike the now-fallible `OsRng`) and build the key from
    // those bytes.
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let private_key = to_hex(&signing_key.to_bytes());
    let public_key = to_hex(verifying_key.as_bytes());

    // Generate simple UUID-like string for agent_id
    let agent_id = format!("agent_uuid_{}", to_hex(&rand::random::<[u8; 8]>()));

    AgentConfig {
        agent_id,
        enrollment_token: enrollment_token.to_string(),
        public_key,
        private_key,
        distracting_apps: String::new(),
        productive_apps: default_productive_apps(),
        meeting_apps: default_meeting_apps(),
        engine_mode: default_engine_mode(),
        llm_provider: String::new(),
        llm_api_key: String::new(),
        llm_prompt: default_llm_prompt(),
        send_screenshots: false,
        dashboard_port: None,
        enforce_synthetic_detection: false,
    }
}

/// Build the config to enroll with, reusing the device's existing keypair when one is already
/// stored (a re-pair). The cloud validates slot signatures against the agent's registered key,
/// so rotating the key on every re-pair would orphan the signed ledger; keeping one stable
/// signing identity across re-pairs avoids that. A fresh keypair is generated only on first
/// enrollment (no key stored yet). The caller fills `agent_id` from the enrollment response.
pub fn config_for_enrollment(config_path: PathBuf, enrollment_token: &str) -> AgentConfig {
    match load_config(config_path) {
        Ok(existing) if !existing.private_key.is_empty() && !existing.public_key.is_empty() => {
            let mut config = existing;
            config.enrollment_token = enrollment_token.to_string();
            config
        }
        _ => generate_enrollment_keys(enrollment_token),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;
    use std::sync::atomic::{AtomicU32, Ordering};

    static INIT_MOCK: Once = Once::new();
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Route keychain access to the in-memory mock store so tests never touch
    /// (or prompt for) the real OS keychain.
    fn use_mock_keychain() {
        INIT_MOCK.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    /// A unique temp path per call so parallel tests don't collide on disk.
    fn temp_config_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tenby10_cfg_test_{}_{}.json",
            std::process::id(),
            n
        ));
        path
    }

    #[test]
    fn test_generate_enrollment_keys() {
        let config = generate_enrollment_keys("test_token");
        assert_eq!(config.enrollment_token, "test_token");
        assert!(!config.public_key.is_empty());
        assert!(!config.private_key.is_empty());
        assert!(config.agent_id.starts_with("agent_uuid_"));

        // Check new LLM fields defaults
        assert_eq!(config.engine_mode, "static");
        assert!(config.distracting_apps.is_empty());
        assert!(config.productive_apps.contains("vscode"));
        assert!(config.llm_provider.is_empty());
        assert!(config.llm_api_key.is_empty());
        assert!(config.llm_prompt.contains("productivity auditor"));
        assert!(!config.send_screenshots);
    }

    #[test]
    fn test_config_deserialization_defaults() {
        // A config without the new fields
        let json = r#"{
            "agent_id": "agent_123",
            "enrollment_token": "token_123",
            "public_key": "pub",
            "private_key": "priv"
        }"#;

        let config: AgentConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.engine_mode, "static"); // Should now use custom default
        assert_eq!(config.llm_provider, "");
        assert_eq!(config.llm_api_key, "");
        assert!(config.llm_prompt.contains("productivity auditor")); // Uses custom default
        assert_eq!(config.distracting_apps, "");
        assert!(config.productive_apps.contains("vscode")); // Uses custom default
        assert!(config.meeting_apps.contains("zoom")); // Uses custom default
        assert!(!config.send_screenshots);
    }

    #[test]
    fn test_save_config_writes_no_secrets_to_disk() {
        use_mock_keychain();
        let path = temp_config_path();

        let mut config = generate_enrollment_keys("tok");
        config.llm_provider = "openai".to_string();
        config.llm_api_key = "sk-super-secret-key".to_string();
        let secret_priv = config.private_key.clone();
        assert!(!secret_priv.is_empty());

        save_config(path.clone(), &config).expect("save_config should succeed");

        let on_disk = fs::read_to_string(&path).expect("config file should exist");
        // Secrets must never appear in plaintext on disk (AUDIT.md G2).
        assert!(
            !on_disk.contains(&secret_priv),
            "private_key leaked into config.json"
        );
        assert!(
            !on_disk.contains("sk-super-secret-key"),
            "llm_api_key leaked into config.json"
        );
        // Non-secret fields are still persisted to disk.
        assert!(on_disk.contains(&config.agent_id));
        assert!(on_disk.contains("openai"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_legacy_plaintext_config_is_migrated() {
        use_mock_keychain();
        let path = temp_config_path();

        // A pre-keychain config file that still holds plaintext secrets.
        let legacy = r#"{
            "agent_id": "agent_legacy",
            "enrollment_token": "tok_legacy",
            "public_key": "pubkey",
            "private_key": "deadbeefprivate",
            "llm_provider": "anthropic",
            "llm_api_key": "sk-legacy-plaintext"
        }"#;
        fs::write(&path, legacy).unwrap();

        let config = load_config(path.clone()).expect("load_config should succeed");
        // Secrets remain available in-memory after migration.
        assert_eq!(config.private_key, "deadbeefprivate");
        assert_eq!(config.llm_api_key, "sk-legacy-plaintext");

        // The file must have been rewritten without the plaintext secrets.
        let on_disk = fs::read_to_string(&path).expect("config file should exist");
        assert!(
            !on_disk.contains("deadbeefprivate"),
            "private_key still plaintext after migration"
        );
        assert!(
            !on_disk.contains("sk-legacy-plaintext"),
            "llm_api_key still plaintext after migration"
        );
        // Non-secret fields survive the migration.
        assert!(on_disk.contains("agent_legacy"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_config_for_enrollment_reuses_existing_keypair() {
        use_mock_keychain();
        let path = temp_config_path();

        // An already-enrolled device. Keys are written inline so the reused values come from the
        // file (the legacy-plaintext path takes precedence over the shared mock keychain slot),
        // keeping the test deterministic under parallel runs.
        let existing = r#"{
            "agent_id": "agent_old",
            "enrollment_token": "first_token",
            "public_key": "aabbccdd_pub",
            "private_key": "aabbccdd_priv"
        }"#;
        fs::write(&path, existing).unwrap();

        // Re-pair with a new token: the stored keypair must be reused, only the token refreshed.
        let repair = config_for_enrollment(path.clone(), "second_token");
        assert_eq!(
            repair.public_key, "aabbccdd_pub",
            "public key must be reused"
        );
        assert_eq!(
            repair.private_key, "aabbccdd_priv",
            "private key must be reused"
        );
        assert_eq!(
            repair.enrollment_token, "second_token",
            "token should be updated"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_config_for_enrollment_generates_when_no_key_stored() {
        use_mock_keychain();
        let path = temp_config_path();

        // No config on disk yet (first-ever pair) → a fresh keypair is minted.
        let config = config_for_enrollment(path.clone(), "tok");
        assert!(!config.public_key.is_empty());
        assert!(!config.private_key.is_empty());
        assert_eq!(config.enrollment_token, "tok");

        let _ = fs::remove_file(&path);
    }
}
