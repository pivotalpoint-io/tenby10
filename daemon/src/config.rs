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

/// Prompt for the slot auditor.
///
/// Carries [`crate::untrusted::PROMPT_RULE`] (#83): the activity log is built from
/// window titles, which the focused application writes, so the prompt has to say
/// what the fence markers around them mean. A user who replaces this prompt
/// wholesale drops that sentence — the fence, the storage cap and the note echo
/// check do not depend on it, but the model's instruction to ignore what is inside
/// the fence does.
pub fn default_llm_prompt() -> String {
    format!(
        "You are an AI productivity auditor. \
        Review the following 10-minute activity log (containing apps, window titles, keystrokes, and clicks). \
        Evaluate the user's focus on a scale of 0 to 100. \
        - Engineering, designing, writing, and active research are highly productive (80-100). \
        - Social media, entertainment, and casual browsing are distracted (0-30). \
        - A meeting with genuine engagement (e.g. Zoom, Teams) is productive; do NOT grant full focus to a completely inactive window merely because its title mentions a meeting app. \
        {} \
        Output ONLY a JSON object with two fields: 'score' (integer) and 'reasoning' (1-2 sentences).",
        crate::untrusted::PROMPT_RULE
    )
}

/// Prompt for the daily work note (ADR 0019). Unlike the scoring prompt, whatever this
/// produces is meant to be read by the client, so the constraints are the privacy
/// mechanism: describe the task, never the window title, never a third party. There is
/// no review step before it publishes, so the prompt is most of what keeps the note safe.
///
/// Most, not all: the no-quoting rule is also checked in code before a note is signed
/// (#83, [`crate::untrusted::note_quotes_a_title`]), because a rule a client's privacy
/// depends on should not rest on a model choosing to follow it. The prompt says so, so
/// the model knows a quoted title costs the note rather than passing unnoticed.
pub fn default_summary_prompt() -> String {
    format!(
        "You are writing a short work note that a client will read next to an invoice. \
        From the activity log below (apps and window titles), write one or two sentences \
        describing what was worked on, in plain professional language. \
        - Describe the task, not the tools: \"reworked the checkout flow\", not \"was in VSCode\". \
        - Never quote a window title, file path, or URL. A note that reproduces one is \
        discarded unread and the day is left without a note. \
        - Never name a person, company, or any third party. \
        - Do not mention hours, focus scores, or productivity. \
        - If the activity is too unclear to describe honestly, say that plainly instead of guessing. \
        {} \
        Output ONLY the sentences, with no preamble.",
        crate::untrusted::PROMPT_RULE
    )
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
    /// API base URL for the auditor provider. Empty = the provider's default
    /// (see `llm::provider_defaults`). Set this to reach an OpenAI-compatible
    /// gateway or a local Ollama (`http://localhost:11434/v1`).
    #[serde(default)]
    pub llm_base_url: String,
    /// Model the auditor calls. Empty = the provider's default.
    #[serde(default)]
    pub llm_model: String,
    #[serde(default = "default_llm_prompt")]
    pub llm_prompt: String,
    /// Prompt for the daily work note (ADR 0019). Its SHA-256 is bound into every
    /// summary record, so a note always carries the rules that wrote it.
    #[serde(default = "default_summary_prompt")]
    pub summary_prompt: String,
    /// Daily work notes are generated whenever the user's own AI is configured — that
    /// is what the AI is for. This opt-out exists for the exception case, not as a
    /// setup step (ADR 0019: setup once, then invisible).
    #[serde(default)]
    pub disable_work_summaries: bool,
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

/// Largest blob the sync endpoint will store, in bytes. A record is signed over the *hash*
/// of its blob, and ingestion refuses the record until the blob is stored — so a blob the
/// cloud rejects means a hash chain that can never advance again. Mirrors the server's own
/// ceiling; keep the two in step.
pub const MAX_CONFIG_BLOB_BYTES: usize = 64 * 1024;

/// Ceiling for a single user-authored prompt, in bytes. Half the blob ceiling, so
/// `llm_prompt` still fits once the app lists it shares the effective-config blob with are
/// counted. ~32,000 characters is around 5,000 words: far past any prompt worth writing,
/// close enough to catch a paste before it stalls the ledger.
pub const MAX_PROMPT_BYTES: usize = 32 * 1024;

/// Render a byte count the way the message needs to read: plain bytes while small, KB once
/// the numbers stop being meaningful (which, at these limits, is always the case).
fn describe_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} characters")
    } else {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    }
}

/// Reject a prompt the cloud could never store. The message is shown to the user in
/// Settings, so it names the field as the UI labels it and says what to do about it.
pub fn validate_prompt(label: &str, prompt: &str) -> Result<(), String> {
    if prompt.len() > MAX_PROMPT_BYTES {
        return Err(format!(
            "The {} is too long ({}). Please shorten it to under {} — a prompt larger than that cannot be synced, and the records that carry it would stop uploading.",
            label,
            describe_bytes(prompt.len()),
            describe_bytes(MAX_PROMPT_BYTES),
        ));
    }
    Ok(())
}

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

    /// Refuse a configuration whose blobs the cloud would reject. Both prompts are bound
    /// into signed records by hash — `llm_prompt` through the effective-config blob on every
    /// slot, `summary_prompt` as the blob behind every work note — and a record is only
    /// accepted once its blob is stored. So an over-long prompt does not degrade sync, it
    /// ends it: the record is signed, the blob is refused, and that chain never advances
    /// again. Cheaper to say no at the keyboard than to strand a ledger.
    ///
    /// Errors are written for the user; the Settings save path surfaces them as-is.
    pub fn validate(&self) -> Result<(), String> {
        validate_prompt("System Auditor Prompt", &self.llm_prompt)?;
        validate_prompt("Work Note Prompt", &self.summary_prompt)?;

        // The prompt ceiling leaves room for the app lists, but nothing bounds those on
        // their own — so check the assembled blob too, rather than assume the parts.
        let blob = self.effective_config_blob();
        if blob.len() > MAX_CONFIG_BLOB_BYTES {
            return Err(format!(
                "Your evaluation rules and prompt are too large together ({}). Please shorten them to under {} — past that they cannot be synced, and your slots would stop uploading.",
                describe_bytes(blob.len()),
                describe_bytes(MAX_CONFIG_BLOB_BYTES),
            ));
        }
        Ok(())
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
            llm_base_url: String::new(),
            llm_model: String::new(),
            llm_prompt: default_llm_prompt(),
            summary_prompt: default_summary_prompt(),
            disable_work_summaries: false,
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

/// Which stored secrets a save is *explicitly* asked to remove.
///
/// [`save_config`] is handed a whole [`AgentConfig`], so an empty secret field on it
/// means "this caller isn't carrying that secret" far more often than it means "the
/// user deleted it". Reading the first as the second is how a settings save could
/// destroy a live Ed25519 signing key and orphan every slot already signed under it
/// (#109). So an empty field never deletes anything; removal has to be said out loud,
/// here, by the one layer that actually knows the user asked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearSecrets {
    pub private_key: bool,
    pub llm_api_key: bool,
}

impl ClearSecrets {
    /// Remove nothing — what a save means unless the user emptied the field themselves.
    pub const NONE: Self = Self {
        private_key: false,
        llm_api_key: false,
    };
}

/// Write a secret to the OS keychain.
///
/// A non-empty value is always written. An empty one is left alone unless `clear` says
/// the caller means to delete it, in which case any existing entry is removed rather
/// than left behind as a stale secret.
fn store_secret(account: &str, value: &str, clear: bool) -> Result<(), String> {
    if value.is_empty() && !clear {
        // Not supplied. Say nothing to the keychain rather than destroy what is in it.
        return Ok(());
    }
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
/// `llm_api_key` secrets are overlaid from the OS keychain — whether or not the
/// file exists, since a missing `config.json` means "nothing configured yet",
/// not "nothing stored anywhere". Legacy config files that still hold plaintext
/// secrets are transparently migrated into the keychain and rewritten without them.
pub fn load_config(config_path: PathBuf) -> Result<AgentConfig, String> {
    // Falling through to the keychain overlay below rather than returning the
    // defaults here is deliberate: a caller that loaded while the file was absent
    // used to get a config carrying no secrets, and handing that back to
    // `save_config` is what deleted stored ones (#109).
    let mut config: AgentConfig = if config_path.exists() {
        // Startup reads this file, and a save may not happen for weeks, so a read is where
        // an upgrade gets to fix the mode an older build left behind (#95).
        crate::env::secure_app_home_for(&config_path);
        crate::env::secure_file(&config_path);
        let data = fs::read_to_string(&config_path)
            .map_err(|err| format!("Failed to read config file: {}", err))?;
        serde_json::from_str(&data)
            .map_err(|err| format!("Failed to parse config file: {}", err))?
    } else {
        AgentConfig::default()
    };

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

    // Settings refuses to save an over-long prompt, but `config.json` can be edited by hand.
    // Signing a record against a blob the cloud will never accept stalls that hash chain for
    // good, so fall back to the built-in prompt rather than sign something unuploadable. The
    // fallback is what the daemon then actually scores with, so the blob it commits to stays
    // an honest record of the rules that were used.
    if config.llm_prompt.len() > MAX_PROMPT_BYTES {
        eprintln!(
            "[WARN] llm_prompt in config.json is {} — over the {} limit, so it cannot be synced. \
             Using the built-in auditor prompt instead. Shorten it in Settings to use your own.",
            describe_bytes(config.llm_prompt.len()),
            describe_bytes(MAX_PROMPT_BYTES),
        );
        config.llm_prompt = default_llm_prompt();
    }
    if config.summary_prompt.len() > MAX_PROMPT_BYTES {
        eprintln!(
            "[WARN] summary_prompt in config.json is {} — over the {} limit, so it cannot be synced. \
             Using the built-in work note prompt instead. Shorten it in Settings to use your own.",
            describe_bytes(config.summary_prompt.len()),
            describe_bytes(MAX_PROMPT_BYTES),
        );
        config.summary_prompt = default_summary_prompt();
    }

    // Nothing bounds the app lists on their own, so a hand-edited config can still exceed the
    // blob ceiling without either prompt being at fault. There is no honest fallback here —
    // silently swapping in different scoring rules would misreport what the slot was judged
    // by — so say plainly what is wrong and leave the rules as written.
    let blob_len = config.effective_config_blob().len();
    if blob_len > MAX_CONFIG_BLOB_BYTES {
        eprintln!(
            "[WARN] The evaluation rules in config.json total {} — over the {} limit, so slots \
             scored under them cannot be uploaded. Shorten the app lists in Settings.",
            describe_bytes(blob_len),
            describe_bytes(MAX_CONFIG_BLOB_BYTES),
        );
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

/// Save configuration to path, removing no stored secret.
///
/// Secrets (`private_key`, `llm_api_key`) are written to the OS keychain; a
/// sanitized copy of the config — with those fields blanked — is written to
/// `config.json` so no secret ever lands in plaintext on disk.
///
/// A secret left empty on `config` is one this caller is not carrying, and is left
/// in the keychain untouched. Deleting one takes [`save_config_clearing`].
///
/// A configuration whose blobs the cloud would refuse is rejected before anything is
/// written, so a save either lands whole or leaves the previous one untouched.
pub fn save_config(config_path: PathBuf, config: &AgentConfig) -> Result<(), String> {
    save_config_clearing(config_path, config, ClearSecrets::NONE)
}

/// [`save_config`], plus the secrets this save is deliberately removing.
///
/// Only a layer that knows the user emptied the field has any business passing
/// anything but [`ClearSecrets::NONE`] here — see [`ClearSecrets`] for why.
pub fn save_config_clearing(
    config_path: PathBuf,
    config: &AgentConfig,
    clear: ClearSecrets,
) -> Result<(), String> {
    config.validate()?;

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create config directory: {}", err))?;
    }
    crate::env::secure_app_home_for(&config_path);

    // Persist secrets to the OS keychain first.
    store_secret(KR_PRIVATE_KEY, &config.private_key, clear.private_key)?;
    store_secret(KR_LLM_API_KEY, &config.llm_api_key, clear.llm_api_key)?;

    // Serialize a sanitized copy so secrets never touch config.json.
    let mut on_disk = config.clone();
    on_disk.private_key = String::new();
    on_disk.llm_api_key = String::new();

    let data = serde_json::to_string_pretty(&on_disk)
        .map_err(|err| format!("Failed to serialize config: {}", err))?;
    fs::write(&config_path, data).map_err(|err| format!("Failed to write config file: {}", err))?;
    // The secrets are in the keychain, but the file still names the agent, its public
    // key and the endpoint it talks to, and it is the file a hand edit reaches (#95).
    crate::env::secure_file(&config_path);
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
        llm_base_url: String::new(),
        llm_model: String::new(),
        llm_prompt: default_llm_prompt(),
        summary_prompt: default_summary_prompt(),
        disable_work_summaries: false,
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
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard, Once};

    static INIT_KEYCHAIN: Once = Once::new();
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    /// The credential builder is process-wide, so its store is too. Serialise the
    /// tests that touch it rather than let cargo's thread pool interleave one test's
    /// save with another's assertion.
    static KEYCHAIN: Mutex<()> = Mutex::new(());
    static STORE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);

    /// A stand-in keychain that actually remembers what was written to it.
    ///
    /// `keyring::mock` cannot be used here: it hands out a fresh, empty credential
    /// per `Entry::new`, so a value written through one entry is invisible to the
    /// next. Every assertion below about a secret *surviving* a save would then pass
    /// whether or not it did. Telling "still there" from "deleted" needs real
    /// persistence, keyed by service and account the way the OS keychain is.
    #[derive(Debug)]
    struct StoreCredential(String);

    impl keyring::credential::CredentialApi for StoreCredential {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            let mut store = STORE.lock().unwrap_or_else(|e| e.into_inner());
            store
                .get_or_insert_with(HashMap::new)
                .insert(self.0.clone(), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            let store = STORE.lock().unwrap_or_else(|e| e.into_inner());
            match store.as_ref().and_then(|s| s.get(&self.0)) {
                Some(secret) => Ok(secret.clone()),
                None => Err(keyring::Error::NoEntry),
            }
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            let mut store = STORE.lock().unwrap_or_else(|e| e.into_inner());
            match store.as_mut().and_then(|s| s.remove(&self.0)) {
                Some(_) => Ok(()),
                None => Err(keyring::Error::NoEntry),
            }
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[derive(Debug)]
    struct StoreBuilder;

    impl keyring::credential::CredentialBuilderApi for StoreBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<keyring::Credential>> {
            Ok(Box::new(StoreCredential(format!("{service}\u{0}{user}"))))
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn persistence(&self) -> keyring::credential::CredentialPersistence {
            keyring::credential::CredentialPersistence::ProcessOnly
        }
    }

    /// Route keychain access to the in-process store so tests never touch — or
    /// prompt for — the real OS keychain. Empties it first: the store outlives each
    /// test, and a leftover secret would let one test satisfy another's assertion.
    fn keychain() -> MutexGuard<'static, ()> {
        INIT_KEYCHAIN.call_once(|| {
            keyring::set_default_credential_builder(Box::new(StoreBuilder));
        });
        let guard = KEYCHAIN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        STORE.lock().unwrap_or_else(|e| e.into_inner()).take();
        guard
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
    }

    /// A config written by a pre-ADR-0018 build still carries `send_screenshots`.
    /// The field is gone from the struct, so loading must ignore it rather than
    /// fail — otherwise upgrading wipes the user's whole configuration.
    #[test]
    fn test_legacy_send_screenshots_key_is_ignored() {
        let json = r#"{
            "agent_id": "agent_123",
            "enrollment_token": "token_123",
            "public_key": "pub",
            "private_key": "priv",
            "send_screenshots": true,
            "engine_mode": "llm"
        }"#;

        let config: AgentConfig = serde_json::from_str(json)
            .expect("a legacy config with send_screenshots must still deserialize");
        assert_eq!(config.agent_id, "agent_123");
        assert_eq!(config.engine_mode, "llm");
    }

    #[test]
    fn test_save_config_writes_no_secrets_to_disk() {
        let _keychain = keychain();
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

    /// The interlock (#109). `save_config` is handed a whole `AgentConfig`, and plenty
    /// of callers assemble one without ever holding the signing key — a settings save
    /// merging a form into a freshly loaded config, most of all. None of them may cost
    /// the user that key: deleting it orphans every slot already signed under it, and
    /// no re-pair brings it back.
    #[test]
    fn a_save_cannot_delete_a_signing_key_it_never_received() {
        let _keychain = keychain();
        let path = temp_config_path();

        let enrolled = generate_enrollment_keys("tok");
        save_config(path.clone(), &enrolled).expect("the baseline save should succeed");
        assert_eq!(
            load_secret(KR_PRIVATE_KEY).expect("the keychain should read"),
            enrolled.private_key,
            "the baseline save should have stored the signing key"
        );

        // A config carrying no secrets at all — exactly what a caller used to get back
        // from `load_config` when `config.json` had gone missing.
        let no_secrets = AgentConfig {
            agent_id: enrolled.agent_id.clone(),
            public_key: enrolled.public_key.clone(),
            ..Default::default()
        };
        save_config(path.clone(), &no_secrets).expect("the save should succeed");

        assert_eq!(
            load_secret(KR_PRIVATE_KEY).expect("the keychain should read"),
            enrolled.private_key,
            "a save that was never given the signing key must not delete it"
        );

        let _ = fs::remove_file(&path);
    }

    /// The other end of the same hazard: a load with no `config.json` skipped the
    /// keychain overlay entirely, so the caller never saw the secrets it was about to
    /// write back out.
    #[test]
    fn a_missing_config_file_still_overlays_the_stored_secrets() {
        let _keychain = keychain();
        let path = temp_config_path();

        let mut enrolled = generate_enrollment_keys("tok");
        enrolled.llm_api_key = "sk-the-users-own-key".to_string();
        save_config(path.clone(), &enrolled).expect("the baseline save should succeed");
        fs::remove_file(&path).expect("the config file should exist to be removed");

        let loaded = load_config(path.clone()).expect("load_config should succeed");
        assert_eq!(
            loaded.private_key, enrolled.private_key,
            "a missing config.json must not hide the stored signing key"
        );
        assert_eq!(loaded.llm_api_key, enrolled.llm_api_key);
        // Everything that lived only in the file is gone, as it should be.
        assert!(loaded.agent_id.is_empty());

        let _ = fs::remove_file(&path);
    }

    /// Removing a secret is still possible — it just has to be asked for by name, by
    /// the one layer that knows the user emptied the field.
    #[test]
    fn only_an_explicit_clear_removes_a_secret() {
        let _keychain = keychain();
        let path = temp_config_path();

        let mut enrolled = generate_enrollment_keys("tok");
        enrolled.llm_api_key = "sk-the-users-own-key".to_string();
        save_config(path.clone(), &enrolled).expect("the baseline save should succeed");

        // The user cleared the API key field: that secret goes, the signing key stays.
        let mut cleared = enrolled.clone();
        cleared.llm_api_key = String::new();
        save_config_clearing(
            path.clone(),
            &cleared,
            ClearSecrets {
                llm_api_key: true,
                ..ClearSecrets::NONE
            },
        )
        .expect("the save should succeed");
        assert!(
            load_secret(KR_LLM_API_KEY)
                .expect("the keychain should read")
                .is_empty(),
            "an explicitly cleared API key must be removed"
        );
        assert_eq!(
            load_secret(KR_PRIVATE_KEY).expect("the keychain should read"),
            enrolled.private_key,
            "clearing the API key must not touch the signing key"
        );

        // And the signing key itself, when that is what was asked for and nothing else.
        let mut wiped = cleared.clone();
        wiped.private_key = String::new();
        save_config_clearing(
            path.clone(),
            &wiped,
            ClearSecrets {
                private_key: true,
                ..ClearSecrets::NONE
            },
        )
        .expect("the save should succeed");
        assert!(
            load_secret(KR_PRIVATE_KEY)
                .expect("the keychain should read")
                .is_empty(),
            "an explicit clear is the one thing that removes the signing key"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_legacy_plaintext_config_is_migrated() {
        let _keychain = keychain();
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
        let _keychain = keychain();
        let path = temp_config_path();

        // An already-enrolled device. Keys are written inline so the reused values come from
        // the file rather than the keychain — the legacy-plaintext path takes precedence over
        // the overlay — which pins what this test is about to the bytes right here.
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

    /// A prompt exactly at the limit is still the user's to write; only past it is refused.
    #[test]
    fn test_prompt_at_the_limit_is_accepted() {
        let at_limit = "x".repeat(MAX_PROMPT_BYTES);
        assert!(validate_prompt("System Auditor Prompt", &at_limit).is_ok());

        let over = "x".repeat(MAX_PROMPT_BYTES + 1);
        let err = validate_prompt("System Auditor Prompt", &over)
            .expect_err("a prompt over the limit must be refused");
        // The message is shown to the user, so it must name the field and the ceiling.
        assert!(err.contains("System Auditor Prompt"), "message was: {err}");
        assert!(err.contains("32 KB"), "message was: {err}");
    }

    /// The whole point of the prompt ceiling: a config that passes validation always
    /// produces a blob the cloud will store, so no slot is ever signed against a hash
    /// whose blob can't upload.
    #[test]
    fn test_max_prompt_leaves_room_for_the_app_lists() {
        let config = AgentConfig {
            llm_prompt: "x".repeat(MAX_PROMPT_BYTES),
            distracting_apps: "y".repeat(4096),
            ..Default::default()
        };
        config
            .validate()
            .expect("a max-length prompt must be valid");
        assert!(
            config.effective_config_blob().len() <= MAX_CONFIG_BLOB_BYTES,
            "the blob for a max-length prompt must still be uploadable"
        );
    }

    /// An over-long prompt must be refused *before* anything is written, so a rejected
    /// save leaves the previous configuration intact rather than half-applied.
    #[test]
    fn test_save_config_rejects_oversized_prompts() {
        let _keychain = keychain();

        for (field, mutate) in [
            (
                "System Auditor Prompt",
                (|c: &mut AgentConfig| c.llm_prompt = "x".repeat(MAX_PROMPT_BYTES + 1))
                    as fn(&mut AgentConfig),
            ),
            ("Work Note Prompt", |c: &mut AgentConfig| {
                c.summary_prompt = "x".repeat(MAX_PROMPT_BYTES + 1)
            }),
        ] {
            let path = temp_config_path();
            let mut config = generate_enrollment_keys("tok");
            save_config(path.clone(), &config).expect("the baseline save should succeed");
            let before = fs::read_to_string(&path).expect("config file should exist");

            mutate(&mut config);
            let err = save_config(path.clone(), &config)
                .expect_err("an over-long prompt must not be saved");
            assert!(err.contains(field), "message was: {err}");

            let after = fs::read_to_string(&path).expect("config file should still exist");
            assert_eq!(before, after, "a rejected save must not touch config.json");

            let _ = fs::remove_file(&path);
        }
    }

    /// Settings refuses an over-long prompt, but `config.json` can be edited by hand. Loading
    /// one must fall back to the built-in prompt: signing a record against a blob the cloud
    /// will never accept stalls that hash chain permanently.
    #[test]
    fn test_load_config_falls_back_on_oversized_prompts() {
        let _keychain = keychain();
        let path = temp_config_path();

        let huge = "x".repeat(MAX_PROMPT_BYTES + 1);
        let handwritten = serde_json::json!({
            "agent_id": "agent_handwritten",
            "enrollment_token": "tok",
            "public_key": "pub",
            "private_key": "",
            "llm_prompt": huge,
            "summary_prompt": huge,
        });
        fs::write(&path, handwritten.to_string()).unwrap();

        let config = load_config(path.clone()).expect("load_config should succeed");
        assert_eq!(config.llm_prompt, default_llm_prompt());
        assert_eq!(config.summary_prompt, default_summary_prompt());
        // The rest of the configuration is untouched — only the unusable prompts are replaced.
        assert_eq!(config.agent_id, "agent_handwritten");
        assert!(
            config.effective_config_blob().len() <= MAX_CONFIG_BLOB_BYTES,
            "the blob a slot commits to must be uploadable after the fallback"
        );

        let _ = fs::remove_file(&path);
    }

    /// Both defaults tell the model what the fence markers mean, and both still fit
    /// under the ceiling that keeps a record's blob uploadable (#83). The second half
    /// matters as much as the first: a prompt the cloud would refuse stalls the chain
    /// that carries it, so growing the defaults has a hard limit.
    #[test]
    fn test_default_prompts_carry_the_untrusted_data_rule() {
        for prompt in [default_llm_prompt(), default_summary_prompt()] {
            assert!(
                prompt.contains(crate::untrusted::FENCE_OPEN)
                    && prompt.contains(crate::untrusted::FENCE_CLOSE),
                "a default prompt must name both markers: {prompt}"
            );
            assert!(validate_prompt("Prompt", &prompt).is_ok());
        }
        assert!(
            AgentConfig::default().validate().is_ok(),
            "the shipped defaults must produce an uploadable blob"
        );
    }

    #[test]
    fn test_config_for_enrollment_generates_when_no_key_stored() {
        let _keychain = keychain();
        let path = temp_config_path();

        // No config on disk yet (first-ever pair) → a fresh keypair is minted.
        let config = config_for_enrollment(path.clone(), "tok");
        assert!(!config.public_key.is_empty());
        assert!(!config.private_key.is_empty());
        assert_eq!(config.enrollment_token, "tok");

        let _ = fs::remove_file(&path);
    }
}
