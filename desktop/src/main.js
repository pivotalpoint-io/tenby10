const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// UI Elements
const dashboardView = document.getElementById("dashboard-view");
const settingsView = document.getElementById("settings-view");
const gotoSettingsBtn = document.getElementById("goto-settings-btn");
const backToDashboardBtn = document.getElementById("back-to-dashboard-btn");

const enrollForm = document.getElementById("enroll-form");
const enrollInput = document.getElementById("enroll-input");
const enrollBtn = document.getElementById("enroll-btn");
const enrollmentDetails = document.getElementById("enrollment-details");
const settingAgentId = document.getElementById("setting-agent-id");
const settingPublicKey = document.getElementById("setting-public-key");

const toggleTrackingBtn = document.getElementById("toggle-tracking-btn");
const openDashboardBtn = document.getElementById("open-dashboard-btn");

// Settings Elements
const tabButtons = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");
const saveSettingsBtn = document.getElementById("save-settings-btn");
const aiEngineToggle = document.getElementById("ai-engine-toggle");

// The redacted configuration this window is allowed to see. It carries no signing
// key and no API key value — see get_agent_config in src-tauri/src/lib.rs.
let currentConfig = null;

// A saved API key never comes back to this window; it stays in the OS keychain and
// `get_agent_config` reports only whether one exists. So the field shows a fixed
// stand-in instead, and the save path reads it as three different intentions:
//   the stand-in, untouched -> keep the stored key (nothing is sent)
//   anything else typed in  -> replace it with what was typed
//   an empty field          -> delete the stored key
const SAVED_API_KEY_STANDIN = "••••••••••••••••";
let llmApiKeyIsSet = false;



// Tracking UI State Sync
function updateTrackingUI(isActive) {
  const badge = document.getElementById("status-badge");
  const statusText = document.getElementById("status-text");
  const toggleIcon = document.getElementById("toggle-btn-icon");
  const toggleText = document.getElementById("toggle-btn-text");
  const toggleBtn = document.getElementById("toggle-tracking-btn");

  if (!badge || !statusText || !toggleIcon || !toggleText || !toggleBtn) return;

  if (isActive) {
    badge.className = "status-badge active";
    statusText.innerText = "Active";
    toggleIcon.innerText = "⏸";
    toggleText.innerText = "Pause Tracking";
    toggleBtn.className = "btn btn-primary";
  } else {
    badge.className = "status-badge paused";
    statusText.innerText = "Paused";
    toggleIcon.innerText = "▶";
    toggleText.innerText = "Resume Tracking";
    toggleBtn.className = "btn btn-primary paused-state";
  }
}

// Fetch Today's Metrics
async function refreshMetrics() {
  try {
    const metrics = await invoke("get_today_metrics");
    
    // 1. Hero Metric (Billable Time / Total Slots)
    const billableEl = document.getElementById("metric-billable-time-main");
    const subSlotsEl = document.getElementById("metric-total-slots-sub");
    
    if (billableEl && subSlotsEl) {
      // Only slots that cleared the focus gate bill 10 min each (ADR 0012);
      // "slots logged" below counts every slot with at least one productive minute,
      // so billable_slots is always a subset you can count on the timeline.
      const billableMins = metrics.billable_slots * 10;
      if (billableMins >= 60) {
        const hrs = Math.floor(billableMins / 60);
        const remMins = billableMins % 60;
        billableEl.innerText = `${hrs}h ${remMins}m`;
      } else {
        billableEl.innerText = `${billableMins}m`;
      }
      
      const slotText = metrics.total_slots === 1 ? "Slot" : "Slots";
      subSlotsEl.innerText = `${metrics.total_slots} ${slotText} Logged Today`;
    }

    // 2. Slot Timeline
    const timelineContainer = document.getElementById("slot-timeline-container");
    if (timelineContainer && metrics.slot_scores) {
      timelineContainer.innerHTML = ""; // Clear existing
      metrics.slot_scores.forEach(score => {
        const block = document.createElement("div");
        block.className = "slot-block";
        if (score >= 80) {
          block.classList.add("focus-high");
        } else if (score >= 40) {
          block.classList.add("focus-medium");
        } else {
          block.classList.add("focus-low");
        }
        timelineContainer.appendChild(block);
      });
    }

    // 3. Secondary Metrics
    const focusEl = document.getElementById("metric-focus-score");
    if (focusEl) {
      focusEl.innerText = `${metrics.average_focus}%`;
    }

    const activeTimeEl = document.getElementById("metric-active-time");
    if (activeTimeEl) {
      const mins = metrics.active_minutes;
      if (mins >= 60) {
        const hrs = Math.floor(mins / 60);
        const remMins = mins % 60;
        activeTimeEl.innerText = `${hrs}h ${remMins}m`;
      } else {
        activeTimeEl.innerText = `${mins}m`;
      }
    }

    const inputsEl = document.getElementById("metric-total-inputs");
    if (inputsEl) {
      const totalInputs = metrics.total_keystrokes + metrics.total_clicks;
      inputsEl.innerText = totalInputs.toLocaleString();
    }
  } catch (err) {
    console.error("Failed to fetch today's metrics:", err);
  }
}

// Check Agent Enrollment Status
let isEnrolled = false;
async function checkStatus() {
  try {
    const status = await invoke("get_agent_status");
    isEnrolled = status.enrolled;
    updateTrackingUI(status.tracking_active);

    if (enrollmentDetails) {
      if (isEnrolled) {
        enrollmentDetails.style.display = "flex";
        if (settingAgentId) settingAgentId.innerText = status.agent_id;
        if (settingPublicKey) settingPublicKey.innerText = status.public_key;
      } else {
        enrollmentDetails.style.display = "none";
      }
    }

    await refreshMetrics();
  } catch (err) {
    console.error("Failed to check agent status:", err);
  }
}

// LLM Input Toggling
function toggleLlmFields(isEnabled) {
  const llmFields = document.getElementById("llm-fields");
  if (llmFields) {
    llmFields.style.display = isEnabled ? "flex" : "none";
  }
  // The daily-work-note switch is inside #llm-fields, so turning the engine off takes
  // it off screen along with the fields. Since the engine now decides whether notes
  // are written at all (#96), the off state has to say so in the switch's place.
  const engineScopeNote = document.getElementById("engine-scope-note");
  if (engineScopeNote) {
    engineScopeNote.style.display = isEnabled ? "block" : "none";
  }
  const engineOffNotice = document.getElementById("engine-off-notice");
  if (engineOffNotice) {
    engineOffNotice.style.display = isEnabled ? "none" : "block";
  }
}

if (aiEngineToggle) {
  aiEngineToggle.addEventListener("change", (e) => {
    toggleLlmFields(e.target.checked);
    // Clear validation error when toggling AI
    const errorEl = document.getElementById("validation-error");
    if (errorEl) {
      errorEl.style.display = "none";
    }
  });
}

// Clear validation error when user types API Key
const aiApiKeyInput = document.getElementById("ai-api-key");
if (aiApiKeyInput) {
  aiApiKeyInput.addEventListener("input", () => {
    const errorEl = document.getElementById("validation-error");
    if (errorEl) {
      errorEl.style.display = "none";
    }
  });
  // Focusing the stand-in selects it, so typing replaces the saved key in one go
  // and backspacing clears the field — the two things the field can mean. Selecting
  // is not editing, so simply clicking in and out still counts as untouched.
  aiApiKeyInput.addEventListener("focus", () => {
    if (llmApiKeyIsSet && aiApiKeyInput.value === SAVED_API_KEY_STANDIN) {
      aiApiKeyInput.select();
    }
  });
}

// Per-provider endpoint/model defaults, read from the daemon (see llm.rs) so
// this form always shows what the auditor will actually call.
let llmProviderDefaults = {};

async function loadLlmProviderDefaults() {
  try {
    const rows = await invoke("get_llm_provider_defaults");
    llmProviderDefaults = Object.fromEntries(
      rows.map(r => [r.provider, { baseUrl: r.base_url, model: r.model }])
    );
  } catch (err) {
    console.error("Failed to load LLM provider defaults:", err);
    llmProviderDefaults = {};
  }
}

// A local endpoint's traffic never leaves the machine, so it may use plain
// http and needs no API key. Mirrors is_loopback_url() in llm.rs.
function isLoopbackUrl(raw) {
  try {
    const host = new URL(raw).hostname.replace(/^\[|\]$/g, "");
    return host === "localhost" || host === "::1" || /^127\./.test(host);
  } catch {
    return false;
  }
}

// Mirrors validate_base_url() in llm.rs. Returns an error string, or null.
function validateBaseUrl(raw) {
  const value = raw.trim();
  if (!value) return null; // empty = use the provider default
  let url;
  try {
    url = new URL(value);
  } catch {
    return "⚠️ API Base URL must be a full URL, e.g. https://api.example.com/v1";
  }
  if (url.protocol === "https:") return null;
  if (url.protocol === "http:" && isLoopbackUrl(value)) return null;
  if (url.protocol === "http:") {
    return "⚠️ API Base URL must use https (http is allowed only for localhost). " +
      "Your API key and window titles would otherwise travel unencrypted.";
  }
  return `⚠️ Unsupported URL scheme '${url.protocol.replace(":", "")}': use https`;
}

// Show each field's effective value as its placeholder, so a blank field is
// never ambiguous about what the daemon will use.
function updateLlmProviderHints() {
  const provider = document.getElementById("ai-provider").value;
  const defaults = llmProviderDefaults[provider];
  const modelInput = document.getElementById("ai-model");
  const baseUrlInput = document.getElementById("ai-base-url");
  const modelHint = document.getElementById("ai-model-hint");
  const baseUrlHint = document.getElementById("ai-base-url-hint");
  const apiKeyHint = document.getElementById("ai-api-key-hint");

  if (modelInput) modelInput.placeholder = defaults ? defaults.model : "";
  if (baseUrlInput) baseUrlInput.placeholder = defaults ? defaults.baseUrl : "";
  if (modelHint) {
    modelHint.innerText = defaults
      ? `Leave blank to use ${defaults.model}.`
      : "";
  }
  if (baseUrlHint) {
    baseUrlHint.innerText = defaults
      ? `Leave blank to use ${defaults.baseUrl}. Point this at a company gateway, ` +
        "or at a local model (Ollama: http://localhost:11434/v1 with the OpenAI provider)."
      : "";
  }
  if (apiKeyHint) {
    const local = baseUrlInput && isLoopbackUrl(baseUrlInput.value.trim());
    if (local) {
      apiKeyHint.innerText = "Not required for a local endpoint.";
    } else if (llmApiKeyIsSet) {
      apiKeyHint.innerText =
        "A key is saved in your OS keychain. It is never read back into this window, " +
        "so leave this field as it is to keep it, type a new key to replace it, or " +
        "clear the field to delete it.";
    } else {
      apiKeyHint.innerText =
        "Stored in your OS keychain, never in a file and never sent to tenby10.";
    }
  }
}

const aiProviderSelect = document.getElementById("ai-provider");
if (aiProviderSelect) {
  aiProviderSelect.addEventListener("change", updateLlmProviderHints);
}

const aiBaseUrlInput = document.getElementById("ai-base-url");
if (aiBaseUrlInput) {
  aiBaseUrlInput.addEventListener("input", () => {
    updateLlmProviderHints();
    const errorEl = document.getElementById("validation-error");
    if (errorEl) {
      errorEl.style.display = "none";
    }
  });
}

// Prompt length limit. A prompt is bound into every record it scores by hash, and a record
// is only accepted once the prompt behind it is stored — so a prompt too long to sync would
// stop those records uploading, silently and for good. The daemon owns the number; this is
// only the fallback for the moment before it answers.
let maxPromptBytes = 32 * 1024;

async function loadPromptLimit() {
  try {
    maxPromptBytes = await invoke("get_max_prompt_bytes");
  } catch (err) {
    console.error("Failed to read the prompt length limit:", err);
  }
}

// The limit is a byte count (that is what the sync endpoint measures), and one typed
// character is not always one byte.
function promptByteLength(text) {
  return new TextEncoder().encode(text).length;
}

function formatBytes(bytes) {
  return bytes < 1024 ? `${bytes} characters` : `${Math.round(bytes / 1024)} KB`;
}

// Show how long a prompt is only once it is long enough to matter: silence for an ordinary
// prompt, a heads-up as it nears the limit, a plain refusal past it.
function updatePromptLengthHint(textareaId, hintId) {
  const textarea = document.getElementById(textareaId);
  const hint = document.getElementById(hintId);
  if (!textarea || !hint) return;

  const used = promptByteLength(textarea.value);
  if (used > maxPromptBytes) {
    hint.innerText =
      `Too long to save: ${formatBytes(used)} of ${formatBytes(maxPromptBytes)}. ` +
      `Please remove about ${formatBytes(used - maxPromptBytes)}.`;
    hint.className = "length-hint over-limit";
    hint.style.display = "block";
  } else if (used > maxPromptBytes * 0.8) {
    hint.innerText = `${formatBytes(used)} of ${formatBytes(maxPromptBytes)} used.`;
    hint.className = "length-hint";
    hint.style.display = "block";
  } else {
    hint.style.display = "none";
  }
}

function updateTokenEstimate() {
  const promptText = document.getElementById("ai-prompt").value;
  const wordCount = promptText.trim().split(/\s+/).filter(w => w.length > 0).length;
  const promptTokens = Math.ceil(wordCount * 1.3);
  const slotInputTokens = 150; // Text log data payload per slot
  const expectedOutputTokens = 300; // Expected LLM reasoning + JSON output
  const dailySlots = 48; // 8 hours of active time

  const dailyTextTotal = dailySlots * (promptTokens + slotInputTokens + expectedOutputTokens);

  const tokenEstimateEl = document.getElementById("token-estimate");
  if (tokenEstimateEl) {
    tokenEstimateEl.innerText = `Estimated daily usage (8h active): ~${(dailyTextTotal / 1000).toFixed(1)}k tokens`;
  }
}

const aiPromptTextarea = document.getElementById("ai-prompt");
if (aiPromptTextarea) {
  aiPromptTextarea.addEventListener("input", () => {
    updateTokenEstimate();
    updatePromptLengthHint("ai-prompt", "ai-prompt-length");
    const errorEl = document.getElementById("validation-error");
    if (errorEl) {
      errorEl.style.display = "none";
    }
  });
}

const summaryPromptTextarea = document.getElementById("summary-prompt");
if (summaryPromptTextarea) {
  summaryPromptTextarea.addEventListener("input", () => {
    updatePromptLengthHint("summary-prompt", "summary-prompt-length");
    const errorEl = document.getElementById("validation-error");
    if (errorEl) {
      errorEl.style.display = "none";
    }
  });
}

// Load Full Configuration
async function loadAgentConfig() {
  try {
    currentConfig = await invoke("get_agent_config");
    await loadPromptLimit();

    // Rules
    document.getElementById("rules-productive").value = currentConfig.productive_apps || "";
    document.getElementById("rules-distracting").value = currentConfig.distracting_apps || "";
    document.getElementById("rules-meeting").value = currentConfig.meeting_apps || "";

    // AI
    const isLlm = currentConfig.engine_mode === "llm";
    if (aiEngineToggle) {
      aiEngineToggle.checked = isLlm;
    }
    document.getElementById("ai-provider").value = currentConfig.llm_provider || "openai";
    llmApiKeyIsSet = currentConfig.llm_api_key_set === true;
    document.getElementById("ai-api-key").value = llmApiKeyIsSet ? SAVED_API_KEY_STANDIN : "";
    document.getElementById("ai-model").value = currentConfig.llm_model || "";
    document.getElementById("ai-base-url").value = currentConfig.llm_base_url || "";
    await loadLlmProviderDefaults();
    updateLlmProviderHints();
    document.getElementById("ai-prompt").value = currentConfig.llm_prompt || "";

    // Work notes are on unless explicitly turned off (ADR 0019): the config stores
    // the opt-out, the switch shows the state.
    const summaryToggle = document.getElementById("summary-toggle");
    if (summaryToggle) {
      summaryToggle.checked = !currentConfig.disable_work_summaries;
    }
    const summaryPrompt = document.getElementById("summary-prompt");
    if (summaryPrompt) {
      summaryPrompt.value = currentConfig.summary_prompt || "";
    }

    updateTokenEstimate();
    updatePromptLengthHint("ai-prompt", "ai-prompt-length");
    updatePromptLengthHint("summary-prompt", "summary-prompt-length");
    toggleLlmFields(isLlm);
  } catch (err) {
    console.error("Failed to load agent config:", err);
  }
}

// View Switches
if (gotoSettingsBtn) {
  gotoSettingsBtn.addEventListener("click", async () => {
    dashboardView.style.display = "none";
    settingsView.style.display = "flex";
    await loadAgentConfig();
    // Normalize to the first tab so its content + Save button state are correct on open.
    const firstTab = document.querySelector(".tab-btn");
    if (firstTab) firstTab.click();
  });
}

if (backToDashboardBtn) {
  backToDashboardBtn.addEventListener("click", () => {
    dashboardView.style.display = "flex";
    settingsView.style.display = "none";
    // Metrics freeze while Settings is open (the interval guard requires the dashboard
    // view to be visible), so snap them back to current on return instead of waiting up
    // to 10s for the next tick.
    refreshMetrics();
  });
}

// Settings Tab Toggles
tabButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    const targetTabId = btn.getAttribute("data-tab");

    tabButtons.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");

    tabContents.forEach(content => {
      content.style.display = content.id === targetTabId ? "flex" : "none";
    });

    // Clear validation errors when switching tabs
    const errorEl = document.getElementById("validation-error");
    if (errorEl) {
      errorEl.style.display = "none";
    }

    if (saveSettingsBtn) {
      saveSettingsBtn.style.display = (targetTabId === "tab-saas" || targetTabId === "tab-permissions") ? "none" : "block";
    }
    if (targetTabId === "tab-permissions") {
      checkPermissionsStatus();
    }
  });
});

// Save Settings Event Handler
if (saveSettingsBtn) {
  saveSettingsBtn.addEventListener("click", async () => {
    if (!currentConfig) return;

    saveSettingsBtn.disabled = true;
    saveSettingsBtn.innerText = "Saving...";

    try {
      // No re-fetch: the payload below carries only the fields this form owns, and
      // the backend merges it into the stored configuration. Identity, the signing
      // key and an untouched API key are preserved there, by never leaving there.
      const config = {};

      // Evaluation Rules
      config.productive_apps = document.getElementById("rules-productive").value.trim();
      config.distracting_apps = document.getElementById("rules-distracting").value.trim();
      config.meeting_apps = document.getElementById("rules-meeting").value.trim();

      // Clear previous validation error
      const errorEl = document.getElementById("validation-error");
      if (errorEl) {
        errorEl.style.display = "none";
        errorEl.innerText = "";
      }

      // AI Settings
      const isLlmEnabled = (aiEngineToggle && aiEngineToggle.checked);

      // The API key field, read as an intention rather than a value (see
      // SAVED_API_KEY_STANDIN). `null` means "send nothing, keep what is stored".
      const apiKeyField = document.getElementById("ai-api-key").value;
      const apiKeyUntouched = llmApiKeyIsSet && apiKeyField === SAVED_API_KEY_STANDIN;
      const apiKeyUpdate = apiKeyUntouched ? null : apiKeyField.trim();
      // Whether a key will be in place once this save lands — which is what the
      // "AI needs a key" check has to ask, now that the field can be a stand-in.
      const willHaveApiKey = apiKeyUntouched || apiKeyUpdate !== "";

      const prompt = document.getElementById("ai-prompt").value.trim();
      const baseUrl = document.getElementById("ai-base-url").value.trim();
      const model = document.getElementById("ai-model").value.trim();

      const rejectSave = (message) => {
        if (errorEl) {
          errorEl.innerText = message;
          errorEl.style.display = "block";
        }
        saveSettingsBtn.disabled = false;
        saveSettingsBtn.innerText = "Save Settings";
      };

      if (isLlmEnabled) {
        const baseUrlError = validateBaseUrl(baseUrl);
        if (baseUrlError) {
          rejectSave(baseUrlError);
          return;
        }
        // A local endpoint needs no key (Ollama ignores it); every remote one does.
        if (!willHaveApiKey && !isLoopbackUrl(baseUrl)) {
          rejectSave("⚠️ API Key is required when AI Auditor is enabled.");
          return;
        }
        if (!prompt) {
          rejectSave("⚠️ System Auditor Prompt is required when AI Auditor is enabled.");
          return;
        }
      }

      const summaryToggleEl = document.getElementById("summary-toggle");
      const summaryPromptEl = document.getElementById("summary-prompt");
      if (isLlmEnabled && summaryToggleEl && summaryToggleEl.checked) {
        // A note with no rules behind it is exactly what we refuse to produce.
        if (summaryPromptEl && !summaryPromptEl.value.trim()) {
          rejectSave("⚠️ Work Note Prompt is required while daily work notes are on.");
          return;
        }
      }

      // Length is checked whatever the engine is set to: the auditor prompt is part of the
      // rules every slot is signed against, so an over-long one stalls uploads even with the
      // AI switched off. The daemon refuses these too — this is so the user is told in the
      // form they typed it in, next to the field at fault.
      const summaryPromptText = summaryPromptEl ? summaryPromptEl.value.trim() : "";
      const tooLong = [
        ["System Auditor Prompt", prompt],
        ["Work Note Prompt", summaryPromptText],
      ].find(([, text]) => promptByteLength(text) > maxPromptBytes);
      if (tooLong) {
        const [label, text] = tooLong;
        rejectSave(
          `⚠️ The ${label} is too long (${formatBytes(promptByteLength(text))}). ` +
          `Please shorten it to under ${formatBytes(maxPromptBytes)} — a longer prompt ` +
          `cannot be synced, and your time would stop uploading.`
        );
        return;
      }

      config.engine_mode = isLlmEnabled ? "llm" : "static";
      config.disable_work_summaries = !(summaryToggleEl && summaryToggleEl.checked);
      // Every field the payload carries is authoritative, so a missing textarea must
      // resend what is stored rather than blank the prompt every note is signed against.
      config.summary_prompt = summaryPromptEl ? summaryPromptText : (currentConfig.summary_prompt || "");
      config.llm_provider = document.getElementById("ai-provider").value;
      // Write-only: null keeps the stored key, "" deletes it, anything else replaces it.
      config.llm_api_key = apiKeyUpdate;
      config.llm_base_url = baseUrl;
      config.llm_model = model;
      config.llm_prompt = prompt;

      await invoke("save_agent_config", { newConfig: config });

      // Re-read the redacted config so the form reflects what was actually stored,
      // and so the API key field goes back to a stand-in rather than sitting there
      // holding the key the user just typed.
      await loadAgentConfig();

      saveSettingsBtn.innerText = "✓ Saved!";
      setTimeout(() => {
        saveSettingsBtn.disabled = false;
        saveSettingsBtn.innerText = "Save Settings";
      }, 1200);

      await refreshMetrics();
    } catch (err) {
      alert("Failed to save settings: " + err);
      saveSettingsBtn.disabled = false;
      saveSettingsBtn.innerText = "Save Settings";
    }
  });
}

// Action handlers
if (toggleTrackingBtn) {
  toggleTrackingBtn.addEventListener("click", async () => {
    toggleTrackingBtn.disabled = true;
    try {
      const newState = await invoke("toggle_tracking");
      updateTrackingUI(newState);
    } catch (err) {
      alert("Failed to toggle tracking: " + err);
    } finally {
      toggleTrackingBtn.disabled = false;
    }
  });
}

const activityView = document.getElementById("activity-view");
const activityFrame = document.getElementById("activity-frame");

async function enterDashboard() {
  // Lazy-load the dashboard document on first open.
  if (activityFrame && !activityFrame.getAttribute("src")) {
    activityFrame.setAttribute("src", "dashboard.html");
  }
  dashboardView.style.display = "none";
  if (settingsView) settingsView.style.display = "none";
  if (activityView) activityView.style.display = "block";
  try {
    await invoke("set_dashboard_mode", { expand: true });
  } catch (err) {
    console.error("Failed to size window for dashboard:", err);
  }
}

// Exposed globally so the embedded dashboard's "Back" control can call it.
async function exitDashboard() {
  if (activityView) activityView.style.display = "none";
  dashboardView.style.display = "flex";
  try {
    await invoke("set_dashboard_mode", { expand: false });
  } catch (err) {
    console.error("Failed to restore window size:", err);
  }
}
window.exitDashboard = exitDashboard;

// The dashboard iframe is same-origin but can't reach into this scope directly,
// so it asks to close via postMessage as well as the window.exitDashboard hook.
window.addEventListener("message", (event) => {
  if (event.data && event.data.type === "tenby10-exit-dashboard") {
    exitDashboard();
  }
});

// Esc leaves the dashboard view.
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && activityView && activityView.style.display === "block") {
    exitDashboard();
  }
});

if (openDashboardBtn) {
  openDashboardBtn.addEventListener("click", enterDashboard);
}

// Enrollment Form Submit
if (enrollForm) {
  enrollForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const token = enrollInput.value.trim();
    if (!token) return;

    enrollBtn.disabled = true;
    enrollBtn.innerText = "Linking…";

    try {
      await invoke("enroll_agent", { token });
      enrollInput.value = "";
      await checkStatus();
    } catch (err) {
      alert("Couldn't link this device: " + err);
    } finally {
      enrollBtn.disabled = false;
      enrollBtn.innerText = "Link device";
    }
  });
}

// Listen to System Tray tracking events
listen("tracking-status-changed", (event) => {
  const newState = event.payload;
  updateTrackingUI(newState);
});

// Permissions Verification Logic
async function checkPermissionsStatus() {
  try {
    const status = await invoke("check_permissions");

    // macOS caches the Screen Recording preflight: CGPreflightScreenCaptureAccess
    // keeps returning true after the grant is revoked. Cross-check it against
    // ground truth (are window titles actually coming back?) so a stale-green
    // permission can never read as "Granted" while titles arrive blank (issue #6).
    let screenRecordingGranted = status.screen_recording;
    if (screenRecordingGranted) {
      try {
        const health = await invoke("get_capture_health");
        if (!health.window_titles_ok) screenRecordingGranted = "stale";
      } catch {
        // Health unavailable — leave the preflight answer as-is rather than
        // inventing a failure.
      }
    }

    // Update individual status tags
    updatePermissionStatusUI("perm-input-monitoring-status", status.input_monitoring);
    updatePermissionStatusUI("perm-accessibility-status", status.accessibility);
    updatePermissionStatusUI("perm-screen-recording-status", screenRecordingGranted);
    updatePermissionStatusUI("perm-automation-status", status.automation);

    // Hide permissions tab completely if the OS doesn't require explicit permissions (Windows/Linux)
    const permTabBtn = document.querySelector('.tab-btn[data-tab="tab-permissions"]');
    if (permTabBtn) {
      permTabBtn.style.display = status.requires_permissions ? "inline-block" : "none";
    }

    // Update main dashboard warning banner. Input Monitoring is the permission that
    // actually gates keys/clicks/scroll capture, so it must be part of "anyMissing".
    const alertBanner = document.getElementById("permissions-alert-banner");
    if (alertBanner) {
      if (!status.requires_permissions) {
        alertBanner.style.display = "none";
      } else {
        // `screenRecordingGranted !== true` also catches the stale-green case, so a
        // machine that is silently not capturing still raises the banner.
        const anyMissing = !status.input_monitoring || !status.accessibility || screenRecordingGranted !== true || !status.automation;
        alertBanner.style.display = anyMissing ? "flex" : "none";
      }
    }
  } catch (err) {
    console.error("Failed to check permissions:", err);
  }
}

// Live capture health — ground truth, independent of the (cache-prone) TCC preflight.
async function checkCaptureHealth() {
  try {
    const health = await invoke("get_capture_health");

    const inputStatus = document.getElementById("health-input-status");
    const inputDetail = document.getElementById("health-input-detail");
    if (inputStatus && inputDetail) {
      if (!health.input_listener_alive) {
        inputStatus.innerText = "Not capturing";
        inputStatus.className = "status-indicator denied";
        inputDetail.innerText = "The input listener failed to start — grant Input Monitoring and restart tenby10.";
      } else if (health.input_recently_seen) {
        inputStatus.innerText = "Capturing";
        inputStatus.className = "status-indicator granted";
        inputDetail.innerText = "Keyboard/mouse events are being received.";
      } else {
        inputStatus.innerText = "Idle";
        inputStatus.className = "status-indicator unknown";
        inputDetail.innerText = health.input_idle_ms < 0
          ? "Listener is alive but no events seen yet — move the mouse or type to confirm."
          : `Listener alive; no input for ${Math.round(health.input_idle_ms / 1000)}s.`;
      }
    }

    const titlesStatus = document.getElementById("health-titles-status");
    const titlesDetail = document.getElementById("health-titles-detail");
    if (titlesStatus && titlesDetail) {
      if (health.window_titles_ok) {
        titlesStatus.innerText = "Readable";
        titlesStatus.className = "status-indicator granted";
        titlesDetail.innerText = "Window titles are coming back with real values — checked live.";
      } else {
        titlesStatus.innerText = "Blank";
        titlesStatus.className = "status-indicator denied";
        titlesDetail.innerText = "Titles keep coming back empty, which is what macOS does without Screen Recording. Grant it, then fully quit and relaunch tenby10.";
      }
    }
  } catch (err) {
    console.error("Failed to check capture health:", err);
  }
}

// `isGranted` is a boolean, or the string "stale" for a permission the OS reports
// as granted while a real capture attempt just failed (issue #6).
function updatePermissionStatusUI(elementId, isGranted) {
  const el = document.getElementById(elementId);
  if (!el) return;
  if (isGranted === "stale") {
    el.innerText = "Not capturing";
    el.className = "status-indicator denied";
    el.title = "macOS reports this permission as granted, but capture is failing right now. Re-grant Screen Recording, then fully quit and relaunch tenby10.";
  } else if (isGranted) {
    el.innerText = "Granted";
    el.className = "status-indicator granted";
    el.title = "";
  } else {
    el.innerText = "Denied";
    el.className = "status-indicator denied";
    el.title = "";
  }
}

// Permissions Tab Deep-Linking Actions
const btnInputMonitoring = document.getElementById("btn-open-input-monitoring");
if (btnInputMonitoring) {
  btnInputMonitoring.addEventListener("click", async () => {
    try {
      await invoke("open_input_monitoring_settings");
    } catch (err) {
      console.error(err);
    }
  });
}

const btnAccessibility = document.getElementById("btn-open-accessibility");
if (btnAccessibility) {
  btnAccessibility.addEventListener("click", async () => {
    try {
      await invoke("open_accessibility_settings");
    } catch (err) {
      console.error(err);
    }
  });
}

const btnScreenRecording = document.getElementById("btn-open-screen-recording");
if (btnScreenRecording) {
  btnScreenRecording.addEventListener("click", async () => {
    try {
      await invoke("open_screen_recording_settings");
    } catch (err) {
      console.error(err);
    }
  });
}

const btnAutomation = document.getElementById("btn-open-automation");
if (btnAutomation) {
  btnAutomation.addEventListener("click", async () => {
    try {
      await invoke("open_automation_settings");
    } catch (err) {
      console.error(err);
    }
  });
}

// Fix Permissions button on Dashboard
const fixPermissionsBtn = document.getElementById("fix-permissions-btn");
if (fixPermissionsBtn) {
  fixPermissionsBtn.addEventListener("click", () => {
    // Navigate to Settings view
    dashboardView.style.display = "none";
    settingsView.style.display = "flex";
    
    // Switch to Permissions tab
    const permTabBtn = document.querySelector('.tab-btn[data-tab="tab-permissions"]');
    if (permTabBtn) {
      permTabBtn.click();
    }
  });
}

// Startup initialization
checkStatus();
checkPermissionsStatus();
checkCaptureHealth();

// Refresh whenever the window regains focus, so a backgrounded window snaps to
// current the moment it is looked at. The WebView's setInterval is throttled/paused
// by macOS App Nap while backgrounded, so without this the metrics can be minutes
// stale on refocus — diverging from the always-foreground web dashboard even though
// both read the same DB.
function refreshOnFocus() {
  checkPermissionsStatus();
  checkCaptureHealth();
  // Metrics are local (they don't depend on cloud enrollment), so refresh whenever
  // the dashboard is showing — gating on isEnrolled froze local-only users on the
  // startup snapshot forever (never updating on focus, the 10s loop, or a new day).
  if (dashboardView.style.display === "flex") {
    refreshMetrics();
  }
}
// Native OS focus event from Rust (fires reliably on app reactivation, where the DOM
// `focus` event below is unreliable — e.g. Cmd-Tab or clicking the title bar).
listen("window-focused", refreshOnFocus);
window.addEventListener("focus", refreshOnFocus);

// Refresh metrics and permissions loop
setInterval(() => {
  checkPermissionsStatus();
  checkCaptureHealth();
  if (dashboardView.style.display === "flex") {
    refreshMetrics();
  }
}, 10000);

