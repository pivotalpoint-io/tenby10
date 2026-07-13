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

let currentConfig = null;



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
}

function updateTokenEstimate() {
  const promptText = document.getElementById("ai-prompt").value;
  const wordCount = promptText.trim().split(/\s+/).filter(w => w.length > 0).length;
  const promptTokens = Math.ceil(wordCount * 1.3);
  const slotInputTokens = 150; // Text log data payload per slot
  const expectedOutputTokens = 300; // Expected LLM reasoning + JSON output
  const dailySlots = 48; // 8 hours of active time

  const dailyTextTotal = dailySlots * (promptTokens + slotInputTokens + expectedOutputTokens);
  // Assume 1 screenshot per slot. A 1080p image is ~1,105 tokens for most vision models.
  const dailyImageTotal = dailyTextTotal + (dailySlots * 1105);
  
  const tokenEstimateEl = document.getElementById("token-estimate");
  if (tokenEstimateEl) {
    tokenEstimateEl.innerText = `Estimated daily usage (8h active): ~${(dailyTextTotal / 1000).toFixed(1)}k tokens (Text) / ~${(dailyImageTotal / 1000).toFixed(1)}k tokens (+ Screenshots)`;
  }
}

const aiPromptTextarea = document.getElementById("ai-prompt");
if (aiPromptTextarea) {
  aiPromptTextarea.addEventListener("input", () => {
    updateTokenEstimate();
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
    document.getElementById("ai-api-key").value = currentConfig.llm_api_key || "";
    document.getElementById("ai-prompt").value = currentConfig.llm_prompt || "";
    document.getElementById("ai-send-screenshots").checked = !!currentConfig.send_screenshots;

    updateTokenEstimate();
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
      // Re-fetch configuration to preserve SaaS credentials
      const config = await invoke("get_agent_config");

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
      const apiKey = document.getElementById("ai-api-key").value.trim();
      const prompt = document.getElementById("ai-prompt").value.trim();
      if (isLlmEnabled) {
        if (!apiKey) {
          if (errorEl) {
            errorEl.innerText = "⚠️ API Key is required when AI Auditor is enabled.";
            errorEl.style.display = "block";
          }
          saveSettingsBtn.disabled = false;
          saveSettingsBtn.innerText = "Save Settings";
          return;
        }
        if (!prompt) {
          if (errorEl) {
            errorEl.innerText = "⚠️ System Auditor Prompt is required when AI Auditor is enabled.";
            errorEl.style.display = "block";
          }
          saveSettingsBtn.disabled = false;
          saveSettingsBtn.innerText = "Save Settings";
          return;
        }
      }

      config.engine_mode = isLlmEnabled ? "llm" : "static";
      config.llm_provider = document.getElementById("ai-provider").value;
      config.llm_api_key = apiKey;
      config.llm_prompt = prompt;
      config.send_screenshots = document.getElementById("ai-send-screenshots").checked;

      await invoke("save_agent_config", { newConfig: config });
      currentConfig = config;

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

if (openDashboardBtn) {
  openDashboardBtn.addEventListener("click", async () => {
    try {
      await invoke("open_dashboard");
    } catch (err) {
      console.error("Failed to open local dashboard:", err);
    }
  });
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
    
    // Update individual status tags
    updatePermissionStatusUI("perm-input-monitoring-status", status.input_monitoring);
    updatePermissionStatusUI("perm-accessibility-status", status.accessibility);
    updatePermissionStatusUI("perm-screen-recording-status", status.screen_recording);
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
        const anyMissing = !status.input_monitoring || !status.accessibility || !status.screen_recording || !status.automation;
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

    const screenStatus = document.getElementById("health-screen-status");
    const screenDetail = document.getElementById("health-screen-detail");
    if (screenStatus && screenDetail) {
      if (health.screen_capture_ok) {
        screenStatus.innerText = "Capturing";
        screenStatus.className = "status-indicator granted";
        screenDetail.innerText = "Last screenshot was a real capture.";
      } else {
        screenStatus.innerText = "Not capturing";
        screenStatus.className = "status-indicator denied";
        screenDetail.innerText = "Last screenshot attempt failed — grant Screen Recording and restart tenby10. (Shows once the first slot completes.)";
      }
    }
  } catch (err) {
    console.error("Failed to check capture health:", err);
  }
}

function updatePermissionStatusUI(elementId, isGranted) {
  const el = document.getElementById(elementId);
  if (!el) return;
  if (isGranted) {
    el.innerText = "Granted";
    el.className = "status-indicator granted";
  } else {
    el.innerText = "Denied";
    el.className = "status-indicator denied";
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

