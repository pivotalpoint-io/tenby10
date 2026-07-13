# tenby10

[![CI](https://github.com/pivotalpoint-io/tenby10/actions/workflows/ci.yml/badge.svg)](https://github.com/pivotalpoint-io/tenby10/actions)
[![License: Source-Available (PPSAL-1.0)](https://img.shields.io/badge/License-Source--Available_(PPSAL--1.0)-purple.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://apple.com)

**tenby10** is a privacy-first, source-available desktop activity tracker. A local background daemon measures your work activity on-device and turns it into a **tamper-evident, cryptographically-signed** record of your time — using only input *counts* and locally blurred screenshots, never raw keystrokes or raw screens.

Everything is stored locally under `~/.tenby10/`. If you enroll a device, only signed 10-minute *summaries* and your scoring configuration are synced — raw keystrokes, screenshots, and window titles never leave your machine (see [AUDIT.md](AUDIT.md)). It also operates on a **Bring Your Own Key (BYOK)** model, letting you use your own private LLM configuration to summarize window titles into structured work notes directly on your machine.

> 🔍 **Don't trust — verify.** This is the full **source-available** client that runs on your machine. Before granting it input and screen access, read the **[Auditor's Guide (AUDIT.md)](AUDIT.md)**: it maps every privacy and fairness claim (no keylogging, no cloud exfiltration, fair scoring rules) to the exact source lines that prove it, and honestly lists where the code doesn't yet match our copy. An AI agent can follow it end-to-end to verify us.

---

## 🚀 Key Features

*   ⏱️ **Passive, Zero-Friction Tracking**: The background daemon automatically logs active application and window states. Includes a convenient Pause/Resume toggle switch in the system tray and settings UI to control when tracking is active.
*   🔒 **Local-First & Sandbox Storage**: All minute logs, configuration files, and screen captures are stored strictly on your machine under `~/.tenby10/`.
    - **Development Mode**: When running from source in debug mode, the app automatically isolates itself to `~/.tenby10_dev/`.
    - **Environment Overrides**: Use `TENBY10_HOME` to override the base directory and `TENBY10_PORT` to override the dashboard port (default: 5005).
*   🛡️ **Tamper-Evident Ledger**: Each 10-minute slot summary is SHA-256 hash-chained over its **full** payload, so editing any stored field breaks the chain. Once you enroll, every slot is additionally **Ed25519-signed with your key**, so even a re-computed hash won't verify without that key. On a machine you control this is tamper-*evidence* and self-asserted authorship — not, by itself, third-party proof.
*   🧠 **BYOK Local AI Scribe**: Connects directly to your own provider (OpenAI, Anthropic, or Gemini) to analyze active logs and generate professional work summaries. 
*   🟢 **10-Minute Slot Standard**: Records your day in verifiable 10-minute slots, each hash-chained and — once you enroll — signed with your key.

---

## 🛠️ Architecture Overview

The codebase is structured as a lightweight monorepo containing two core components:

```
                  ┌──────────────────────────────────────────────┐
                  │              Tauri Desktop App               │
                  │   - Settings UI (token, LLM key, toggle)     │
                  │   - Starts Rust daemon on app initialize     │
                  └──────────────┬───────────────────────────────┘
                                 │ Spawns
                                 ▼
                  ┌──────────────────────────────────────────────┐
                  │              Background Daemon               │
                  │   - Global OS Input Listeners (rdev)         │
                  │   - Window Scraper (polling at 10s)          │
                  │   - Screen Blur Capture (10m slot random)    │
                  │   - Local DB & Cryptographic Ledger          │
                  └──────────────┬───────────────────────────────┘
                                 │ Serves localhost:5005
                                 ▼
                  ┌──────────────────────────────────────────────┐
                  │             Analytics Dashboard              │
                  │   - HTML5 / CSS3 local dashboard UI          │
                  │   - Interactive focus entropy graphs         │
                  │   - Blurred timeline screen browser          │
                  └──────────────────────────────────────────────┘
```

1.  **Background Daemon (`/daemon`)**: A background service written in Rust that handles global OS input hooks, scrapes active window titles at a 10s interval, processes Gaussian blurred screenshots, maintains the local SQLite database (`tenby10.db`), and exposes a local Axum HTTP server at `localhost:5005`.
2.  **Desktop GUI (`/desktop`)**: A native desktop wrapper built using **Tauri (v2)** with a frosted glassmorphism settings interface, enabling cryptographic key enrollment and configuration management.

---

## 🔒 Privacy & Security Blueprint

*   **In-Memory Screen Blurring**: The daemon captures the active screen once per 10-minute slot. The raw image buffer is immediately processed in-memory using a 20px Gaussian blur. Only the blurred low-resolution JPEG (~13 KB) is written to the disk. The raw screenshot is immediately discarded from memory and **never** hits the persistent storage.
*   **Negligible Footprint**: Telemetry metrics consume under **700 KB per active workday** (~80 KB SQLite DB + ~624 KB blurred screenshots), translating to less than 170 MB of disk usage per year. No background database fragmentation or CPU spikes are caused by automated deletion/vacuum cycles.
*   **On-device by default — you decide what leaves**: Nothing is uploaded until *you* choose to share verifiable reports (by enrolling a device). The split is deliberate:
    - **Always stays on your machine**: raw keystrokes (only *counts* are kept — never the keys), the screen (blurred in memory; only a low-res blurred JPEG is saved), window titles, and the full activity database under `~/.tenby10/`.
    - **Leaves only when you share a report**: signed 10-minute *summaries* (focus score, active/idle and input **counts**, app-category counts, a **hash** of any AI note) plus your scoring configuration — enough for a recipient to see the numbers and which rules produced them. Raw keystrokes, screenshots, and window titles are **never** uploaded.
    - **Your own AI, opt-in and separate**: if you enable BYOK LLM scoring, activity text (including window titles) goes directly to *your* provider using *your* key — to your provider, never to tenby10.

---

## 🛡️ Anti-Cheat Verification Layer

These are **speed bumps against lazy automation**, not a guarantee against a determined cheater — the detector's source ships with this client, so any fixed rule can be tuned around. They raise the cost of off-the-shelf jigglers and naive macros, and feed higher-layer checks; they bias toward *never flagging a real person* over catching every bot. Over a rolling multi-minute window the tracker looks at the **structure** of input, not its raw magnitude:
1.  **Mouse Path Structure**: Flags cursor motion that is confined to a tiny region despite a long path (in-place jiggling), or moves at robotically constant speed and direction. Genuine human movement — including fast, straight swipes that accelerate and decelerate — is left alone.
2.  **Keystroke Regularity**: Flags inter-key timing that is too regular *for its own rate* (low coefficient of variation), which catches jittered macros and even ~1-key/min macros that an absolute-threshold check misses. Real typing, with its bursts and pauses, varies far more.
3.  **Signed Log Ledger**: Every 10-minute slot summary is hash-chained to its parent over the slot's full payload using `SHA-256`, and (once enrolled) Ed25519-signed with your key. Editing a row breaks the chain; re-computing the hash to hide the edit still fails signature verification. This is tamper-evidence you control — see [AUDIT.md](AUDIT.md) for the honest scope and limits.

---

## 💻 Local Development & Build

### Prerequisites
*   [Rust & Cargo](https://rustup.rs/) (edition 2024 or newer)
*   [Node.js & npm](https://nodejs.org/) (for Tauri desktop app bindings)

### 1. Build and Run the Telemetry Daemon
```bash
cd daemon
# Build daemon binaries
cargo build --release

# Run daemon manually (spawns the Axum local dashboard server on http://localhost:5005)
cargo run
```

### 2. Build and Run the Tauri Desktop App
```bash
cd desktop
# Install dependencies
npm install

# Run the Tauri app in development mode
npm run tauri dev
```

### Dev vs. prod on macOS (permissions)

macOS grants Screen Recording / Input Monitoring / Accessibility per **code-signing
identity**, so dev and prod must be distinct apps or they clobber each other's grants.

- `scripts/dev.sh` (`tauri dev`) — fast iteration. Runs the raw cargo binary
  `tenby10-desktop` with a **volatile ad-hoc signature** (cdhash changes every rebuild)
  that shares its executable name with the prod app. **Do not grant/test macOS
  permissions here** — grants are invalidated on the next rebuild and can confuse the
  prod app's Privacy entries.
- `scripts/dev_bundle.sh` — builds & installs `tenby10-dev.app` with a fully distinct,
  stable identity (`io.pivotalpoint.tenby10.dev`, binary `tenby10-dev`). **Use this for
  permission-accurate local testing.** Set `APPLE_SIGNING_IDENTITY` (Developer ID) for a
  grant that survives rebuilds. The dev app self-isolates to `~/.tenby10_dev` / port 5006.
- `scripts/prod.sh` — prod config locally (identity `io.pivotalpoint.tenby10`).

> Input capture (keys/clicks/scroll) requires **Input Monitoring**, *not* Accessibility —
> the settings page reports both, plus a live capture-health readout that reflects whether
> telemetry is actually being captured.

---

## 🧪 Testing & CI/CD

Both the background daemon and the Tauri desktop projects are equipped with robust unit tests.

### Running Tests Locally
```bash
# Test the daemon crate
cd daemon && cargo test

# Test the desktop crate
cd desktop/src-tauri && cargo test
```

### Setup Pre-commit Hooks
To automate testing, formatting, and linting checks locally before committing, run the setup script:
```bash
./scripts/setup_hooks.sh
```

### CI/CD Workflow
The repository utilizes GitHub Actions to ensure code quality. On every push and pull request to `main`, the workflow [.github/workflows/ci.yml](.github/workflows/ci.yml) builds, formats (`cargo fmt`), checks lints (`cargo clippy -- -D warnings`), and executes tests for both crates in parallel. 

**Releases are tag-driven**: The expensive "Release Build and Smoke Test" job only triggers when a version tag (e.g., `v1.2.3`) is pushed to the repository.

---

## 🔐 Security

Found a vulnerability? Please report it **privately** — do not open a public issue. See [SECURITY.md](SECURITY.md) for the reporting process (GitHub private vulnerability reporting or `security@pivotalpoint.io`) and scope.

---

## 🤝 Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) to learn about our branch strategy, commit message rules, and software development lifecycle (SDLC) flow.
