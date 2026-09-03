# tenby10

[![CI](https://github.com/pivotalpoint-io/tenby10/actions/workflows/ci.yml/badge.svg)](https://github.com/pivotalpoint-io/tenby10/actions)
[![License: Source-Available (PPSAL-1.0)](https://img.shields.io/badge/License-Source--Available_(PPSAL--1.0)-purple.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://apple.com)

**tenby10** is a privacy-first, source-available desktop activity tracker. A local background daemon measures your work activity on-device and turns it into a **tamper-evident, cryptographically-signed** record of your time — using only input *counts*, app names and window titles — never raw keystrokes, and never an image of your screen.

Everything is stored locally under `~/.tenby10/`. If you enroll a device, what syncs is signed 10-minute *summaries*, your scoring configuration and, once you connect your own AI, one signed *work note* per finished day. **Raw keystrokes and raw window titles never reach tenby10.** The work note is a sentence your own AI writes *from* your window titles, so it is the one place title-*derived* text travels; **Privacy & Security Blueprint** below says what constrains it. [AUDIT.md §2](AUDIT.md#2-what-leaves-your-machine-network-egress-inventory) is the authoritative, field-by-field list of what leaves this machine. It also operates on a **Bring Your Own Key (BYOK)** model: connect a provider and activity text (including window titles) goes from your machine straight to the LLM provider *you* configure. Your key, your provider, never through tenby10. With local Ollama it stays fully on-device.

> 🔍 **Don't trust — verify.** This is the full **source-available** client that runs on your machine. Before granting it input and screen access, read the **[Auditor's Guide (AUDIT.md)](AUDIT.md)**: it maps every privacy and fairness claim (no keylogging, no screen capture, exactly what syncs, fair scoring rules) to the exact source lines that prove it, and honestly lists where the code doesn't yet match our copy. An AI agent can follow it end-to-end to verify us.

---

## 📦 Install

```bash
brew install --cask pivotalpoint-io/tap/tenby10
```

Or take the `.dmg` straight from [the latest release](https://github.com/pivotalpoint-io/tenby10/releases/latest). Apple silicon, macOS Big Sur or later, signed and notarized.

Windows installers ship with every release too, but they are **not code-signed yet**, so SmartScreen shows an unknown-publisher warning. That is it doing its job on an unsigned installer rather than a sign of anything wrong: verify the download through its [build provenance](#verifying-a-release-download) or build it yourself.

Uninstalling with `brew uninstall --cask tenby10` leaves your ledger under `~/.tenby10` alone, because it is your record and not ours. `--zap` deletes it.

---

## 🚀 Key Features

*   ⏱️ **Passive, Zero-Friction Tracking**: The background daemon automatically logs active application and window states. Includes a convenient Pause/Resume toggle switch in the system tray and settings UI to control when tracking is active.
*   🔒 **Local-First & Sandbox Storage**: All minute logs and configuration files are stored strictly on your machine under `~/.tenby10/`.
*   🚫 **No screen capture, by construction**: tenby10 takes no screenshots — there is no capture code in the client. Read [`daemon/src/`](daemon/src/) and check for yourself.
    - **Development Mode**: When running from source in debug mode, the app automatically isolates itself to `~/.tenby10_dev/`.
    - **Environment Overrides**: Use `TENBY10_HOME` to override the base directory. `TENBY10_DEBUG_HTTP` opts the standalone daemon into a loopback debug server (off by default), and `TENBY10_PORT` sets its port (default: 5005).
*   🛡️ **Tamper-Evident Ledger**: Each 10-minute slot summary is SHA-256 hash-chained over its **full** payload, so editing any stored field breaks the chain. Once you enroll, every slot is additionally **Ed25519-signed with your key**, so even a re-computed hash won't verify without that key. On a machine you control this is tamper-*evidence* and self-asserted authorship — not, by itself, third-party proof.
*   🧠 **BYOK Local AI Scribe**: Connects directly to your own provider (OpenAI, Anthropic, Gemini, or any OpenAI-compatible endpoint, including a local Ollama) to score slots and write one short work note per finished day.
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
                  │   - Window Scraper (one read per minute)     │
                  │   - Local DB & Cryptographic Ledger          │
                  └──────────────┬───────────────────────────────┘
                                 │ Tauri IPC (no network)
                                 ▼
                  ┌──────────────────────────────────────────────┐
                  │      Analytics Dashboard (in-app view)       │
                  │   - Renders inside the app window            │
                  │   - Interactive focus entropy graphs         │
                  └──────────────────────────────────────────────┘
```

1.  **Background Daemon (`/daemon`)**: A background service written in Rust that handles global OS input hooks, reads the frontmost app and window title once per 60-second aggregation cycle, and maintains the local SQLite database (`tenby10.db`). **The installed app opens no network port** — the dashboard reads from the daemon over Tauri IPC. A loopback HTTP server exists in the codebase purely as a debugging escape hatch for the standalone `daemon` binary, and stays off unless `TENBY10_DEBUG_HTTP` is explicitly set.
2.  **Desktop GUI (`/desktop`)**: A native desktop wrapper built using **Tauri (v2)** with a frosted glassmorphism settings interface, enabling cryptographic key enrollment and configuration management.

---

## 🔒 Privacy & Security Blueprint

*   **No screen capture at all**: tenby10 never reads the pixels on your screen. Earlier versions saved one heavily-blurred JPEG per 10-minute slot; that subsystem was removed outright (ADR 0018) rather than left switchable, and upgrading deletes the old `screenshots/` folder. macOS still asks for Screen Recording because it withholds *window titles* without it — the app reads titles, not pixels.
*   **Negligible Footprint**: Telemetry metrics consume well under **100 KB per active workday**, translating to a few MB of disk usage per year. There is no retention or vacuum cycle in the client, so nothing is deleted or compacted behind your back: what was recorded stays until you remove it.
*   **On-device by default — you decide what leaves**: Nothing is uploaded until *you* choose to share verifiable reports (by enrolling a device). The split is deliberate:
    - **Always stays on your machine**: raw keystrokes (only *counts* are kept — never the keys), raw window titles, and the full activity database under `~/.tenby10/`. Your screen is never captured at all.
    - **Leaves only when you share a report**: signed 10-minute *summaries* plus your scoring configuration, enough for a recipient to see the numbers and which rules produced them. [AUDIT.md §2](AUDIT.md#2-what-leaves-your-machine-network-egress-inventory) lists every field of every request, and is the one place that list is maintained.
    - **Your daily work note, once you connect an AI**: one or two sentences per finished day, written on your machine by *your* AI from your own window titles, then uploaded as text. It is on once an AI is configured and there is a switch in settings to turn it off. A raw title is never uploaded, but a sentence derived from one is, so three things constrain it. The daemon discards a note that reproduces a run of any of that day's window titles verbatim, before anything is signed; that check catches a quotation, not a paraphrase. The SHA-256 of the prompt that wrote the note is bound into the signed record, so a reader can see which rules were in force. And the note waits 12 hours on your machine, visible in your own dashboard first: revise or withdraw it inside that window and it never travels at all.
    - **Your own AI, opt-in and separate**: connect a provider and activity text (including window titles) goes directly to *your* provider using *your* key, for slot scoring when the LLM engine is on and for writing the work note. To your provider, never to tenby10.

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

# Run daemon manually (opens no network port)
cargo run

# Optional: also start the loopback debug dashboard for triage. It is
# unauthenticated — anything that can reach loopback on this machine can read the
# activity data and CSV it serves — so leave it off by default.
TENBY10_DEBUG_HTTP=1 cargo run   # then open http://localhost:5005
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

### Verifying a release download

Release artifacts ship with [build provenance attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations), so you can confirm a download was built by this repository's release workflow from a specific commit:

```bash
gh attestation verify tenby10_0.2.3_aarch64.dmg --repo pivotalpoint-io/tenby10
```

This attests where the artifact *came from*, not how the program behaves at runtime. Windows builds are not yet code-signed, so provenance is currently the way to check a Windows download is genuine. See [AUDIT.md](AUDIT.md) for the full verification guide.

---

## 🔐 Security

Found a vulnerability? Please report it **privately** — do not open a public issue. See [SECURITY.md](SECURITY.md) for the reporting process (GitHub private vulnerability reporting or `security@pivotalpoint.io`) and scope.

---

## 🤝 Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) to learn about our branch strategy, commit message rules, and software development lifecycle (SDLC) flow.
