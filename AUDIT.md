# tenby10 Client — Auditor's Guide

**Audience:** any human or AI agent auditing the tenby10 desktop client before trusting it with
OS-level input and screen access.

**Claim under audit:** *"tenby10 is not a keylogger, does not capture anything sensitive, keeps
everything local, and scores your focus by fair, inspectable rules."*

This guide maps each of those claims to the exact source that proves (or, honestly, does **not** yet
prove) it. Every reference is `file:line` and is meant to be opened and read directly — do not take
this document's word for it. The `## How to verify` section at the bottom gives grep recipes so you
can re-derive every claim yourself.

This client is **source-available** under the PivotalPoint Source-Available License, Version 1.0
(PPSAL-1.0 — see [LICENSE](LICENSE)) — the full client that runs on your machine is readable and
auditable; the cloud portal is not part of this repository.

---

## TL;DR verdict table

| # | Claim | Status | Primary evidence |
|---|-------|--------|------------------|
| 1 | No key **content** is captured (not a keylogger) | ✅ Verified in code | [daemon.rs:88](daemon/src/daemon.rs#L88) — `KeyPress(_)` discards the key value |
| 2 | Only counts/metadata are stored per minute | ✅ Verified | [daemon.rs:235](daemon/src/daemon.rs#L235), [db.rs schema](daemon/src/db.rs) |
| 3 | Raw screenshots never touch disk; only blurred JPEGs saved | ✅ Verified | [screen.rs:47-66](daemon/src/screen.rs#L47) |
| 4 | Nothing is sent to a tenby10 cloud server | ✅ Verified (no such code exists yet) | No sync/HTTP-egress module in `daemon/src` |
| 5 | The only outbound network is your **own** BYOK LLM, opt-in | ✅ Verified | [llm.rs](daemon/src/llm.rs), gated by [daemon.rs:432](daemon/src/daemon.rs#L432) |
| 6 | Screenshots are never uploaded anywhere | ✅ Verified (stronger than claimed) | No image is attached to any LLM call — see Gap G1 |
| 7 | Focus-scoring rules are deterministic and inspectable | ✅ Verified | [evaluator.rs](daemon/src/evaluator.rs), [entropy.rs](daemon/src/entropy.rs) |
| 8 | Local logs are tamper-evident (full-payload hash chain) + self-signed when enrolled | ✅ Verified | [db.rs `insert_slot_summary`/`verify_ledger_integrity`](daemon/src/db.rs) |
| — | Secrets stored in OS keychain | ✅ Verified | [config.rs `save_config`/`load_config`](daemon/src/config.rs) — `private_key` & `llm_api_key` kept in the OS keychain via the `keyring` crate |
| — | Local dashboard makes no third-party calls | ✅ Verified | [dashboard.rs](daemon/src/dashboard.rs) — Outfit font embedded as a data URI; no CDN `<link>` |

Bottom line: the core privacy claims — **no keylogging, no cloud exfiltration, local-only raw
data** — hold up against the code. One honest gap remains between marketing copy and code (G1 below);
it does not leak your keystrokes or raw screen, but it should be closed so the code matches what we say.

---

## 1. Is it a keylogger? (What is captured from the keyboard)

**No key content is ever read.** The global input listener uses `rdev` and matches key events as
`KeyPress(_)` — the underscore **discards** the actual key/character. All it does is `+1` a counter
and record the *timing gap* between presses (for bot detection), never *what* was typed.

- [daemon.rs:87-98](daemon/src/daemon.rs#L87) — `KeyPress(_)` → increment `keystroke_count`, push
  the inter-key interval in ms. The keycode is pattern-matched away.
- [daemon.rs:99-103](daemon/src/daemon.rs#L99) — mouse buttons and scroll are counted the same way
  (counts only).
- [daemon.rs:105-118](daemon/src/daemon.rs#L105) — mouse *movement* stores `(x, y, timestamp)` for
  entropy analysis. This is cursor coordinates, not content.
- A **second, listen-only** macOS tap in [provenance.rs](daemon/src/provenance.rs) (issue #87) reads
  only the `kCGEventSourceStateID` field — whether an event came from real hardware vs. software
  injection — and counts synthetic vs. genuine events. It never reads the key value either, and passes
  every event through unchanged.

An auditor should confirm there is **no** branch anywhere that reads the key value. Grep recipe in
[How to verify](#how-to-verify).

### What a minute log actually contains
Written once per 60s at [daemon.rs:235-244](daemon/src/daemon.rs#L235):

| Field | Example | Sensitive? |
|-------|---------|-----------|
| `timestamp` | `1782489000` | no |
| `keystroke_count` | `342` | no — a count, not keys |
| `mouse_click_count` | `45` | no |
| `scroll_event_count` | `12` | no |
| `mouse_distance` | `10453.2` | no |
| `active_app_name` | `"Terminal"` | low |
| `active_window_title` | `"vim daemon.rs"` | **yes — plaintext window title** |
| `low_entropy` | `false` | no |

The one genuinely sensitive field is `active_window_title` (it can contain document names, email
subjects, URLs). It is captured via [daemon.rs:56-73](daemon/src/daemon.rs#L56) (`active-win-pos-rs`)
and stored **locally**. It only ever leaves the machine if you turn on BYOK LLM scoring (§2).

---

## 2. What leaves your machine (network egress inventory)

The daemon's dependencies that can make network calls are `reqwest` (LLM) and `axum`/`tower-http`
(the *inbound* localhost dashboard server). There is **no** module that syncs telemetry to a tenby10
cloud. The complete list of outbound calls:

1. **Your own LLM provider — opt-in, BYOK.** [llm.rs](daemon/src/llm.rs) posts directly to
   `api.openai.com` ([llm.rs:35](daemon/src/llm.rs#L35)), `api.anthropic.com`
   ([llm.rs:78](daemon/src/llm.rs#L78)), or `generativelanguage.googleapis.com`
   ([llm.rs:132](daemon/src/llm.rs#L132)) using *your* API key. This path is reached **only** when:
   - `engine_mode == "llm"` ([daemon.rs:432](daemon/src/daemon.rs#L432)), **and**
   - a provider **and** key are configured ([llm.rs:152-155](daemon/src/llm.rs#L152) returns `None`
     otherwise — default config ships empty, so the default is off).

   When active, the payload is the activity text (app names, **window titles**, key/click counts) —
   built at [daemon.rs:440-449](daemon/src/daemon.rs#L440). No screenshot bytes are included (§ Gap G1).

2. **Enrollment is localhost-only and mocked.** The desktop "enroll" command posts to
   `http://127.0.0.1:{port}/api/enroll` — the daemon's own Axum server, not a remote host — and key
   generation happens locally with `ed25519-dalek`
   ([desktop/src-tauri/src/lib.rs:74-93](desktop/src-tauri/src/lib.rs#L74)). No cloud enrollment
   endpoint is contacted.

3. **Dashboard webfont — self-hosted.** The dashboard font is embedded as a `data:` URI
   ([dashboard.rs](daemon/src/dashboard.rs)); opening the local dashboard makes **no** third-party
   requests.

The privacy-safe aggregated cloud payload described in the engineering spec (§5.3) is **not yet
implemented** in this repo — there is no code that uploads focus scores anywhere.

---

## 3. Screen capture privacy

One screenshot per 10-minute slot, blurred in memory, raw bytes dropped before anything is written.

- [screen.rs:20-45](daemon/src/screen.rs#L20) — captures via the macOS `screencapture` tool to
  stdout. If permission is denied, it generates a gray placeholder (never silently retries).
- [screen.rs:49-54](daemon/src/screen.rs#L49) — `imageops::blur(&raw_img, 20.0)` then
  **`drop(raw_img)`** to purge the raw buffer.
- [screen.rs:59-66](daemon/src/screen.rs#L59) — only the blurred image is saved, as JPEG, to
  `~/.tenby10/screenshots/slot_<ts>.jpg`.

The raw, unblurred image is never passed to `save`. Note: screen capture is currently
**macOS-only** (shells out to `screencapture`); there is no Windows/Linux capture path in
[screen.rs](daemon/src/screen.rs) yet.

---

## 4. Are the scoring rules fair?

All classification is isolated in one pure module so it can be read and unit-tested without the
capture loop ([decisions/0002](../decisions/0002-activity-evaluation-engine.md)). A minute is sorted
into exactly one state by a fixed priority order in
[evaluator.rs:53-113](daemon/src/evaluator.rs#L53):

1. **Anti-cheat first** — mouse jiggler or keyboard macro → `Tampered`
   ([evaluator.rs:54-60](daemon/src/evaluator.rs#L54)).
2. **Distraction** — active app/title matches your `distracting_apps` list → `Distracted`
   ([evaluator.rs:62-76](daemon/src/evaluator.rs#L62)).
3. **Active** — any keystroke, click, or scroll → `Active`
   ([evaluator.rs:78-83](daemon/src/evaluator.rs#L78)).
4. **Meeting** — no input but the active window is a genuine meeting → `Meeting`
   (`is_meeting_context` in [evaluator.rs](daemon/src/evaluator.rs)). Matching is hardened (#97): a
   **native meeting app** by application name, a **whole-word** title keyword (so "Meeting notes" is
   not a meeting), or a Google Meet **URL/code** in the title — not a loose substring. To stop a
   spoofed/idle "meeting" window from billing a slot on zero interaction, only up to
   `MEETING_NO_INPUT_STREAK_CAP` **consecutive**
   no-input meeting minutes count as active — the streak resets on any real input, so an interactive
   meeting is fully credited but a fully silent slot stays below the billable gate (see
   `aggregate_slot` in [daemon.rs](daemon/src/daemon.rs)). The bound also holds in LLM mode: demoted
   minutes are removed from the ceiling the LLM score may claim (`meeting_creditable_ceiling`).
5. **Passive review** — no input but a `productive_apps` app *and* you were recently active →
   `PassiveReview` ([evaluator.rs:97-109](daemon/src/evaluator.rs#L97)).
6. **Idle** otherwise.

The lists (`distracting_apps`, `productive_apps`, `meeting_apps`) are **user-configurable** and live
in your local `config.json` ([config.rs:30-54](daemon/src/config.rs#L30)); defaults at
[config.rs:8-18](daemon/src/config.rs#L8). Nothing is hard-coded against you.

**Anti-cheat heuristics are explicit and inspectable** in [entropy.rs](daemon/src/entropy.rs) — and
are honest **speed bumps**, not a wall: the code ships with the client, so a determined cheater can
tune around any fixed rule. They score the *structure* of input over a rolling multi-minute window
and bias toward never flagging a real person:
- Keyboard macro = inter-key timing too regular *for its own rate* (low coefficient of variation), so
  jittered and low-rate (~1/min) macros are caught, not just near-constant ones.
- Mouse jiggler = a long path confined to a tiny region (in-place jiggling), or robotically constant
  speed and direction. The velocity-CoV guard leaves genuine fast human swipes alone.
- The buffers are **not** cleared each minute (`clear_entropy_window` only fires on pause/lock), so
  low-rate automation becomes visible as samples accumulate. Adaptive detection that must stay hidden
  from a source-reading cheater is a server-side concern, not part of this client.

**Scoring is deterministic and forgiving of thinking time:**
- Fixed 10-minute denominator so you can't game a 100% off one active minute
  ([daemon.rs:424](daemon/src/daemon.rs#L424), [decisions/0006](../decisions/0006-focus-score-fixed-denominator.md)).
- 5-minute delayed "idle forgiveness" for reading/thinking pauses at slot boundaries
  ([daemon.rs:369-421](daemon/src/daemon.rs#L369), [decisions/0011](../decisions/0011-contextual-idle-forgiveness.md)).

**The rules are locked by tests** — read these to see the intended behavior as executable spec:
- [evaluator.rs:175-294](daemon/src/evaluator.rs#L175) — active / passive / idle / distraction / jiggler.
- [entropy.rs:136-181](daemon/src/entropy.rs#L136) — human vs macro keyboard, human vs jiggler mouse.
- [daemon.rs:546-811](daemon/src/daemon.rs#L546) — full-slot aggregation, partial-slot ADR-0006,
  idle-forgiveness approved/rejected.

Run them with `cd daemon && cargo test`.

---

## 5. Local storage & tamper-evidence

- Everything lives under `~/.tenby10/` (or `~/.tenby10_dev/` in debug); overridable via
  `TENBY10_HOME` — see [env.rs](daemon/src/env.rs).
- Slot summaries are hash-chained with SHA-256 over a **canonical payload covering every stored
  field** (score, segments, keystrokes, clicks, app categories, LLM reasoning, parent link) —
  `canonical_slot_payload` in [db.rs](daemon/src/db.rs). Hand-editing *any* field of the SQLite file
  breaks the chain; `verify_ledger_integrity` re-derives and compares it.
- Once you enroll, each slot is also **Ed25519-signed with your key** (private key in the OS
  keychain). This closes the obvious hole in a bare hash chain: an attacker who edits a row and then
  re-computes its hash to hide the edit still cannot produce a valid signature without your key, so
  verification fails. Slots written before enrollment are unsigned (hash-chain tamper-evidence only).
- **Honest scope.** This is *tamper-evidence and self-asserted authorship on a machine you control*,
  not encryption and not third-party proof: you hold the signing key, so anyone with your key (i.e.
  you) can still fabricate a self-consistent, self-signed ledger. Verifying a report *to a
  counterparty who does not trust you* is out of scope for this local client and not part of this
  repository. Locked by tests in [db.rs](daemon/src/db.rs): `test_signature_defeats_the_recompute_attack`,
  `test_signed_slot_roundtrip_and_wrong_key_rejected`, `test_unsigned_row_recompute_is_not_detected`.

---

## 6. Known gaps — where copy over-claims vs. the code

These are the things an honest auditor will find. None leak keystrokes or raw screens, but they are
real mismatches to close:

- **G1 — Screenshots are never actually sent to any LLM, even with the toggle on.** The
  `send_screenshots` flag ([config.rs:51](daemon/src/config.rs#L51), default `false`) is only
  interpolated into the LLM system prompt as text
  ([daemon.rs:462-476](daemon/src/daemon.rs#L462)); no image bytes are attached in
  [llm.rs](daemon/src/llm.rs). So the multimodal path from
  [decisions/0005](../decisions/0005-byok-screenshot-llm-transmission.md) is **not wired up**.
  *Privacy-positive today*, but the toggle is misleading — it implies a data flow that doesn't exist.

- **G2 — Secrets are handed to the settings UI over local IPC.** `private_key` and `llm_api_key`
  live in the OS keychain and `config.json` is written sanitized with those fields blanked
  ([config.rs](daemon/src/config.rs)), so nothing sensitive is at rest in plaintext. The one caveat
  an auditor should note: over the local Tauri IPC channel, `get_agent_config` still returns the
  in-memory config *including* those secrets so the settings form can render them — an in-process
  transfer to the app you launched, not at-rest plaintext on disk.

---

## How to verify

Run these from the `client/` directory. Each is designed to *fail loudly* if a claim is false.

```bash
# 1. No key content read: the ONLY KeyPress match must discard the value (`KeyPress(_)`).
#    Any match binding the key (e.g. `KeyPress(key)`) is a red flag to inspect.
grep -rn "KeyPress" daemon/src/

# 2. Full outbound-network inventory. Expect ONLY llm.rs (BYOK) — the dashboard font is now inlined.
grep -rniE "reqwest|\.post\(|\.get\(|https?://" daemon/src/

# 3. No tenby10 cloud sync endpoint anywhere in the client.
grep -rniE "sync|/api/v1|ingest|upload|telemetry.*(post|send)" daemon/src/

# 4. Raw screenshot is dropped, never saved: `drop(raw_img)` before any `.save`.
grep -n "drop(raw_img)\|save_with_format\|imageops::blur" daemon/src/screen.rs

# 5. The scoring rules and their tests are all in these two files.
sed -n '53,113p' daemon/src/evaluator.rs   # classification priority order
cargo test                                 # rules + entropy + aggregation locked by tests

# 6. Secrets are NOT in config.json (G2). After enrolling, the file must contain
#    neither the private key nor the LLM API key value — they live in the keychain.
grep -E '"(private_key|llm_api_key)"\s*:\s*"[^"]+"' ~/.tenby10/config.json && \
  echo "LEAK: plaintext secret found" || echo "OK: no plaintext secret in config.json"
#    On macOS you can confirm the keychain entries exist:
security find-generic-password -s tenby10 -a private_key >/dev/null 2>&1 && echo "keychain: private_key present"
```

If any of these produce results that contradict the tables above, treat this guide as **out of date**
and trust the code.

---

*Maintainers: keep this file honest. When you change what is captured, what leaves the machine, or a
scoring rule, update the relevant row here in the same PR.*
