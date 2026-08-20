# tenby10 Client — Auditor's Guide

**Audience:** any human or AI agent auditing the tenby10 desktop client before trusting it with
OS-level input and screen access.

**Claim under audit:** *"tenby10 is not a keylogger, does not capture anything sensitive, keeps your
raw activity on your machine, and scores your focus by fair, inspectable rules."* When you enroll and
share a link, signed 10-minute *summaries*, your scoring configuration and — once you connect your
own AI — a signed one-or-two-sentence *work note* per day are uploaded to tenby10. Raw keystrokes and
raw window titles are not, and no screen images exist to upload (§2, §3). That work note is prose
your own AI writes *from* your window titles, so it is the one place where title-*derived* text
travels to tenby10; read rows 4 and 9 before you rely on that boundary. The other egress is opt-in
BYOK inference: activity text (window titles included) sent directly to the LLM provider *you*
configure (row 5) — fully on-device with local Ollama.

This guide maps each of those claims to the exact source that proves (or, honestly, does **not** yet
prove) it. Every reference is `file:line` and is meant to be opened and read directly — do not take
this document's word for it. The `## How to verify` section at the bottom gives grep recipes so you
can re-derive every claim yourself.

This client is **source-available** under the PivotalPoint Source-Available License, Version 1.0
(PPSAL-1.0 — see [LICENSE](LICENSE)) — the full client that runs on your machine is readable and
auditable; the cloud portal is not part of this repository.

> **Found a vulnerability while auditing?** Please report it **privately** — see
> [SECURITY.md](SECURITY.md). Don't open a public issue for security problems.

---

## TL;DR verdict table

| # | Claim | Status | Primary evidence |
|---|-------|--------|------------------|
| 1 | No key **content** is captured (not a keylogger) | ✅ Verified in code | [daemon.rs:246](daemon/src/daemon.rs#L246) — `KeyPress(_)` discards the key value |
| 2 | Only counts/metadata are stored per minute | ✅ Verified | [daemon.rs:414](daemon/src/daemon.rs#L414), [db.rs schema](daemon/src/db.rs) |
| 3 | No screen capture exists at all | ✅ Verified | No capture code in the client (ADR 0018) — §3 has the grep and names the two lookalike symbols it deliberately excludes |
| 4 | Raw keystrokes never leave the machine; **raw** window titles never reach tenby10 | ⚠️ Verified, but narrowed on 2026-08-14 | Still true of raw titles: no upload payload has a title field ([sync.rs:85](daemon/src/sync.rs#L85), [sync.rs:168](daemon/src/sync.rs#L168), [sync.rs:185](daemon/src/sync.rs#L185)). What changed: a title-*derived* sentence now does reach tenby10, in the daily work note (§2) — row 9 is what constrains it. Raw titles still go only to your own BYOK provider (row 5) |
| 5 | Cloud sync (when enrolled) is count/category summaries + hashes + config + your daily work notes; your BYOK provider is the only other destination | ✅ Verified, scope corrected | Five endpoints, all inventoried in §2 — [sync.rs](daemon/src/sync.rs). BYOK calls live in [llm.rs](daemon/src/llm.rs), reached from slot scoring ([daemon.rs:794](daemon/src/daemon.rs#L794)) and from note writing ([daemon.rs:454](daemon/src/daemon.rs#L454)) |
| 6 | No image is sent to your LLM provider, ever | ✅ Verified structurally | The provider trait takes text only ([llm.rs](daemon/src/llm.rs)); nothing in the client can produce an image to send |
| 7 | Focus-scoring rules are deterministic and inspectable | ✅ Verified | [evaluator.rs](daemon/src/evaluator.rs), [entropy.rs](daemon/src/entropy.rs) |
| 8 | Local logs are tamper-evident (full-payload hash chain) + self-signed when enrolled | ✅ Verified | [db.rs `insert_slot_summary`/`verify_ledger_integrity`](daemon/src/db.rs) — work notes have their own chain, same construction (§5) |
| 9 | Your daily work note describes the task, not the window title | ⚠️ Prompt-enforced, not mechanism-enforced | The default prompt ([config.rs:51](daemon/src/config.rs#L51)) tells the model never to quote a window title, file path, URL, or third-party name. Nothing inspects the sentence afterwards: `sanitize_note` ([llm.rs:108](daemon/src/llm.rs#L108)) rejects empty or essay-length replies, not leaked content. The prompt's SHA-256 is bound into the signed record so a reader can check which rules applied — that is evidence of the rule, not proof the model obeyed it |
| — | Secrets stored in OS keychain | ✅ Verified | [config.rs `save_config`/`load_config`](daemon/src/config.rs) — `private_key` & `llm_api_key` kept in the OS keychain via the `keyring` crate |
| — | Local dashboard makes no third-party calls | ✅ Verified | [dashboard.rs](daemon/src/dashboard.rs) — Outfit font embedded as a data URI; no CDN `<link>` |
| — | The installed app opens **no listening port** | ✅ Verified | The dashboard renders in-app over Tauri IPC. The loopback HTTP server is a debug-only escape hatch for the standalone `daemon` binary, off unless `TENBY10_DEBUG_HTTP` is set — [env.rs `debug_http_enabled`](daemon/src/env.rs) |

Bottom line: the core privacy claims — **no keylogging; no screen capture; raw keystrokes never leave
the machine; raw window titles never reach tenby10 or anyone you share a link with** — hold up
against the code. When you enroll and sync, signed 10-minute *summaries* and your scoring
configuration are uploaded to the cloud (§2); raw activity is not. Connect your own AI and one more
thing is uploaded: a one-or-two-sentence *work note* per finished day, written on your machine from
your own window titles and held for 12 hours so you can revise or withdraw it first. So the honest
boundary is "raw titles stay here", not "nothing derived from a title ever travels" — rows 4 and 9
say how far it goes. Opt-in BYOK inference sends activity text (window titles included) directly to
the provider *you* configure — fully on-device with local Ollama.

The gap previously logged here as **G1** (a `send_screenshots` toggle that never sent anything) is
closed: rather than wire it up, the screenshot subsystem was removed outright
([ADR 0018](../decisions/0018-remove-screenshot-subsystem.md)). The toggle is gone, and so is every
line of capture code.

---

## 1. Is it a keylogger? (What is captured from the keyboard)

**No key content is ever read.** The global input listener uses `rdev` and matches key events as
`KeyPress(_)` — the underscore **discards** the actual key/character. All it does is `+1` a counter
and record the *timing gap* between presses (for bot detection), never *what* was typed.

- [daemon.rs:246-255](daemon/src/daemon.rs#L246) — `KeyPress(_)` → increment `keystroke_count`, push
  the inter-key interval in ms. The keycode is pattern-matched away.
- [daemon.rs:257-262](daemon/src/daemon.rs#L257) — mouse buttons and scroll are counted the same way
  (counts only).
- [daemon.rs:263-276](daemon/src/daemon.rs#L263) — mouse *movement* stores `(x, y, timestamp)` for
  entropy analysis. This is cursor coordinates, not content.
- A **second, listen-only** tap in [provenance.rs](daemon/src/provenance.rs) (issue #87) — on macOS a
  `CGEventTap` reading only `kCGEventSourceStateID`, on Windows low-level hooks reading only the
  injected-event flag — classifies each event as real-hardware vs. software-injected and counts them.
  It never reads the key value either, and passes every event through unchanged.

An auditor should confirm there is **no** branch anywhere that reads the key value. Grep recipe in
[How to verify](#how-to-verify).

### What a minute log actually contains
Written once per 60s at [daemon.rs:414-423](daemon/src/daemon.rs#L414):

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
subjects, URLs). It is captured via [daemon.rs:197-215](daemon/src/daemon.rs#L197)
(`active-win-pos-rs`) and stored **locally**. The title itself only leaves the machine if you connect
your own AI, and then it goes to *your* provider — for slot scoring, and for writing the daily work
note (§2). It is **never** a field in anything uploaded to tenby10. What tenby10 does receive is the
work note: a sentence written *from* titles, which is a weaker boundary than "no title ever travels"
and is stated as such in rows 4 and 9.

---

## 2. What leaves your machine (network egress inventory)

Nothing leaves the machine until you **enroll** and sync. The complete list of outbound calls:

1. **tenby10 cloud sync — only when enrolled.** Once you pair a device,
   [sync.rs](daemon/src/sync.rs) uploads to the tenby10 cloud (`cloud_base_url()`,
   [sync.rs:16](daemon/src/sync.rs#L16), default `https://tenby10.pivotalpoint.io`). This is reached
   only when `config.agent_id` is set ([daemon.rs:923](daemon/src/daemon.rs#L923)). **Five** requests
   exist, and nothing else:
   - **Enrollment** (`enroll_with_cloud`, [sync.rs:22](daemon/src/sync.rs#L22), `POST /api/v1/enroll`):
     your pairing token and **public** key. The private key is generated locally and never leaves the
     keychain.
   - **Signed slot summaries** (`slot_payload`, [sync.rs:85](daemon/src/sync.rs#L85),
     `POST /api/v1/slots`): per 10-minute slot — a focus score, active/idle segment counts,
     keystroke/click **counts**, app-category **counts**, a SHA-256 **hash** of the LLM reasoning
     (not the text), the effective-config hash, and the hash-chain link + Ed25519 signature.
   - **Signed daily work notes** (`summary_payload`, [sync.rs:168](daemon/src/sync.rs#L168),
     `POST /api/v1/summaries`, [ADR 0019](../decisions/0019-worker-controlled-summary-sharing.md),
     shipped 2026-08-14): one or two sentences per finished local day, **as text**. This is the only
     upload that carries prose rather than counts and hashes.
     Fields: `agent_id`, `scheme_version`, `period_start`, `period_end`, `generated_at`,
     `revision`, `summary_text` (the note itself), `prompt_hash` (SHA-256 of the prompt that wrote
     it), `ledger` (`hash` + `parent_hash`), `signature`. The note is written on your machine by
     *your* AI from your own window titles (item 2 below), so this is where title-*derived* text
     reaches tenby10 — see rows 4 and 9, and §5 for what the signature covers.
   - **Withdrawals** (`withdrawal_payload`, [sync.rs:185](daemon/src/sync.rs#L185),
     `POST /api/v1/summaries/withdraw`): `agent_id`, `scheme_version`, `period_start`,
     `withdrawn_at`, `ledger` (`hash` + `parent_hash`), `signature`. Deliberately short — it names
     *which* day is being taken back and *when*, and never restates the text, so a withdrawal cannot
     smuggle a second version of a note into the record.
   - **Blobs a record names** (`upload_config`, [sync.rs:57](daemon/src/sync.rs#L57),
     `POST /api/v1/config`): `agent_id`, `config_hash`, `config_blob`. Two kinds of blob share this
     endpoint, which is a plain SHA-256-keyed store: the effective config a slot was scored under
     (your app lists, engine mode, synthetic-detection flag and the AI auditor prompt, #62/#80), and
     the prompt a work note was written with (#147). A blob is sent **only after** the cloud rejects
     the record that names it with HTTP 428 ([sync.rs:49](daemon/src/sync.rs#L49)) — no speculative
     pre-upload — so a relying party can always resolve the rules behind a score or a sentence.

   **Timing, and how a note can be stopped.** A note does not go up when it is written. It waits out
   a 12-hour correction window (`SUMMARY_CORRECTION_WINDOW_SECS`,
   [sync.rs:166](daemon/src/sync.rs#L166)) on your machine, visible in your own dashboard first:
   `get_unsynced_summaries` ([db.rs:1355](daemon/src/db.rs#L1355)) will not return a note until
   `generated_at` is older than that. **Withdraw it before the window closes and it never travels at
   all** — the same query drops withdrawn notes. Withdrawal *records* are exempt from the wait and
   upload immediately, because taking something back is useless if it queues. Unsigned rows are never
   uploaded either, so nothing syncs before you enroll.

   **Never sent:** raw keystrokes, and raw window titles — no payload above has a title field. The
   one thing that can carry information *derived* from a title is the work note's `summary_text`, and
   what keeps a title out of that sentence is the prompt, not a filter (row 9).

2. **Your own LLM provider — opt-in, BYOK.** [llm.rs](daemon/src/llm.rs) posts directly to the
   provider *you* configure with *your* API key — this goes to your provider, not to tenby10. The
   defaults are `api.openai.com` ([llm.rs:15](daemon/src/llm.rs#L15)), `api.anthropic.com`
   ([llm.rs:17](daemon/src/llm.rs#L17)) and `generativelanguage.googleapis.com`
   ([llm.rs:19](daemon/src/llm.rs#L19)); `llm_base_url` overrides any of them, so you can point the
   client at an OpenAI-compatible gateway or at a local Ollama and keep inference on-device.
   `validate_base_url` ([llm.rs:66](daemon/src/llm.rs#L66)) refuses plain `http` for anything that is
   not loopback. Nothing is reachable unless a provider is configured: `get_llm_provider`
   ([llm.rs:398](daemon/src/llm.rs#L398)) returns `None` on an empty provider, an invalid base URL,
   or a missing key for a remote endpoint — and the default config ships empty, so the default is
   off.

   Two different calls reach it, on two different conditions:
   - **Slot scoring** — only when `engine_mode == "llm"`
     ([daemon.rs:794](daemon/src/daemon.rs#L794)). Payload: one line per minute of the slot with the
     app name, the **window title**, and key/click counts.
   - **Daily work note** — whenever a provider is configured and you have not opted out
     (`disable_work_summaries`, [daemon.rs:454-470](daemon/src/daemon.rs#L454)). Note this is **not**
     gated on `engine_mode`: connecting an AI is enough, by design (ADR 0019 — "setup once, then
     invisible"). Payload: the day's activity digest (`activity_digest`,
     [db.rs:1308](daemon/src/db.rs#L1308)) — up to 60 `"12m — App: Window title"` lines, drawn only
     from slots that cleared the focus bar and only from minutes with real input, so an unbilled
     personal browse never reaches the model.

   Text only in both cases; no image exists to send (§3).

3. **Dashboard webfont — self-hosted.** The dashboard font is embedded as a `data:` URI
   ([dashboard.rs](daemon/src/dashboard.rs)); opening the local dashboard makes **no** third-party
   requests.

What the cloud receives is category- and count-level summaries, hashes, your config, and — once you
connect an AI — one or two sentences per day describing the work. It never receives the raw
keystrokes, screens, or window titles behind any of it.

---

## 3. Screen capture: there isn't any

tenby10 does not read the pixels on your screen. This is not a setting — there is no capture code in
the client, so there is nothing to enable, misconfigure, or push down from a managed profile.

Verify it yourself; all three return nothing:

```bash
# Capture APIs, case-sensitively. Two symbols look like capture and are not, so a looser
# pattern reports hits and reads like a caught lie — run the second grep and read all five
# lines it returns rather than taking this on trust:
#   CGDisplayIsAsleep            (sys_state.rs)  asks whether the screen is powered off, so the
#                                                daemon can skip that minute. Reads no pixels.
#   CGPreflightScreenCaptureAccess, Privacy_ScreenCapture  (platform/macos.rs)  ask whether the
#                                                Screen Recording permission was granted, and
#                                                open the pane where you grant it. macOS
#                                                withholds *window titles* without it (§1).
grep -rnE "CGDisplayCreateImage|CGWindowListCreateImage|CGDisplayStream|BitBlt|GetDIBits|screencapture|imageops" daemon/src/ desktop/src-tauri/src/
grep -rniE "CGDisplay|ScreenCapture" daemon/src/ desktop/src-tauri/src/   # the five benign lines
grep -rn "image" daemon/Cargo.toml         # no imaging crate is even a dependency
ls ~/.tenby10/screenshots 2>/dev/null      # removed on upgrade; never recreated
```

Earlier versions (≤ v0.2.x) captured one heavily-blurred JPEG per 10-minute slot and kept it locally,
never uploading it. That subsystem was deleted rather than left switchable — see
[ADR 0018](../decisions/0018-remove-screenshot-subsystem.md) — and the first run of a current build
deletes the old `~/.tenby10/screenshots/` folder
([env.rs `purge_legacy_screenshots`](daemon/src/env.rs)).

**Why macOS still asks for Screen Recording.** The app reads *window titles*, and macOS withholds
`kCGWindowName` from any process without that grant — titles come back empty. So the permission is
held for text metadata, not pixels. The settings page reports whether titles are actually readable
(`window_titles_ok`), which is ground truth rather than a cached TCC preflight.

---

## 4. Are the scoring rules fair?

All classification is isolated in one pure module so it can be read and unit-tested without the
capture loop ([decisions/0002](../decisions/0002-activity-evaluation-engine.md)). A minute is sorted
into exactly one state by a fixed priority order in
[evaluator.rs:114-167](daemon/src/evaluator.rs#L114):

1. **Anti-cheat first** — mouse jiggler or keyboard macro → `Tampered`
   ([evaluator.rs:115-121](daemon/src/evaluator.rs#L115)).
2. **Distraction** — active app/title matches your `distracting_apps` list → `Distracted`
   ([evaluator.rs:123-137](daemon/src/evaluator.rs#L123)).
3. **Active** — any keystroke, click, or scroll → `Active`
   ([evaluator.rs:139-144](daemon/src/evaluator.rs#L139)).
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
   `PassiveReview` ([evaluator.rs:151-163](daemon/src/evaluator.rs#L151)).
6. **Idle** otherwise.

The lists (`distracting_apps`, `productive_apps`, `meeting_apps`) are **user-configurable** and live
in your local `config.json` ([config.rs:74-100](daemon/src/config.rs#L74)); defaults at
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
  ([daemon.rs:785-786](daemon/src/daemon.rs#L785), [decisions/0006](../decisions/0006-focus-score-fixed-denominator.md)).
- 5-minute delayed "idle forgiveness" for reading/thinking pauses at slot boundaries
  ([daemon.rs:727-783](daemon/src/daemon.rs#L727), [decisions/0011](../decisions/0011-contextual-idle-forgiveness.md)).

**The rules are locked by tests** — read these to see the intended behavior as executable spec:
- [evaluator.rs:223-459](daemon/src/evaluator.rs#L223) — active / passive / idle / distraction / jiggler.
- [entropy.rs:204-418](daemon/src/entropy.rs#L204) — human vs macro keyboard, human vs jiggler mouse.
- [daemon.rs:946-1677](daemon/src/daemon.rs#L946) — full-slot aggregation, partial-slot ADR-0006,
  idle-forgiveness approved/rejected, and the v2 config-hash binding.

Run them with `cd daemon && cargo test`.

---

## 5. Local storage & tamper-evidence

- Everything lives under `~/.tenby10/` (or `~/.tenby10_dev/` in debug); overridable via
  `TENBY10_HOME` — see [env.rs](daemon/src/env.rs).
- Slot summaries are hash-chained with SHA-256 over a **canonical payload covering every stored
  field** (score, segments, keystrokes, clicks, app categories, LLM reasoning hash, **effective-config
  hash**, parent link) — `canonical_slot_payload` in [db.rs](daemon/src/db.rs). Hand-editing *any* field
  of the SQLite file breaks the chain; `verify_ledger_integrity` re-derives and compares it.
- **The scoring rubric is bound in (v2, #62).** The payload includes a SHA-256 of the effective config
  (your auditing rules + AI auditor prompt), so a score can't be silently divorced from the rules that
  produced it. The exact config blob is uploaded on demand — the cloud refuses a slot naming a config
  it does not hold, and sync backfills it then (§2) — so a relying party can always inspect it. Locked by
  `test_v2_payload_binds_config_hash` and the cross-language vector `test_v2_canonical_vector_matches_cloud`.
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

### The work-note ledger

Daily work notes (§2) are the one record type whose *text* leaves the machine, so they get the same
construction as slots — hash-chained and, once enrolled, Ed25519-signed — on a **separate** chain, so
a stalled note never blocks an hour from syncing or the reverse (`work_summaries` table,
[db.rs:503](daemon/src/db.rs#L503); locked by `test_summary_chain_is_independent_of_slots`).

- **The text is inside the signature.** `canonical_summary_payload`
  ([db.rs:288](daemon/src/db.rs#L288)) folds `summary_text` to a SHA-256 and signs that, so the
  signature covers the exact words without the signable string growing with the note. Edit the text
  in SQLite and the row stops verifying (`test_edited_summary_text_is_detected`); recompute the hash
  to hide the edit and the signature still fails
  (`test_signature_defeats_summary_recompute_attack`). What lands in the cloud is therefore provably
  the text that was signed.
- **Lateness is visible.** `generated_at` is inside the signed payload, so what is being signed is
  "this text described this period, and it was written at this moment". A note backdated to look
  contemporaneous cannot be re-signed without your key.
- **The prompt is bound in (v2).** The payload also carries the SHA-256 of the prompt that produced
  the note (`SUMMARY_SCHEME_VERSION`, [db.rs:64](daemon/src/db.rs#L64)), and the cloud will not
  accept a note until it holds that prompt (#147), so a reader can always see the rules behind the
  words. That is what makes the limit in row 9 checkable rather than merely asserted — it evidences
  the instruction, not the model's obedience to it.
- **Corrections append, never edit.** A revision is a new row with a higher `revision` for the same
  period (`revise_work_summary`, [db.rs:1048](daemon/src/db.rs#L1048)); the earlier revision stays in
  the ledger and stays signed. Readers take the highest revision.
- **Withdrawal is its own signed record, not a mutable flag.** `withdraw_work_summary`
  ([db.rs:1160](daemon/src/db.rs#L1160)) appends a separate `kind = 'withdrawal'` row with its own
  canonical form ([db.rs:337](daemon/src/db.rs#L337)) — period and moment only, never the text. The
  local `withdrawn` column is deliberately **outside** the signed payload: withdrawing is a decision
  about sharing from now on, not an assertion about the past, and the past is what a signature
  covers. A flag on its own would be an instruction anyone could send about anyone's note; the
  signature is what lets the cloud act on it. Locked by
  `test_withdrawal_is_a_signed_record_on_the_same_chain` and `test_forged_withdrawal_fails_verification`.
- `verify_summary_chain` ([db.rs:1419](daemon/src/db.rs#L1419)) walks the chain the way an auditor
  would — every link, every hash, every signature — re-deriving each row under its own kind, so a
  withdrawal that tried to pass as a note (or the reverse) fails there.
- **Honest scope, same as above, plus one more limit.** This is still a ledger you sign with your own
  key: it evidences integrity and authorship, not that the sentence is true. And withdrawal is a
  signed *request* travelling upstream — the client can stop sending a note, and can tell the cloud
  to stop showing one, but nothing in this repository can make a copy that has already left forget
  it. Withdrawing inside the 12-hour window is the only case where the note demonstrably never
  travelled (§2).

---

## 6. Known gaps — where copy over-claims vs. the code

These are the things an honest auditor will find. None leak keystrokes or raw screens, but they are
real mismatches to close:

- **G1 — CLOSED (removed, not fixed).** A `send_screenshots` toggle used to imply a multimodal
  data flow that was never wired up. Instead of implementing it, the whole screenshot subsystem was
  deleted ([ADR 0018](../decisions/0018-remove-screenshot-subsystem.md)): no toggle, no capture code,
  no image path to any provider. See §3.

- **G2 — Secrets are handed to the settings UI over local IPC.** `private_key` and `llm_api_key`
  live in the OS keychain and `config.json` is written sanitized with those fields blanked
  ([config.rs](daemon/src/config.rs)), so nothing sensitive is at rest in plaintext. The one caveat
  an auditor should note: over the local Tauri IPC channel, `get_agent_config` still returns the
  in-memory config *including* those secrets so the settings form can render them — an in-process
  transfer to the app you launched, not at-rest plaintext on disk.

- **G3 — NARROWED (#83).** A work note (§2) is written from window titles by your own AI, and this
  used to rest entirely on `default_summary_prompt` asking the model not to quote one
  ([config.rs:51](daemon/src/config.rs#L51)) — a model behaviour, not a mechanism. Two mechanisms now
  sit under it. Captured text is wrapped in explicit untrusted-data markers before it reaches either
  prompt, and the daemon refuses to sign a note that reproduces a run of any window title from the
  period ([untrusted.rs](daemon/src/untrusted.rs)); a refused note is simply left unwritten, the same
  honest failure as the AI being unreachable. `sanitize_note` ([llm.rs](daemon/src/llm.rs)) also now
  rejects a reply carrying those markers back.

  What remains a gap: the echo check catches a verbatim run, not a paraphrase, so a model that
  *describes* a client's name rather than quoting a title can still put it in the note. The markers
  are a strong instruction to a model, not a guarantee — this client is source-available, so the
  marker text is public. Two things still bound the rest: the prompt's hash is bound into the signed
  record so a reader can see which rules were in force (§5), and the 12-hour correction window means
  you see the note in your own dashboard before anyone else can (§2). Count it as narrowed, not
  closed.

---

## How to verify

Run these from the `client/` directory. Each is designed to *fail loudly* if a claim is false.

```bash
# 1. No key content read: the ONLY KeyPress match must discard the value (`KeyPress(_)`).
#    Any match binding the key (e.g. `KeyPress(key)`) is a red flag to inspect.
grep -rn "KeyPress" daemon/src/

# 2. Full outbound-network inventory. Expect llm.rs (your BYOK provider) and sync.rs (tenby10 cloud
#    sync, only when enrolled). The dashboard font is inlined, so the dashboard makes no requests.
grep -rniE "reqwest|\.post\(|\.get\(|https?://" daemon/src/

# 3. Every tenby10 endpoint the client can reach. §2 inventories exactly five; this must print those
#    five and nothing more. A path listed here that §2 does not name means the egress inventory is
#    incomplete — trust this output, not §2, and please open an issue.
grep -rhoE "/api/v1/[a-z/]+" daemon/src/ | sort -u
#    expect exactly: /api/v1/config  /api/v1/enroll  /api/v1/slots  /api/v1/summaries
#                    /api/v1/summaries/withdraw

# 4. What the cloud sync actually sends: inspect the upload payloads. Expect five `json!` blocks —
#    enrollment, blob, slot, work note, withdrawal — carrying counts, category counts, hashes
#    (reasoning_hash, config_hash, prompt_hash), the config/prompt blob, signatures, and the work
#    note's own text. Nothing else.
grep -n "json!" daemon/src/sync.rs

# 5. The work note's text is the ONLY free-form string in any upload, and the only place where
#    anything derived from a window title travels to tenby10 (rows 4 and 9). Expect three lines:
#    `"summary_text": note.summary_text`; `llm_reasoning` wrapped in `sha256_hex_pub(...)`, never
#    bare; and the doc comment above it. Zero hits for active_window_title. Anything else is a leak.
grep -nE "summary_text|active_window_title|llm_reasoning" daemon/src/sync.rs

# 6. No screen-capture code exists anywhere in the client (ADR 0018) — expect zero hits.
#    Case-sensitive, and matching capture APIs only. A looser pattern also catches the display
#    sleep check and the Screen Recording *permission* preflight, neither of which reads a
#    pixel — §3 names all five lines and explains why they are there.
grep -rnE "CGDisplayCreateImage|CGWindowListCreateImage|CGDisplayStream|BitBlt|GetDIBits|screencapture|imageops" daemon/src/ desktop/src-tauri/src/

# 7. The scoring rules and their tests are all in these two files.
sed -n '114,167p' daemon/src/evaluator.rs  # classification priority order
cargo test                                 # rules + entropy + aggregation locked by tests

# 8. Secrets are NOT in config.json (G2). After enrolling, the file must contain
#    neither the private key nor the LLM API key value — they live in the keychain.
grep -E '"(private_key|llm_api_key)"\s*:\s*"[^"]+"' ~/.tenby10/config.json && \
  echo "LEAK: plaintext secret found" || echo "OK: no plaintext secret in config.json"
#    On macOS you can confirm the keychain entries exist:
security find-generic-password -s tenby10 -a private_key >/dev/null 2>&1 && echo "keychain: private_key present"
```

If any of these produce results that contradict the tables above, treat this guide as **out of date**
and trust the code.

### Verifying a downloaded build came from this repo

Every release artifact carries a [build provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations)
(Sigstore/SLSA), generated by the release workflow. It proves a given `.dmg`, `.msi`, or `.exe` was
built by *this* repository's workflow from a specific commit — so a file someone hands you, or a
mirror you did not download from, can be checked rather than trusted.

```bash
# Verify a downloaded artifact (needs the GitHub CLI, `gh auth login` once).
gh attestation verify tenby10_0.2.3_aarch64.dmg --repo pivotalpoint-io/tenby10
```

A pass prints the source commit and the workflow that produced the file; a tampered or
foreign-built file fails loudly.

**What this does and does not prove.** Provenance attests the artifact's **origin** — which repo,
which commit, which workflow built it. It says **nothing about the runtime behaviour** of the
resulting process: a faithfully-built artifact from an honest commit is still only as trustworthy
as the source you can read above. It is a supply-chain control, not a behavioural guarantee. See
§6 for the gaps that provenance does not close.

> Windows builds are **not yet code-signed** (SmartScreen will warn on first run). Until signing
> lands, provenance verification is the way to confirm a Windows download is genuine.

---

*Maintainers: keep this file honest. When you change what is captured, what leaves the machine, or a
scoring rule, update the relevant row here in the same PR. Adding an endpoint without touching §2 is
how this guide last went stale (#84) — command 3 in "How to verify" now catches that.*

*Last checked line-by-line against the code on 2026-08-19.*
