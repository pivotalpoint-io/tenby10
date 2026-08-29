# Architectural Decision Record (ADR): Choice of a Separated Activity Evaluation Engine

*Public edition of this record from the project's decision log: file references are
repository-relative here, and issue numbers from the project's internal tracker are written out
in prose. Decision records that are not part of this published set are named in prose rather than
linked. The decisions and their rationale are complete.*

## Status
Accepted

## Context
tenby10 requires classifying 1-minute telemetry segments into Focus states (Active, PassiveReview, Idle, or Tampered) based on user input activity, statistical entropy checks, and active application context. 

We need an architecture that keeps the main background daemon thread thin and guarantees that the activity classification rules remain clean, maintainable, and easily extendable as we refine our anti-cheat heuristics and whitelisting.

## Decision
We will decouple all active focus classification heuristics from the main loop and encapsulate them inside a dedicated module: `evaluator` ([evaluator.rs](../../daemon/src/evaluator.rs)), exposing an `ActivityEvaluator` struct.

## Justification

### 1. Separation of Concerns
- The background daemon ([daemon.rs](../../daemon/src/daemon.rs)) is solely responsible for OS event gathering, timer management, database writes, and screenshot triggers *(the screenshot subsystem has since been removed — [ADR 0018](0018-remove-screenshot-subsystem.md))*.
- The `ActivityEvaluator` is a pure function-like engine: it takes the collected inputs (keystroke counts, click counts, scroll event counts, mouse trajectory coordinates, timing intervals, active app name, and recent activity history) and outputs a typed classification enum `ActivityClassification`.

### 2. Extensibility
By isolating the heuristics, we can easily implement future enhancements without risk of breaking core threading loops:
- Custom user-configured whitelists for passive review.
- Advanced machine learning classification algorithms.
- Dynamically tweaked threshold parameters for idle times.

### 3. Support for Passive Focus (Yellow Slots)
- The evaluator checks if a segment with zero inputs was preceded by active focus (which now incorporates scroll events to catch pure-reading behavior). If the app belongs to the dynamically configurable productivity whitelist, it correctly maps the segment to a `PassiveReview` (Yellow) focus state instead of forcing it to `Idle` (Red).

### 4. Support for Meeting State (Blue Slots)
- The evaluator natively supports a `Meeting` state, matching active windows against a `meeting_apps` list. This guarantees 100% focus for scheduled syncs without punishing users for zero inputs.

## Alternatives Considered
- **Inline Heuristics**: Embedding classification checks inside the main daemon loop. This was rejected because it quickly bloats `daemon.rs`, makes unit testing of the heuristics difficult, and makes iteration on classification models high-risk.

---

## Addendum (2026-07-11): Active credit = genuine engagement, not input volume

Reviewing the scoring trio against the 10by10 model
([ADR 0006](0006-focus-score-fixed-denominator.md), ADR 0012 — the billable-slot focus gate), we
affirm the principle that a minute earns active credit for **genuine engagement**, and we draw a
hard line between two lanes:

- **Scoring stays generous and humane.** We deliberately do **not** add a per-minute input-intensity
  floor. A macro tapping once a minute and a developer reading a spec are indistinguishable *by input
  volume*; any floor high enough to stop the macro also punishes honest reading/thinking/meeting —
  rebuilding the surveillance tracker that ADR 0012 walked away from. The
  discriminator is **authenticity**, not volume.
- **Authenticity is enforced in the anti-cheat lane, not the scoring lane.** The "single input =
  active minute" concern is therefore routed to the anti-cheat work (macro/jiggler
  robustness, synthetic-input detection) — detect the fake/periodic input; do not nerf honest
  low-input minutes.

Two concrete rule changes land in `aggregate_slot`:

1. **Meeting no-input cap.** `Meeting` credit is bounded: at most `MEETING_NO_INPUT_STREAK_CAP`
   (= 3) **consecutive** no-input meeting minutes count as active; the streak resets on any real
   input. A spoofed or idle "meeting" window therefore cannot bill a slot (3 < the ADR-0012 gate of
   4 minutes), while a genuinely interactive meeting stays fully credited. This **narrows §4 above**:
   we no longer grant unconditional 100% for zero-input meeting windows. Matching is intentionally
   left on `app`+`title` (not app/bundle-id only) so browser-hosted meetings — Google Meet, Teams-web,
   whose only signal is the tab title — keep working; the cap, not the match, closes the spoof.
   The cap holds in **LLM mode** too: minutes demoted for exceeding it are removed from the ceiling
   the LLM score may claim (`meeting_creditable_ceiling`), so turning on BYOK/LLM scoring cannot
   re-inflate a silent meeting — while the LLM keeps full latitude to credit genuine passive work in
   *non*-meeting apps. (Without this, the static-only cap would silently evaporate the moment a user
   enabled LLM mode.)
2. **Idle forgiveness requires genuine resumption.** Contextual idle forgiveness
   ([ADR 0011](0011-contextual-idle-forgiveness.md)) only triggers when work resumes with a **non-flagged**
   (non-`low_entropy`) minute, so an automated tap after a pause cannot unlock forgiveness.

**Known limitation (accepted).** A genuinely silent, zero-interaction meeting (pure listening, no
input for a whole slot) now under-credits. Closing that without reopening the spoof requires a
corroborating signal (mic/camera active, or in-call state); tracked as a follow-up. We chose this
over requiring corroboration now, which needs new capture plumbing and permissions.

---

## Addendum (2026-07-11): Anti-automation doctrine

**Doctrine.** Client-side anti-automation is a **speed bump, not a wall** — the same ceiling as the
signing work (ADR 0014, the signing and trust model). Because the client is source-available, every
threshold we ship is a spec a motivated cheater reads and tunes around. So the client carries only
**simple, deterministic heuristics + categorical signals**; the durable, *adaptive* detection
(behavioral/statistical analysis over time) lives **server-side**, where the logic is never shipped
to the attacker. The client's heuristics exist to stop lazy / off-the-shelf automation and to feed
those higher layers — not to defeat a determined adversary who owns the machine.

Concretely, `entropy.rs` was reworked ([entropy.rs](../../daemon/src/entropy.rs)):

1. **Score structure, not magnitude.** Keyboard detection now flags low **coefficient of
   variation** (regularity relative to the input's own rate) instead of an absolute stddev threshold,
   so jittered macros no longer slip through. Mouse detection adds a **spatial-confinement** signal (a
   long path inside a tiny bounding box) that catches circular / random-in-place jigglers the old
   "must be near-straight" rule treated as human, and swaps absolute velocity thresholds for velocity
   CoV so genuine fast human swipes are not flagged.
2. **Rolling multi-minute window.** The interval/position buffers are no longer cleared every
   minute ([daemon.rs](../../daemon/src/daemon.rs) — `reset_minute`
   vs `clear_entropy_window`); they keep the most recent N samples across minutes. A low-rate macro
   (e.g. one key/min) is invisible in a single minute but becomes visible once the window accumulates
   enough samples. This is why **the concern is resolved here rather than with a per-minute intensity
   floor**, which would have punished honest low-input work.
3. **Bias to false negatives.** Thresholds are set to avoid flagging real people (CoV `< 0.15`); we
   would rather miss a clever macro than brand a genuine user a cheater.

**Categorical signal — implemented, observe-only.** The rdev tap cannot tell a hardware event
from a `CGEventPost`ed one, so a second **listen-only macOS `CGEventTap`**
([provenance.rs](../../daemon/src/provenance.rs)) reads
`kCGEventSourceStateID` per event and counts synthetic vs genuine input — a categorical signal with no
threshold to tune. It ships **observe-only**: it logs/surfaces injected input but does **not** mark a
minute tampered unless `enforce_synthetic_detection` is set (default off), because (a) the tap can't be
runtime-verified in CI and a bad field read would falsely flag real typists, and (b) legitimate tools
(text expanders, password-manager auto-type) also post synthetic events. The enforcement rule, when
enabled, only fires on the pure-automation signature — a minute with input but **zero** genuine
hardware events — so a real person touching their keyboard is never flagged. On-device red-team
calibration before enabling is tracked by the fixture-corpus gate (addendum below). Honest limits: a
hardware HID emulator (Teensy/QMK) posts genuine HID events, and a sophisticated injector can spoof
the source state — both evade, and are a server-side / human-review concern.

**Honesty.** The README's anti-cheat copy is updated to describe these as speed bumps, not a settled
guarantee — matching the framing [AUDIT.md](../../AUDIT.md) already uses.

---

## Addendum (2026-07-11): Harden meeting matching

Meeting detection matched a `meeting_apps` keyword as a loose **substring** of the app name *or* title,
so "Meeting notes" hit `meet`, "myzoomrecording.mp4" hit `zoom`, and any window renamed to contain
"zoom" read as a meeting. Every false meeting classification is surface area the no-input cap above
must absorb. Detection is now `is_meeting_context` in
[evaluator.rs](../../daemon/src/evaluator.rs):

- **Native client** — loose substring match against the *application name* (OS-reported, hard to spoof)
  keeps Zoom/Teams/Webex working.
- **Title keyword** — must be a **whole word** (so `meet` no longer matches "meeting", `zoom` no longer
  matches "zoomed"); punctuated/multi-token config entries (e.g. `slack | huddle`) keep substring
  matching.
- **Browser meeting URL/code** — a Google Meet `xxx-xxxx-xxx` code or `meet.google.com` in the title is
  a positive signal, since a browser-hosted Meet's only signal is its tab title. (We capture the window
  *title*, not the address-bar URL.)

**This hardens matching, not liveness.** It raises the spoofing bar but does **not** close the
silent-meeting limitation above: the title/code is attacker-controlled (paste a real Meet link, mute,
walk away → identical signal), so crediting a genuinely *silent* meeting still needs a liveness
signal (mic/camera/in-call state). That follow-up remains open, re-scoped to record exactly this.

---

## Addendum (2026-07-12): Fixture corpus & red-team

The entropy unit tests are **circular** — the detector and its samples were authored together, so they
prove the functions do what we designed, not that they catch what *real* tools emit. To break that:

- **Fixture corpus** — a `fixtures` module
  defines a labelled `Trace` (keyboard intervals / mouse positions, `source: captured|synthetic`); the
  `anti_cheat_corpus` integration test runs the real detector over every trace and asserts the verdict
  matches the label. It **reports `captured / synthetic` counts and warns at 0 captured**, so a green
  run is never mistaken for "verified against real tools" while the corpus is synthetic-only.
- **Capture tool** — `daemon --capture-trace` records a real, labelled trace on a real machine (run a
  jiggler/macro, or act naturally), producing a `captured` fixture.
- **Red-team protocol** — a written protocol covers capturing fixtures and the end-to-end run
  (drive a real cheat at a live daemon, confirm the slot doesn't bill).

**This is the calibration gate for enforcement.** `enforce_synthetic_detection` and any tightening
of the entropy thresholds stay off/unchanged until captured human traces show no false positives and a
red-team run confirms detection. The machinery ships here; the corpus starts synthetic-only and is
filled from real captures on real hardware (the payoff can't be produced in CI).

*Public-edition note: the fixture tooling described in this addendum is not part of the current
tree — the entropy detectors and their unit tests are ([entropy.rs](../../daemon/src/entropy.rs)),
but the labelled-trace corpus, its capture subcommand, and the corpus test are not. The calibration
gate stands as written: `enforce_synthetic_detection` remains off by default.*
