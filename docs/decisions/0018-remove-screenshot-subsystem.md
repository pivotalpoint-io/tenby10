# ADR 0018: Remove the screenshot subsystem — no screen pixels, by construction

*Public edition of this record from the project's decision log. File references describe the
tree as it stood before the removal (the cited code no longer exists, which is the point);
references into unpublished records and internal planning documents are summarized or omitted,
and internal tracker numbers are written out in prose. The decision and its rationale are
complete.*

**Status: Accepted** (2026-08-09). Supersedes ADR 0005 (BYOK screenshot transmission to the LLM
provider). Amends ADR 0004 (local data retention — its screenshot retention clause becomes
moot). Decision: **delete screenshot capture, storage, and every transmission pathway for screen
pixels. tenby10 does not take pictures of screens. Not "off by default" — absent.**

## Context

What the subsystem actually was at the time of this decision (≤ v0.2.x):

- One screenshot per 10-minute slot, captured **deterministically at the slot boundary**
  (`daemon.rs:322-354` of that tree). Blurred with a 20px Gaussian in memory, raw buffer dropped
  before any write
  (`screen.rs:43-70`), stored at native resolution under `~/.tenby10/screenshots/`, retained
  indefinitely (ADR 0004).
- It went nowhere. The cloud payload carried only a `screenshot_count` integer (`sync.rs:100`);
  the portal and the `/verified` page have never displayed a screenshot to anyone.
- The ADR 0005 `send_screenshots` toggle was a **no-op** (AUDIT.md gap G1): no image bytes were
  attached to any LLM request; the flag was string-interpolated into the system prompt as the
  words "Screenshots Enabled: true" (`daemon.rs:687`).
- The permission cost was real even though the feature was inert: capture requires macOS
  **Screen Recording** — the scariest consent dialog on the platform, which Apple deliberately
  makes ungrantable via MDM (PPPC is deny-only for ScreenCapture). Window titles ride the *same*
  grant: `active-win-pos-rs` reads `kCGWindowName` via `CGWindowListCopyWindowInfo`, which macOS
  redacts without Screen Recording. The permission set at the time: **Input Monitoring + Screen
  Recording**.

Trigger: the managed-configuration (MDM) design review (2026-08-09) asked what an
employer-pushed config could escalate. The sharpest possible answer is to have nothing to
escalate.

## Decision

1. **Remove the capture path** — screenshot capture in `screen.rs`, the `screenshots/`
   directory, and the debug dashboard's static serving of it (`dashboard.rs:36-55` of that
   tree). Migration purges the existing local archive (app-generated artifacts; release-notes
   line).
2. **Remove `send_screenshots`** — config field, settings toggle, and cost-estimate copy.
   AUDIT.md gap G1 closes as **won't-build**.
3. **Remove `screenshot_count` from the canonical slot payload** — a scheme bump to v4 under
   the ADR 0017 versioned-aggregation process; the cloud accepts v3 and v4 during transition.
4. **Supersede ADR 0005 in full:** no screen-pixel capture or transmission to any endpoint —
   LLM, tenby10 cloud, or otherwise — *by construction*. Reintroducing any form of screen-pixel
   capture (including hashed or downscaled derivatives) requires a new ADR, because any of it
   re-acquires the Screen Recording permission and re-opens the pressure this ADR closes.
5. **The Screen Recording permission stays.** Window titles ride the same grant (`kCGWindowName`
   is redacted without it), and we are not chasing an Accessibility-API migration to remove it:
   the permission is not the problem — what the app *does* under a permission is, and that is
   answerable by downloading and auditing the source. Nothing to hide. Revisit only if the
   permission request itself becomes a validated adoption blocker.

## Justification

### 1. It was below the evidential noise floor
One frame per 10 minutes cannot distinguish 10 minutes of work from 10 seconds of staged screen —
and ours was *predictable*, taken at the boundary, so even that one frame was gameable on a
schedule. One blurred frame per slot, stored locally and shown to nobody, was the costume of
screenshot-evidence with none of the evidence.

### 2. It was squeezed dead between redundant and forbidden
Everything a 20px-blurred frame could tell an auditor ("looks like an IDE"), the window title
already says with perfect fidelity (`App: 'VS Code', Title: 'main.rs'`) in the text the LLM
mode already sends. Everything an *unblurred* frame would add is exactly what this product
refuses to do. There is no third setting. Any multimodal-auditing ambition dies in that gap,
and with it the last claimed purpose of the archive.

### 3. It contributed zero verification value
The product's trust is the signed chain (ADR 0014, the signing and trust model) — integrity,
attestation, policy authenticity. Pixels appear nowhere in that chain: the cloud saw a count,
the verifier saw nothing, and the trust model's own summary of the design is "a trust ceiling
comparable to a screenshot, **minus the surveillance**." The product's thesis is that the
signed ledger *replaces* the image. A vestigial screenshot organ inside that product is a
contradiction waiting to be quoted, in a source-available repo whose claim is "no screenshots."

### 4. Its costs were structural and recurring
- The Screen Recording dialog is the single scariest ask in onboarding, for a product whose
  stated promise is that it takes no pictures of your screen — and it had already produced real
  field pain (dev/prod TCC identity collisions, silently faked captures).
- An indefinite local screen archive is pure liability surface — a discovery/subpoena target,
  and every component that can read it is one more thing to keep bounded.
- Employer-side gravity: capability that exists invites the demand to unlock it; capability
  that does not exist ends the conversation. This is the strongest possible foundation for the
  managed-configuration (MDM) work: **an employer profile cannot force what the binary cannot
  do.**

### 5. The decisive risk was egress, and removal closes it by construction
The scenario that triggered this ADR: a managed/employer-distributed config pairs the auditor
with an org-owned LLM key, and screen pixels end up recorded in a third party's account —
provider retention, gateway logging, org-admin access, all outside the worker's (and our)
control or verification. A toggle guarding that pathway is a policy; an absent pathway is a
fact. With the subsystem deleted there is nothing for any config — local, managed, or
malicious — to switch on. The claim that matters is *"no screenshots, by construction —
download the code and audit it."* Source auditability, not permission minimization, is the
trust mechanism; the permission pane is not the story.

## What we give up (said plainly)

- **The "screen change" liveness candidate** from
  [ADR 0002](0002-activity-evaluation-engine.md)'s silent-meeting addendum is foreclosed — even
  a perceptual hash needs pixel access and keeps the permission. The liveness track continues
  via mic/camera/in-call signals instead.
- **Even if screen images were later judged necessary**, a blurred, local-only, never-shown
  archive was never going to serve that purpose. Nothing is hedged by keeping it.
- **Anti-cheat ceiling: unchanged.** The adversary still owns the machine (ADR 0014);
  screenshots never raised that ceiling.

## Consequences & sequencing

**Removal (this repository):** items 1–4 above; README fixes ("10m slot random" dies with the
feature); AUDIT.md G1 closed as won't-build; permissions copy updated to state that Screen
Recording is requested **only to read window titles** and that no capture code exists.

**Standing copy rule:** the app still requests Screen Recording (titles). Copy may say "no
screenshots — the code has no capture path, audit it" but must **never** claim the permission
isn't requested. A permission-drop migration (reading titles via the Accessibility API instead)
was evaluated and **rejected as a non-goal**.

**Paper trail:** ADR 0005 → superseded stamp. ADR 0004 → addendum (screenshot clause moot;
DB-row retention unchanged). The managed-config design proceeds with its escalation class
reduced to a single member: LLM-mode activation under an org-owned key.

---

## Implementation record (2026-08-09)

Shipped as client PR [#55](https://github.com/pivotalpoint-io/tenby10/pull/55), with a matching
cloud-side ingest change. **Deploy order mattered: the cloud change had to land first**, or an
upgraded client's v4 slots would have been rejected at ingest.

Two things the removal surfaced that were not obvious when this ADR was written:

1. **Deleting capture would have deleted the permission detector.** The screen-capture probe
   existed to catch the stale-TCC case (#6) where the permission reads green but nothing is
   captured — and window titles ride the *same* grant. Removing capture without replacing the
   probe would have swapped "green but not capturing" for a quieter "green but every title is
   blank", since `get_active_window`'s fallback silently substitutes the app name for a missing
   title. The probe is therefore **replaced, not removed**: an identified frontmost app with a
   blank title is the redaction fingerprint, needs no pixels, and is ground truth for the grant.
   The settings page now reports *Window titles: Readable / Blank*.
2. **The scheme bump is subtractive, which is new.** v2 and v3 only ever *appended* fields, so
   `>= version` branches were safe on both sides. v4 removes a field, so both the client and the
   cloud had to switch the v3 branch to an exact `== 3` match. Rows signed under v3 must keep
   hashing exactly as signed, forever, and an upgraded client can still hold unsynced v3 rows in
   its backlog — so v2/v3/v4 verify concurrently and this is not a cutover. The cloud gained its
   own canonical vector tests; previously that cross-language contract was asserted only from
   the Rust side against a doc comment.
