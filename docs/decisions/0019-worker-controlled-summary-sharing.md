# ADR 0019: Worker-Approved Work Summaries on Verified Links

*Public edition of this record from the project's decision log: references into unpublished
internal documents are summarized or omitted, and file references are written for this
repository. The decision, its constraints, and its non-goals are complete.*

## Status
Accepted. §4 revised 2026-08-28: notes name the work in their own words; the constraints
narrowed to verbatim reproduction and person names.

## Context

Real verified links show numbers, categories, and rules. No narrative. (The `aiSummary` on the
sample page is a demo fixture.)

A number on its own is hard to check. A short note naming the work lets a reader match hours to
something concrete. The long-standing manual practice is a weekly written summary next to the
invoice. Its two failure modes: people write bad notes, and they write them late.

Privacy contract at the time of this decision (the cloud privacy page and
[AUDIT.md](../../AUDIT.md)): per-slot AI reasoning never leaves the machine; only its SHA-256
syncs. Window titles never sync. Shipping summary text upstream is a contract change. It must
be explicit, worker-controlled, and reflected on the privacy page in the same release.

## Decision

(Revised twice, final 2026-08-14. The governing direction: the tool works for the worker, never
blocks on the worker, and is never a step in anyone's workflow. Setup once, then invisible.)

**Design principle, binding:** setup once, then invisible. No approval queues, no toggles that
restate consent already given, no daily actions. Consent lives in the acts that already exist:
connecting your own AI, enrolling a device, sharing a link.

1. **Daily summary records, generated locally.** When BYOK AI is enabled, the daemon generates
   one short work summary per day from window titles and slot data. That is what the AI is for.
   Same prompt-visibility rule as scoring: the exact prompt is part of the signed config.
2. **On by default with AI.** Summaries sync like every other record once enrolled, and appear
   on links the worker shares. No separate toggle decision at setup. An opt-out switch exists in
   settings for the exception case.
3. **Disclosure at the moment of choice.** The connect-AI screen carries one line: "Daily work
   summaries will appear on links you share. Turn off in settings." Setup, not workflow.
4. **Privacy by the prompt, not by review — and specific by design (revised 2026-08-28).** The
   note's value is that it names the work. The prompt instructs the model to name the project,
   repository, document, or feature in its own words; a note that names nothing does not do the
   note's job, and notes are read most carefully when hours are questioned. Exactly three constraints
   remain: no verbatim reproduction of a window title, file path, or URL (mechanism-enforced —
   a note echoing a long run of any captured title is refused before signing, #83); no
   private persons' names (email subjects, DMs — the sharpest edge titles capture); no hours or
   scores in prose. Project, product, and company names are allowed: they are what the work is
   about. Accepted exposure, stated: a day spanning several clients can name one client's
   project on a link another client sees. Mitigations stay as designed — the correction window,
   withdraw/revise — and the per-link name allowlist remains the escalation if that exposure
   bites in practice rather than in theory.
5. **Correction window, blocking on nobody.** Generated at day close, synced the next morning.
   Nothing waits for anyone. The worker can withdraw or revise any summary; a revision is a new
   chained record labeled "revised by {name}". Nothing is silently rewritten.
6. **Signed records.** Each summary is a chained ledger record (period, text, generated-at),
   signed with the worker's key, counter-signed by the cloud on sync. Rendered grouped by week,
   labeled "Written by AI on {name}'s machine from the work log." Generation lagging the period
   by more than 48 hours is labeled late.
7. **Privacy page and AUDIT.md update in the same release**, one sentence of truth: per-slot
   reasoning never leaves; daily summaries sync when AI is enabled and the device is enrolled,
   are visible only on links the worker shares, and can be turned off in settings.

## Non-goals

- Summary text never changes billed numbers. It is context, not evidence.
- **No approval queue, no pending states for the worker.** Instances get correction, patterns
  get rules — for the worker exactly as for the manager.
- No retroactive bulk generation presented as contemporaneous.
- Accepted tradeoff, stated: a bad summary can publish before the worker notices. Guards: the
  constrained signed prompt, the morning delay, visible revision. A worker who finds this
  unacceptable keeps the toggle off; that is their rule to make, once.

## Consequences

Adds: one new record type to the ledger and sync payload, review UI in the desktop app,
verified-page rendering, privacy copy updates. The "what leaves your machine" answer grows by
exactly one item, and it is the item the worker reads and approves.
