# Anti-cheat red-team & fixture corpus (issue #119)

The entropy detectors ([`entropy.rs`](../src/entropy.rs)) are unit-tested with hand-authored
samples — which proves they do what we *designed*, not that they catch what *real* cheat tools emit.
This doc is how we break that circularity with **real** data, and how we validate detection
end-to-end before trusting it.

> **Current honest state:** the corpus in [`fixtures/`](fixtures/) is **synthetic-only**. The corpus
> test prints `0 captured / N synthetic` and warns until real captures are added. A green corpus run
> is *not* "verified against real tools" until that count is non-zero.

## 1. Capture a real trace

On a real machine, with Input Monitoring granted, record a labelled trace while a tool runs (or while
you act naturally):

```bash
# A real mouse jiggler app, recorded for 60s:
daemon --capture-trace jiggler_app_x.json --kind mouse --label jiggler --seconds 60
#   ...launch the jiggler now...

# A real keyboard macro (e.g. AutoHotkey), recorded for 60s:
daemon --capture-trace macro_ahk.json --kind keyboard --label macro --seconds 60

# A genuine human session (type / move naturally):
daemon --capture-trace human_me.json --kind keyboard --label human --seconds 120
```

A trace records only what the detectors consume — keyboard inter-key **timing** and mouse
**positions**; never key contents. Then commit the JSON into `daemon/tests/fixtures/` (it is written
with `source: "captured"`). The corpus test picks it up automatically:

```bash
cd daemon && cargo test --test anti_cheat_corpus -- --nocapture
```

It runs the real detector over every fixture and asserts the verdict matches the label. Aim for a
spread: several real jigglers/macros (must be flagged) **and** several real human sessions from
different people/devices (must NOT be flagged — false positives are the worst failure).

## 2. End-to-end red-team

Unit tests can't prove the *live pipeline* stops a cheat. Periodically, on a real machine:

1. Run the daemon normally and let a real **jiggler**/**macro** drive input for a full 10-minute slot,
   with no genuine work.
2. Confirm the slot is **not billable**: `daemon --verify` passes (the ledger is intact) and the slot's
   focus is below the billable gate / classified `Tampered` (check the dashboard or the DB).
3. Repeat with a genuine light-work session and confirm it **is** credited (no false positive).

Record the date, tools, versions, and outcome below.

## 3. Gate: enabling synthetic-input enforcement

`enforce_synthetic_detection` ships **off**. Turn it on only after:
- captured human traces show no false positives, and
- a red-team run confirms injected input is both detected (provenance) and denied billing.

Until then it stays observe-only.

## Red-team log

| Date | Platform | Tool / version | Detected? | Billed? | Notes |
|------|----------|----------------|-----------|---------|-------|
| _e.g._ 2026-08-29 | macOS 15 | (add real runs here) | | | |
