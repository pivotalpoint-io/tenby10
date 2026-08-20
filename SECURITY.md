# Security Policy

tenby10's desktop client runs as a background process that hooks global input and reads the title
of the active window, so we take security reports seriously and want them to reach us **privately**
before they reach the public.

It takes no screenshots — the screen-capture subsystem was removed outright rather than left
switchable (ADR 0018), and there is no capture code in the client to report a bug in. macOS still
asks for Screen Recording because it withholds *window titles* without it; the app reads titles, not
pixels. See [`AUDIT.md`](AUDIT.md) §3 if you want to verify that before reporting anything.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected security vulnerability.**

Use one of these private channels instead:

1. **GitHub private vulnerability reporting (preferred).** On this repository, go to the **Security**
   tab → **Report a vulnerability**. This opens a private advisory visible only to you and the
   maintainers.
2. **Email:** `security@pivotalpoint.io`. If you like, encrypt sensitive details or ask for a key
   before sending them.

Please include enough for us to reproduce: affected version/commit, platform (macOS/Windows),
steps or a proof-of-concept, and the impact you observed.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment (and a severity estimate) within **10 business days**.
- Progress updates as we investigate and fix, and credit in the release notes / advisory once a fix
  ships — unless you prefer to remain anonymous.
- We practise **coordinated disclosure**: we ask that you give us a reasonable window to release a
  fix before any public write-up. We won't take legal action against good-faith research that
  respects this policy and does not access, modify, or delete other people's data.

## Scope

**In scope** — anything in this repository:

- the background telemetry **daemon** (`daemon/`),
- the **Tauri desktop app** (`desktop/`),
- the in-app dashboard, and the debug-only loopback HTTP server — note the installed app starts no
  server and opens no port; it runs only for the standalone `daemon` binary with
  `TENBY10_DEBUG_HTTP` set, and is in scope anyway,
- local key handling, the signing/hash-chain ledger, and the anti-cheat / provenance code.

**Out of scope:**

- The tenby10 **cloud portal / API** — it is a separate, closed-source service and is not part of
  this repository. Report cloud issues via the same private channels above and mark them as such.
- Vulnerabilities in **third-party dependencies** — please report those upstream; if a dependency
  issue affects tenby10 specifically, let us know and we'll expedite the bump.
- Findings that require a **already-compromised machine** or physical access, social engineering, or
  denial of service against your own local instance.

## Supported versions

Security fixes target the **latest released version**. There are no long-term support branches;
please reproduce on the most recent release before reporting.
