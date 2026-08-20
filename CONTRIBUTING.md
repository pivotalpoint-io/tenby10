# Contributing to tenby10

Thank you for your interest in contributing to tenby10! To maintain codebase health, quality, and a clean Git history, all contributors must follow our software development lifecycle (SDLC) guidelines.

---

## 1. Branch Strategy

We protect our `main` branch to ensure stability. 
* **Rule:** Never commit or push directly to `main`. All changes must be proposed via a Pull Request (PR).
* **Workflow:**
  1. File a GitHub Issue describing the bug, feature request, or chore.
  2. Create a local branch off `main` following this naming convention:
     * `feat/short-description` (for new features)
     * `bug/short-description` or `fix/short-description` (for bug fixes)
     * `chore/short-description` (for refactoring, documentation, or tooling updates)
  3. Implement your changes, write tests, and verify lints.
  4. Push your branch and open a PR targeting `main`.

---

## 2. Commit Message Guidelines

We follow the **Conventional Commits** specification. Commit messages should be structured as follows:

```
<type>(<optional-scope>): <description>

[optional body]

[optional footer(s)]
```

### Allowed Types:
* `feat:` A new feature.
* `fix:` or `bug:` A bug fix.
* `chore:` Tooling, configuration, or structural changes.
* `refactor:` A code change that neither fixes a bug nor adds a feature.
* `test:` Adding missing tests or correcting existing tests.
* `docs:` Documentation-only changes.
* `style:` Changes that do not affect the meaning of the code (formatting, white-space, etc.).
* `ci:` Changes to CI/CD workflows and scripts.
* `perf:` A code change that improves performance.

---

## 3. Pull Request Requirements

We run automated lints on every Pull Request to enforce guidelines:

### PR Title
The PR title must conform to the conventional commit prefix format:
* **Regex Pattern:** `^(feat|fix|chore|bug|refactor|test|docs|style|ci|perf)(\(.+\))?: .+$`
* **Example:** `feat(auth): add user enrollment support` or `chore: update build scripts`

### PR Description Body
The description must contain:
1. **Structural Section Header:** At least one markdown header such as `## Summary`, `## Context`, or `## Description`.
2. **Linked Issue:** A reference linking the PR to the issue it resolves (e.g. `closes #N`, `fixes #N`, or `resolves #N` where `N` is the issue number).

> **These rules are baked into the workflow so you don't hit them after pushing:**
> - `.github/pull_request_template.md` pre-fills a compliant body (`## Summary` + `Closes #N`) — keep
>   the headers and fill in the blanks.
> - The `commit-msg` hook (installed by `scripts/setup_hooks.sh`) rejects non-conforming commit
>   subjects locally, so the PR title — which derives from them — passes the title lint by construction.

# 5. Release Process (Informational)

Releases are tag-driven and fully automated:
1. When a stable set of features is accumulated on `main`, the owner creates a version tag (e.g., `v1.2.3`).
2. **Dynamic Versioning**: The CI automatically syncs the project version with the tag during the build. No manual file edits are required.
3. This tag push triggers the full release build, smoke tests, and GitHub Release creation.

---

## 4. Local Development & Testing

### First, once per clone: stage the icons

`desktop/src-tauri/icons/` is gitignored. The desktop crate `include_bytes!`s several
files out of it, so in a fresh clone (or a fresh `git worktree`) the desktop build fails
with a confusing "no such file" compile error until the directory is populated.

Run this once from the repo root:

```bash
mkdir -p desktop/src-tauri/icons && cp -r desktop/src-tauri/icons_prod/. desktop/src-tauri/icons/
```

`scripts/dev.sh` and `scripts/prod.sh` also stage the icons, but they launch the app
straight afterwards, so they are not a substitute if you only want to build or commit.
The `pre-commit` hook checks for the icons first and prints the command above if they
are missing, rather than letting you hit the compile error.

Before committing your code, please verify that your changes build and pass all local tests.

### Telemetry Daemon (Rust)
```bash
cd daemon
# Check formatting
cargo fmt -- --check

# Check clippy lints
cargo clippy -- -D warnings

# Run all unit tests
cargo test
```

### Desktop UI (Tauri)
```bash
cd desktop
# Install dependencies
npm install

# Run the Tauri app tests
cd src-tauri && cargo test
```

### Dependency advisories

The `Advisories` workflow runs `cargo audit` over both lockfiles on every PR, nightly
against `main`, and fails the build on a vulnerability or an unsoundness advisory. To
reproduce it locally:

```bash
cargo install cargo-audit --locked
cargo audit --file daemon/Cargo.lock
cargo audit --file desktop/src-tauri/Cargo.lock
```

Fix a hit with a **targeted** update in the affected workspace, e.g. `cargo update -p h2`.
Avoid a bare `cargo update`: it re-resolves hundreds of unrelated crates and makes the
lockfile diff unreviewable.

Two things the gate deliberately does not block on, both reported on every run and never
suppressed silently:

* `unmaintained` advisories, which by definition have no fixed version to move to. Ours
  are the Linux-only GTK3 stack that Tauri pulls in and which never compiles into a macOS
  or Windows artifact.
* Anything on the explicit ignore list in `.github/workflows/audit.yml`. Each entry
  carries a written reason and is reviewed like any other diff.

The `rdev` dependency is pinned to an exact commit in `daemon/Cargo.toml`. It installs the
global keyboard and mouse hooks and lives on a personal fork rather than crates.io, so
changing that SHA is a security-relevant change and belongs in its own PR.
