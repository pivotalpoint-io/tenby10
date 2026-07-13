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
