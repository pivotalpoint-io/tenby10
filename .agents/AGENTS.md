# Agent Guidelines: tenby10 Workspace Customizations

You are an AI coding assistant / agent working in the tenby10 workspace. You must adhere strictly to these operational and SDLC constraints.

---

## 1. Architectural Integrity
* **Decisions First:** Before making any modifications, read existing Architectural Decision Records in the [decisions/](file:///Users/pablo/repos/tenby10/decisions/) directory to understand the design choices and paradigms of the codebase.
* **No Code Leaks:** Respect the decoupling of the source-available client and any SaaS portal sync contracts.

---

## 2. Core SDLC Loop (Mandatory for Agents)

Every code change must go through a formal ticket-branch-PR process. You must execute this workflow when modifying files:

### Step 1: Issue Verification / Creation
If the task is not already associated with an issue:
1. Search issues: `gh issue list`
2. Create an issue if missing:
   ```bash
   gh issue create \
     --title "<type>: <short description>" \
     --body "## Context\n...\n## Expected behavior\n...\n## Acceptance criteria\n..."
   ```
   *Note the issue number `N`.*

### Step 2: Branch Creation
Create a branch named `<type>/<issue-number>-<description>` off `main`:
```bash
git checkout main && git pull
git checkout -b chore/N-description # or feat/N-description, bug/N-description
```

### Step 3: Code, Verify & Lint
Before staging any modifications:
1. Run formatter: `cargo fmt` inside `daemon` and `desktop/src-tauri`.
2. Run clippy: `cargo clippy -- -D warnings` (must compile without warnings).
3. Run tests: `cargo test` (must be 100% green).

### Step 4: Committing Changes
Commit messages must follow the Conventional Commits spec and link to the issue in the footer:
```bash
git add .
git commit -m "feat: add slot aggregation heuristics

Allows the aggregation daemon to calculate metrics properly.

closes #N"
```

### Step 5: Push and Open PR
1. Push your branch: `git push -u origin <branch-name>`
2. Create the Pull Request targeting the **main** branch:
   ```bash
   gh pr create \
     --base main \
     --title "<type>: <description> (#N)" \
     --body "## Summary\n...\n## Testing\n...\ncloses #N"
   ```
3. After creating the PR, return your workspace to the stable branch:
   ```bash
   git checkout main
   ```

---

## 3. Release Process (Informational)
Releases are tag-driven and fully automated:
1. When a set of features is ready on `main`, the owner creates a version tag (e.g., `v1.2.3`).
2. **Automated Versioning**: The CI dynamically injects the tag version into `tauri.conf.json` and `package.json` during the build. **No manual version bumps in files are required.**
3. The tag push triggers the "Release Build and Smoke Test" job.
4. Artifacts and a GitHub Release are automatically created.

---

## 3. Pull Request Lint Constraints
The repository has an active PR Lint GitHub Action. If you fail to follow these, your PR will fail validation:
* **PR Title:** Must match `^(feat|fix|chore|bug|refactor|test|docs|style|ci|perf)(\(.+\))?: .+$`.
* **PR Description:** Must contain a header (`## Summary`, `## Context`, or `## Description`) and link the issue using keywords (e.g. `closes #N`, `fixes #N`).
