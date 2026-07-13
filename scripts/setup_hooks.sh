#!/bin/bash
set -e

# Make hooks executable
chmod +x .githooks/pre-commit
chmod +x .githooks/commit-msg

# Configure git to use our custom hooks directory
git config core.hooksPath .githooks

echo "Git hooks configured successfully to use .githooks/ directory!"
echo "  - pre-commit: fmt + clippy + tests (mirrors CI)"
echo "  - commit-msg: Conventional Commits check (mirrors the PR title lint)"
