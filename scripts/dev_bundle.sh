#!/bin/bash
# scripts/dev_bundle.sh — Build & install a *bundled* dev app with a fully distinct,
# stable macOS identity (io.pivotalpoint.tenby10.dev / tenby10-dev.app).
#
# Use this — not `scripts/dev.sh` (tauri dev) — whenever you need to grant or test
# macOS permissions (Screen Recording, Input Monitoring, Accessibility) locally.
# Unlike the `tauri dev` binary, this app:
#   - shows up in System Settings as "tenby10-dev" (never confused with prod "tenby10"),
#   - has its own bundle id, so its TCC grants never touch the prod app's,
#   - self-isolates data to ~/.tenby10_dev and port 5006 even when launched from Finder
#     (env::is_dev() detects the tenby10-dev binary name — see daemon/src/env.rs).
#
# For a grant that survives rebuilds, set APPLE_SIGNING_IDENTITY to your Developer ID
# (e.g. "Developer ID Application: PivotalPoint OU (DY226C3367)"). Without it the bundle
# is ad-hoc signed and macOS will re-prompt after each rebuild (cdhash changes).
set -e
cd "$(git rev-parse --show-toplevel)"

echo "=== Staging development assets ==="
mkdir -p desktop/src-tauri/icons
cp -r desktop/src-tauri/icons_dev/* desktop/src-tauri/icons/
cp desktop/src-tauri/icons_dev/32x32.png desktop/src/favicon.png
cp desktop/src-tauri/icons_dev/128x128.png daemon/src/logo.png
cp desktop/src-tauri/icons_dev/32x32.png daemon/src/favicon.png

echo "=== Building bundled dev app (tenby10-dev.app) ==="
( cd desktop/src-tauri && npx tauri build --debug --config tauri.dev.conf.json --bundles app )

APP_SRC="desktop/src-tauri/target/debug/bundle/macos/tenby10-dev.app"
if [ ! -d "$APP_SRC" ]; then
  echo "[ERROR] Expected bundle not found at $APP_SRC" >&2
  exit 1
fi

DEST="/Applications/tenby10-dev.app"
echo "=== Installing to $DEST ==="
rm -rf "$DEST"
cp -R "$APP_SRC" "$DEST"

if [ -n "${APPLE_SIGNING_IDENTITY:-}" ]; then
  echo "=== Re-signing with Developer ID for a rebuild-stable TCC identity ==="
  codesign --force --deep --options runtime \
    --identifier io.pivotalpoint.tenby10.dev \
    --sign "$APPLE_SIGNING_IDENTITY" "$DEST"
else
  echo "[WARN] APPLE_SIGNING_IDENTITY not set — bundle is ad-hoc signed; macOS will"
  echo "       re-prompt for permissions after each rebuild."
fi

echo "=== Launching tenby10-dev ==="
open "$DEST"
