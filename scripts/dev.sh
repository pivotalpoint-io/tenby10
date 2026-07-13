#!/bin/bash
# scripts/dev.sh — Run tenby10 in development mode
set -e
cd "$(git rev-parse --show-toplevel)"

echo "=== Staging development assets ==="
mkdir -p desktop/src-tauri/icons
cp -r desktop/src-tauri/icons_dev/* desktop/src-tauri/icons/
cp desktop/src-tauri/icons_dev/32x32.png desktop/src/favicon.png
cp desktop/src-tauri/icons_dev/128x128.png daemon/src/logo.png
cp desktop/src-tauri/icons_dev/32x32.png daemon/src/favicon.png

echo "=== Launching tenby10 (Dev) ==="
echo "NOTE (macOS): 'tauri dev' runs the raw cargo binary 'tenby10-desktop' with a"
echo "volatile ad-hoc signature whose cdhash changes on every rebuild. It shares its"
echo "executable name with the prod app and cannot hold a stable TCC grant, so DO NOT"
echo "use it to grant/test Screen Recording or Input Monitoring — those grants will be"
echo "invalidated on the next rebuild and can confuse the prod app's Privacy entries."
echo "For permission-accurate local testing, use: scripts/dev_bundle.sh"
echo ""
export TENBY10_DEV=1
export TENBY10_PORT=5006
# tauri.dev.conf.json gives the *bundled* dev app a distinct identity
# (io.pivotalpoint.tenby10.dev / tenby10-dev). mainBinaryName only applies to
# `tauri build`, so under `tauri dev` the binary is still tenby10-desktop.
cd desktop/src-tauri && npx tauri dev --config tauri.dev.conf.json
