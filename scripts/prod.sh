#!/bin/bash
# scripts/prod.sh — Run tenby10 in production mode (locally)
set -e
cd "$(git rev-parse --show-toplevel)"

echo "=== Staging production assets ==="
mkdir -p desktop/src-tauri/icons
cp -r desktop/src-tauri/icons_prod/* desktop/src-tauri/icons/
cp desktop/src-tauri/icons_prod/32x32.png desktop/src/favicon.png
cp desktop/src-tauri/icons_prod/128x128.png daemon/src/logo.png
cp desktop/src-tauri/icons_prod/32x32.png daemon/src/favicon.png

echo "=== Launching tenby10 (Prod) ==="
cd desktop/src-tauri && npx tauri dev
