#!/bin/bash
set -e

echo "=== Starting tenby10 Local Smoke Tests ==="

# Define test environment directory
TEST_HOME="/tmp/tenby10-smoke-test"
TEST_PORT="5999"

# Clean up previous test runs
rm -rf "$TEST_HOME"
mkdir -p "$TEST_HOME"

echo "1. Verifying Daemon Binary Release Compilation..."
if [ ! -f daemon/target/release/daemon ]; then
    echo "ERROR: Daemon release binary not found at daemon/target/release/daemon. Please build it first."
    exit 1
fi
echo "SUCCESS: Daemon binary found."

echo "2. Launching Daemon on port $TEST_PORT under isolated HOME=$TEST_HOME..."
HOME="$TEST_HOME" TENBY10_PORT="$TEST_PORT" daemon/target/release/daemon > "$TEST_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!

# Ensure daemon is killed on exit
cleanup() {
    echo "Cleaning up processes..."
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "Killing Daemon process (PID: $DAEMON_PID)..."
        kill "$DAEMON_PID" || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Waiting for Daemon to start up..."
sleep 2

# Check if daemon process is still running
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: Daemon exited prematurely. Check logs at $TEST_HOME/daemon.log"
    cat "$TEST_HOME/daemon.log"
    exit 1
fi

echo "3. Performing HTTP Status Check on Local Dashboard..."
RESPONSE_CODE=$(curl -o /dev/null -s -w "%{http_code}" "http://127.0.0.1:$TEST_PORT/")
if [ "$RESPONSE_CODE" -ne 200 ]; then
    echo "ERROR: Local dashboard returned HTTP $RESPONSE_CODE (expected 200)."
    exit 1
fi
echo "SUCCESS: Dashboard server is responsive (HTTP 200)."

echo "4. Verifying Local Storage Initialization..."
if [ ! -f "$TEST_HOME/.tenby10/tenby10.db" ]; then
    echo "ERROR: SQLite database was not initialized at $TEST_HOME/.tenby10/tenby10.db"
    exit 1
fi
echo "SUCCESS: SQLite database initialized."

echo "5. Verifying Database Integrity CLI Options..."
INTEGRITY_RES=0
HOME="$TEST_HOME" daemon/target/release/daemon --verify || INTEGRITY_RES=$?
if [ "$INTEGRITY_RES" -ne 0 ]; then
    echo "ERROR: Database cryptographic ledger verification failed with exit code $INTEGRITY_RES."
    exit 1
fi
echo "SUCCESS: Database integrity check passed."

echo "6. Verifying Tauri Desktop App Bundle..."
APP_PATH="desktop/src-tauri/target/release/bundle/macos/tenby10.app"
if [ ! -d "$APP_PATH" ]; then
    echo "ERROR: Tauri App bundle not found at $APP_PATH. Please run 'npm run tauri build' first."
    exit 1
fi
if [ ! -f "$APP_PATH/Contents/MacOS/tenby10-desktop" ]; then
    echo "ERROR: Tauri App binary not found inside app bundle at $APP_PATH/Contents/MacOS/tenby10-desktop"
    exit 1
fi
echo "SUCCESS: Tauri App bundle verified."

echo "=== All local smoke tests passed successfully! ==="
exit 0
