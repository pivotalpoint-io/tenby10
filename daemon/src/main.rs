use std::env;
use std::sync::Arc;

use daemon::daemon::{TelemetryState, start_daemon_loop, start_input_listener};
use daemon::dashboard::start_dashboard_server;
use daemon::db::Database;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let is_verify = args.iter().any(|arg| arg == "--verify" || arg == "-v");
    // `--reseal <from_unix>`: one-shot recovery of an orphaned pre-sync ledger (#19).
    let reseal_from = args
        .iter()
        .position(|a| a == "--reseal")
        .and_then(|i| args.get(i + 1))
        .map(|v| {
            v.parse::<i64>()
                .expect("--reseal needs a unix timestamp argument")
        });

    let app_home = daemon::env::get_app_home();
    let mut db_path = app_home.clone();
    db_path.push("tenby10.db");

    let mut config_path = app_home.clone();
    config_path.push("config.json");
    let config = daemon::config::load_config(config_path).unwrap_or_default();

    if let Some(from) = reseal_from {
        // Run the whole recovery on a plain thread: the sync path uses blocking HTTP, which must
        // not run inside the async runtime.
        let handle = std::thread::spawn(move || reseal_and_sync(db_path, config, from));
        std::process::exit(handle.join().expect("reseal thread panicked"));
    }

    if is_verify {
        println!("Verifying database integrity at {:?}...", db_path);
        let db = Database::new(db_path).expect("Failed to open SQLite database");
        match db.verify_ledger_integrity(&config.public_key) {
            Ok(Ok(())) => {
                println!(
                    "SUCCESS: Cryptographic hash chain is fully intact. No tampering detected!"
                );
                std::process::exit(0);
            }
            Ok(Err(err)) => {
                println!("TAMPERED: Verification failed: {}", err);
                std::process::exit(1);
            }
            Err(err) => {
                println!("ERROR: Verification check encountered error: {}", err);
                std::process::exit(2);
            }
        }
    }

    println!("Initializing Database at {:?}", db_path);
    let db = Arc::new(Database::new(db_path).expect("Failed to initialize SQLite database"));

    // Debug-only HTTP dashboard, off unless explicitly opted into (#40). The app's
    // dashboard renders natively over IPC, so this exists purely as a triage escape
    // hatch ("is it actually capturing?"). It stays off by default so a normal run
    // opens no listening port.
    if daemon::env::debug_http_enabled() {
        let port = daemon::env::get_app_port(&config);
        println!(
            "[Dashboard] TENBY10_DEBUG_HTTP is set — starting the debug HTTP server on \
             127.0.0.1:{}. It serves activity data and a CSV export to anything \
             that can reach loopback; unset the variable to disable it.",
            port
        );
        start_dashboard_server(db.clone(), port);
    }

    let state = Arc::new(TelemetryState::new());

    // Start the global event listener thread in the background
    start_input_listener(state.clone());

    // Start the input-provenance monitor (#87): flags software-injected input.
    daemon::provenance::start_provenance_monitor();

    // Start the main loop (this blocks and runs indefinitely)
    start_daemon_loop(db, state);
}

/// One-shot `--reseal` recovery (#19): re-chain + re-sign the ledger suffix `>= from` under the
/// current key, force the effective config to re-upload, then sync. Returns a process exit code.
fn reseal_and_sync(
    db_path: std::path::PathBuf,
    config: daemon::config::AgentConfig,
    from: i64,
) -> i32 {
    use daemon::db::SlotSigner;

    if config.agent_id.is_empty() {
        eprintln!("ERROR: not enrolled — nothing to reseal to.");
        return 2;
    }
    if config.public_key.is_empty() || config.private_key.is_empty() {
        eprintln!("ERROR: no signing key in config/keychain — cannot re-sign.");
        return 2;
    }

    let db = match Database::new(db_path) {
        Ok(db) => db,
        Err(err) => {
            eprintln!("ERROR: failed to open database: {err}");
            return 2;
        }
    };

    let signer = SlotSigner {
        public_key: &config.public_key,
        private_key: &config.private_key,
    };
    let n = match db.reseal_from(from, &signer) {
        Ok(n) => n,
        Err(err) => {
            eprintln!("ERROR: reseal failed: {err}");
            return 2;
        }
    };
    println!(
        "Resealed {n} slot(s) from {from} under key {}.",
        config.public_key
    );
    if n == 0 {
        println!("No slots in range — nothing to upload.");
        return 0;
    }

    // Each resealed slot carries its own config_hash; sync backfills whichever configs the cloud
    // is missing via the 428 retry (#80), so no config pre-upload here. Persist the current config
    // blob so slots scored under it (the common case) can be backfilled even if they predate the
    // local config-blob store.
    if let Err(err) = db.store_config_blob(
        &config.effective_config_hash(),
        &config.effective_config_blob(),
    ) {
        eprintln!("WARN: could not persist current config blob: {err}");
    }

    let base = daemon::sync::cloud_base_url();
    match daemon::sync::sync_signed_slots(&db, &config.agent_id, &base) {
        Ok(uploaded) => {
            println!("Uploaded {uploaded} slot(s) to {base}.");
            if let Ok(head) = db.get_latest_slot_hash() {
                println!("Ledger head is now 0x{}", head.get(..8).unwrap_or(&head));
            }
            0
        }
        Err(err) => {
            eprintln!("ERROR: slot sync failed: {err}");
            1
        }
    }
}
