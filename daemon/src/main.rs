use std::env;
use std::sync::Arc;

use daemon::daemon::{TelemetryState, start_daemon_loop, start_input_listener};
use daemon::dashboard::start_dashboard_server;
use daemon::db::Database;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let is_verify = args.iter().any(|arg| arg == "--verify" || arg == "-v");

    let app_home = daemon::env::get_app_home();
    let mut db_path = app_home.clone();
    db_path.push("tenby10.db");

    let mut config_path = app_home.clone();
    config_path.push("config.json");
    let config = daemon::config::load_config(config_path).unwrap_or_default();

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

    // Start the local web dashboard server
    let port = daemon::env::get_app_port(&config);
    start_dashboard_server(db.clone(), port);

    let state = Arc::new(TelemetryState::new());

    // Start the global event listener thread in the background
    start_input_listener(state.clone());

    // Start the input-provenance monitor (#87): flags software-injected input.
    daemon::provenance::start_provenance_monitor();

    // Start the main loop (this blocks and runs indefinitely)
    start_daemon_loop(db, state);
}
