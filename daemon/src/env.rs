use crate::config::AgentConfig;
use std::env;
use std::path::PathBuf;

/// Returns true if the application is running in development mode.
///
/// Two independent signals, so a dev build is isolated from prod no matter how it
/// is launched:
/// 1. The `TENBY10_DEV` environment variable (set by `scripts/dev.sh` for `tauri dev`).
/// 2. The main binary being named `tenby10-dev` — the name a bundled dev build ships
///    under (see `tauri.dev.conf.json`). This lets a dev `.app` launched from Finder
///    (which does NOT inherit env vars) still resolve to the dev data dir + port
///    instead of clobbering the prod `~/.tenby10` / port 5005.
pub fn is_dev() -> bool {
    if env::var("TENBY10_DEV").is_ok() {
        return true;
    }
    env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.contains("tenby10-dev"))
        })
        .unwrap_or(false)
}

/// Returns the base directory for app data (config, db, screenshots).
/// Priority:
/// 1. TENBY10_HOME environment variable.
/// 2. ~/.tenby10_dev (in debug builds).
/// 3. ~/.tenby10 (in release builds).
pub fn get_app_home() -> PathBuf {
    if let Ok(home_env) = env::var("TENBY10_HOME") {
        return PathBuf::from(home_env);
    }

    let mut path = PathBuf::from(env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()));
    if is_dev() {
        path.push(".tenby10_dev");
    } else {
        path.push(".tenby10");
    }
    path
}

/// Returns the port for the dashboard server.
/// Priority:
/// 1. TENBY10_PORT environment variable.
/// 2. config.dashboard_port (if set).
/// 3. 5006 (in debug builds).
/// 4. 5005 (in release builds).
pub fn get_app_port(config: &AgentConfig) -> u16 {
    if let Ok(port_env) = env::var("TENBY10_PORT")
        && let Ok(port) = port_env.parse::<u16>()
    {
        return port;
    }

    if let Some(port) = config.dashboard_port {
        return port;
    }

    if is_dev() { 5006 } else { 5005 }
}
