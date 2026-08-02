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

/// Whether the debug HTTP dashboard server may start (#40).
///
/// Off unless `TENBY10_DEBUG_HTTP` is set to a truthy value, so a normal run — and
/// every installed app — opens no listening port. The server is a triage escape
/// hatch only; the real dashboard renders in-app over Tauri IPC.
pub fn debug_http_enabled() -> bool {
    debug_http_enabled_from(env::var("TENBY10_DEBUG_HTTP").ok().as_deref())
}

/// Pure form of [`debug_http_enabled`], so the default-off behaviour is testable
/// without mutating process environment from tests.
fn debug_http_enabled_from(value: Option<&str>) -> bool {
    match value {
        Some(val) => {
            let val = val.trim().to_ascii_lowercase();
            // Treat an explicitly falsey value as off, so `TENBY10_DEBUG_HTTP=0`
            // does what it looks like rather than enabling via mere presence.
            !val.is_empty() && val != "0" && val != "false" && val != "no"
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_http_is_off_unless_explicitly_enabled() {
        // The default install must open no port (#40).
        assert!(!debug_http_enabled_from(None), "unset -> off");
        assert!(!debug_http_enabled_from(Some("")), "empty -> off");
        assert!(!debug_http_enabled_from(Some("  ")), "whitespace -> off");

        // An explicitly falsey value must mean off, not "present therefore on".
        assert!(!debug_http_enabled_from(Some("0")), "0 -> off");
        assert!(!debug_http_enabled_from(Some("false")), "false -> off");
        assert!(!debug_http_enabled_from(Some("FALSE")), "case-insensitive");
        assert!(!debug_http_enabled_from(Some("no")), "no -> off");
    }

    #[test]
    fn test_debug_http_enables_on_a_truthy_value() {
        assert!(debug_http_enabled_from(Some("1")));
        assert!(debug_http_enabled_from(Some("true")));
        assert!(debug_http_enabled_from(Some(" 1 ")), "trims whitespace");
    }
}
