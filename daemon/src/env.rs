use crate::config::AgentConfig;
use std::env;
use std::path::{Path, PathBuf};

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

/// Returns the base directory for app data (config, db).
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

/// Owner-only modes for the app data directory and the files in it (#95).
///
/// `~/.tenby10` holds `tenby10.db`, and that database keeps every window title this
/// machine has ever observed, in plaintext. That is the most sensitive material the
/// app has — more so than the two secrets, which already live in the OS keychain —
/// and until now it was written at whatever the process umask happened to be,
/// typically `0755` on the directory and `0644` on the files. Every other account on
/// the machine could read it.
///
/// A `0700` home directory does hide it on a normal single-user macOS install, but
/// that is inherited protection rather than designed protection: it disappears the
/// moment `TENBY10_HOME` points somewhere else, and it was never true of a shared or
/// managed machine.
#[cfg(unix)]
const APP_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const APP_FILE_MODE: u32 = 0o600;

/// Restrict `dir` to its owner (`0700`).
pub fn secure_dir(dir: &Path) {
    #[cfg(unix)]
    set_owner_only(dir, APP_DIR_MODE);
    #[cfg(not(unix))]
    warn_permissions_not_enforced(dir);
}

/// Restrict `path` to its owner (`0600`).
pub fn secure_file(path: &Path) {
    #[cfg(unix)]
    set_owner_only(path, APP_FILE_MODE);
    #[cfg(not(unix))]
    warn_permissions_not_enforced(path);
}

/// Restrict the app data directory to `0700`, but only when `path` is a file we keep
/// inside it.
///
/// The check is deliberate rather than defensive noise. These helpers are called from
/// [`crate::db::Database::new`] and [`crate::config::save_config`], which take whatever
/// path they are handed — tests open a database under `/tmp`, and `TENBY10_HOME` can
/// point at any directory at all. Chmodding "whatever directory this file happens to
/// sit in" would lock other accounts out of a directory that was never ours. Only
/// [`get_app_home`] is tightened, and only when it really is the parent.
pub fn secure_app_home_for(path: &Path) {
    let home = get_app_home();
    if path.parent() == Some(home.as_path()) {
        secure_dir(&home);
    }
}

/// Restrict the database and the sidecar files SQLite keeps beside it.
///
/// A rollback journal, and a WAL plus its shared-memory index, hold the same rows as
/// the database itself, so leaving them world-readable would leak exactly what
/// tightening the database was meant to prevent. Two things happen here: SQLite gives
/// a journal or WAL it creates the mode of the database file it belongs to, so
/// tightening the database *first* is what keeps future sidecars owner-only; the loop
/// then catches any an older build already left on disk. Missing files are skipped
/// silently — in the default rollback-journal mode there is usually nothing there.
pub fn secure_db_files(db_path: &Path) {
    secure_file(db_path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = db_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        secure_file(Path::new(&sidecar));
    }
}

/// Apply `mode` to an existing path. Missing paths are not an error: callers pass
/// sidecar files that often do not exist, and a warning for each would be noise.
///
/// A failure is reported and not propagated. Every caller is on a startup path where
/// the alternative is refusing to run, and a database the user can still read is worth
/// more than one nobody can — but the user is told, because they are now relying on
/// their home directory instead of on us.
#[cfg(unix)]
fn set_owner_only(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if !path.exists() {
        return;
    }
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        eprintln!(
            "[WARN] Could not restrict {:?} to {:o}: {}. Other accounts on this machine may be \
             able to read it.",
            path, mode, err
        );
    }
}

/// Windows has no mode bits, and this is **not** covered there.
///
/// The honest equivalent is an explicit DACL on `%USERPROFILE%\.tenby10` granting only
/// the owner, written with `SetNamedSecurityInfoW` — a chunk of `windows-sys` and a
/// hand-built ACL for a platform this app is not yet shipped on. Rather than pretend,
/// this says plainly that the protection is missing, once per process so it is visible
/// without being noise. A Windows user's data is protected only by the default ACL on
/// their profile directory, which on a stock install does keep other standard users out
/// but is not something we set or check.
#[cfg(not(unix))]
fn warn_permissions_not_enforced(path: &Path) {
    use std::sync::Once;
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "[WARN] tenby10 does not set file permissions on this platform, so {:?} and the rest \
             of the app data directory keep whatever access their parent folder grants. That \
             directory holds every window title observed on this machine. If other accounts use \
             it, restrict the folder by hand (Properties -> Security).",
            path
        );
    });
}

/// Delete the legacy `screenshots/` directory left by pre-ADR-0018 builds.
///
/// The subsystem is gone, so an upgrade must not silently leave a folder of
/// screen captures on disk (retained indefinitely under the old ADR 0004 policy)
/// with nothing left in the app that would ever show or clean it. Idempotent:
/// after the first run there is nothing to remove. Only ever removes the
/// directory this app created.
pub fn purge_legacy_screenshots() {
    let mut dir = get_app_home();
    dir.push("screenshots");
    if !dir.is_dir() {
        return;
    }
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => println!(
            "[Migration] Removed the legacy screenshot archive at {:?} (ADR 0018 — \
             screen capture no longer exists).",
            dir
        ),
        Err(err) => eprintln!(
            "[Migration] Could not remove the legacy screenshot archive at {:?}: {}. \
             It is no longer written to or read; delete it by hand if you want it gone.",
            dir, err
        ),
    }
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

    /// Mode bits of `path`, without the file-type bits.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("tenby10_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn test_app_data_is_tightened_to_its_owner_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("perm_test");
        let file = dir.join("config.json");
        std::fs::write(&file, "{}").unwrap();

        // Start from the modes an install made by an earlier build actually has, so
        // this covers the upgrade path and not only a fresh directory.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        secure_dir(&dir);
        secure_file(&file);
        assert_eq!(
            mode_of(&dir),
            0o700,
            "app data directory must be owner-only"
        );
        assert_eq!(mode_of(&file), 0o600, "config.json must be owner-only");

        // Idempotent, and a path that does not exist is not an error — SQLite's
        // sidecars are absent most of the time and must not produce a warning each run.
        secure_dir(&dir);
        secure_file(&dir.join("tenby10.db-wal"));
        assert_eq!(mode_of(&dir), 0o700);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_only_our_own_directory_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        // A database can be opened anywhere — tests do exactly that — and locking other
        // accounts out of a directory that was never ours would be a bug, not hardening.
        let outsider = scratch_dir("foreign_dir");
        std::fs::set_permissions(&outsider, std::fs::Permissions::from_mode(0o755)).unwrap();

        secure_app_home_for(&outsider.join("tenby10.db"));
        assert_eq!(
            mode_of(&outsider),
            0o755,
            "a directory that is not the app home is left exactly as it was"
        );

        let _ = std::fs::remove_dir_all(&outsider);
    }

    #[test]
    fn test_debug_http_enables_on_a_truthy_value() {
        assert!(debug_http_enabled_from(Some("1")));
        assert!(debug_http_enabled_from(Some("true")));
        assert!(debug_http_enabled_from(Some(" 1 ")), "trims whitespace");
    }
}
