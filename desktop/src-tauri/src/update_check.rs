//! Once-a-day check for a newer tenby10 release.
//!
//! Notify only: when GitHub Releases lists a newer version, the app shows a banner
//! and a tray menu item that open the release page. Nothing is downloaded or
//! installed; the user decides whether to update.
//!
//! One request, `GET` [`RELEASES_API`], with a fixed `User-Agent` and nothing else:
//! no device ID, no installed version, no query string, no cookies. The version
//! comparison happens here, on this machine. Turned off by `disable_update_check`
//! in `config.json` (the "Check for updates" switch in Settings → Connect).
//!
//! See AUDIT.md §2, item 4.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{Emitter, Manager};

/// The one URL this module requests. `releases/latest` skips drafts and pre-releases.
pub const RELEASES_API: &str =
    "https://api.github.com/repos/pivotalpoint-io/tenby10/releases/latest";
/// The release page a found update links to: this prefix plus the release tag.
const RELEASE_PAGE_PREFIX: &str = "https://github.com/pivotalpoint-io/tenby10/releases/tag/";
/// Sent as the `User-Agent`, which GitHub's API requires. Deliberately carries no version.
const USER_AGENT: &str = "tenby10-update-check";

/// How often a check may run.
const CHECK_INTERVAL_SECS: i64 = 24 * 60 * 60;
/// Wait after launch before the first look, so the check never competes with start-up.
const FIRST_LOOK_DELAY: Duration = Duration::from_secs(120);
/// How often the loop wakes to see whether a check is due. Waking is local only.
const WAKE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub const TRAY_ITEM_ID: &str = "open_update";

/// A release newer than the running app.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AvailableUpdate {
    /// The version, without the leading `v` (e.g. `0.9.1`).
    pub version: String,
    /// The release page. Built here from the tag, never taken from the response.
    pub url: String,
}

/// What the check has found so far this run.
#[derive(Default)]
pub struct UpdateState(pub Mutex<Option<AvailableUpdate>>);

/// `MAJOR.MINOR.PATCH`, with an optional leading `v`. Anything else (a pre-release
/// suffix, build metadata, a stray character) is not a version this check acts on.
pub fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let mut parts = raw.split('.');
    let mut next = || -> Option<u64> {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let version = (next()?, next()?, next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(version)
}

/// The update to offer, if `latest_tag` is a release newer than `current`.
pub fn newer_release(current: &str, latest_tag: &str) -> Option<AvailableUpdate> {
    let current = parse_version(current)?;
    let latest = parse_version(latest_tag)?;
    if latest <= current {
        return None;
    }
    let version = format!("{}.{}.{}", latest.0, latest.1, latest.2);
    Some(AvailableUpdate {
        url: format!("{RELEASE_PAGE_PREFIX}v{version}"),
        version,
    })
}

/// Whether a check is due, given when the last one ran (unix seconds, 0 = never).
pub fn check_is_due(last_checked: i64, now: i64) -> bool {
    // A clock set backwards would otherwise hold off checks until it caught up.
    last_checked > now || now - last_checked >= CHECK_INTERVAL_SECS
}

#[derive(serde::Deserialize)]
struct UpdatePreference {
    #[serde(default)]
    disable_update_check: bool,
}

/// Reads only the switch from `config.json`, without touching the keychain. A missing
/// or unreadable file means the default, which is on.
pub fn update_check_disabled(config_path: &Path) -> bool {
    std::fs::read_to_string(config_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<UpdatePreference>(&raw).ok())
        .is_some_and(|pref| pref.disable_update_check)
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct CheckRecord {
    #[serde(default)]
    last_checked: i64,
}

fn record_path() -> PathBuf {
    let mut path = daemon::env::get_app_home();
    path.push("update_check.json");
    path
}

fn read_last_checked(path: &Path) -> i64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<CheckRecord>(&raw).ok())
        .map(|record| record.last_checked)
        .unwrap_or(0)
}

/// Best effort: if this fails, the worst case is one extra check after a restart.
fn write_last_checked(path: &Path, when: i64) {
    if let Ok(raw) = serde_json::to_string(&CheckRecord { last_checked: when }) {
        let _ = std::fs::write(path, raw);
    }
}

#[derive(serde::Deserialize)]
struct LatestRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

async fn fetch_latest_tag() -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let release: LatestRelease = client
        .get(RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if release.draft || release.prerelease {
        return Err("latest release is not a final release".into());
    }
    Ok(release.tag_name)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Runs for the life of the app. Development builds never check: their version is
/// a placeholder, not a release.
pub async fn run(app: tauri::AppHandle, config_path: PathBuf) {
    if daemon::env::is_dev() {
        return;
    }
    let current = app.package_info().version.to_string();
    let record = record_path();

    tokio::time::sleep(FIRST_LOOK_DELAY).await;
    loop {
        let now = now_secs();
        if !update_check_disabled(&config_path) && check_is_due(read_last_checked(&record), now) {
            // Recorded before the request, so a network that is down costs one try a
            // day rather than one an hour.
            write_last_checked(&record, now);
            match fetch_latest_tag().await {
                Ok(tag) => {
                    if let Some(update) = newer_release(&current, &tag) {
                        announce(&app, update);
                    }
                }
                Err(e) => eprintln!("[update-check] {e}"),
            }
        }
        tokio::time::sleep(WAKE_INTERVAL).await;
    }
}

/// Stores the update, adds the tray item the first time, and tells the window.
fn announce(app: &tauri::AppHandle, update: AvailableUpdate) {
    let state = app.state::<UpdateState>();
    let mut found = state.0.lock().unwrap_or_else(|e| e.into_inner());
    if found.as_ref() == Some(&update) {
        return;
    }
    let label = format!("Get tenby10 {}", update.version);
    let tray = app.state::<crate::TrayState>();
    let mut tray_item = tray.update_item.lock().unwrap_or_else(|e| e.into_inner());
    match tray_item.as_ref() {
        Some(item) => {
            let _ = item.set_text(&label);
        }
        None => {
            if let Ok(item) =
                tauri::menu::MenuItem::with_id(app, TRAY_ITEM_ID, &label, true, None::<&str>)
            {
                if tray.menu.insert(&item, 0).is_ok() {
                    *tray_item = Some(item);
                }
            }
        }
    }
    drop(tray_item);
    *found = Some(update.clone());
    drop(found);
    let _ = app.emit("update-available", update);
}

/// Opens the page of the update found, if there is one.
pub fn open_release_page(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let url = app
        .state::<UpdateState>()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|update| update.url.clone())
        .ok_or("No update has been found.")?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_tags() {
        assert_eq!(parse_version("v0.9.0"), Some((0, 9, 0)));
        assert_eq!(parse_version("1.12.3"), Some((1, 12, 3)));
        assert_eq!(parse_version(" v2.0.10 "), Some((2, 0, 10)));
    }

    #[test]
    fn ignores_anything_that_is_not_a_plain_version() {
        for raw in [
            "",
            "v",
            "0.9",
            "0.9.0.1",
            "v0.9.0-beta",
            "0.9.x",
            "v.9.0",
            "0..1",
            "+1.2.3",
        ] {
            assert_eq!(parse_version(raw), None, "{raw}");
        }
    }

    #[test]
    fn offers_only_a_newer_release() {
        assert_eq!(
            newer_release("0.9.0", "v0.9.1"),
            Some(AvailableUpdate {
                version: "0.9.1".into(),
                url: "https://github.com/pivotalpoint-io/tenby10/releases/tag/v0.9.1".into(),
            })
        );
        assert!(newer_release("0.9.0", "v0.10.0").is_some());
        assert!(newer_release("0.9.0", "v1.0.0").is_some());
        assert_eq!(newer_release("0.9.0", "v0.9.0"), None);
        assert_eq!(newer_release("0.10.0", "v0.9.9"), None);
        assert_eq!(newer_release("0.9.0", "v1.0.0-rc1"), None);
        assert_eq!(newer_release("garbage", "v1.0.0"), None);
    }

    #[test]
    fn the_link_is_built_from_the_version_not_the_response() {
        // A tag that is not a plain version never yields a link at all.
        assert_eq!(
            newer_release("0.9.0", "v1.0.0/../../evil?x=https://example.com"),
            None
        );
    }

    #[test]
    fn checks_at_most_once_a_day() {
        let now = 1_800_000_000;
        assert!(check_is_due(0, now));
        assert!(check_is_due(now - CHECK_INTERVAL_SECS, now));
        assert!(!check_is_due(now - CHECK_INTERVAL_SECS + 1, now));
        assert!(!check_is_due(now, now));
        // A clock moved backwards does not hold off checks.
        assert!(check_is_due(now + 3600, now));
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tenby10-update-check-{}-{}-{name}",
            std::process::id(),
            now_secs()
        ));
        path
    }

    #[test]
    fn the_switch_is_on_unless_the_config_turns_it_off() {
        let path = temp_path("config.json");
        assert!(!update_check_disabled(&path), "missing file means on");
        std::fs::write(&path, r#"{"agent_id":""}"#).unwrap();
        assert!(!update_check_disabled(&path), "absent field means on");
        std::fs::write(&path, r#"{"disable_update_check":true}"#).unwrap();
        assert!(update_check_disabled(&path));
        std::fs::write(&path, "not json").unwrap();
        assert!(!update_check_disabled(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn last_check_round_trips() {
        let path = temp_path("update_check.json");
        assert_eq!(read_last_checked(&path), 0);
        write_last_checked(&path, 1_234);
        assert_eq!(read_last_checked(&path), 1_234);
        let _ = std::fs::remove_file(&path);
    }
}
