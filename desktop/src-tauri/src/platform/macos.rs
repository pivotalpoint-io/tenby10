extern "C" {
    fn AXIsProcessTrusted() -> bool;
}

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightScreenCaptureAccess() -> bool;
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    // IOHIDAccessType IOHIDCheckAccess(IOHIDRequestType request)
    fn IOHIDCheckAccess(request: u32) -> u32;
    // bool IOHIDRequestAccess(IOHIDRequestType request)
    fn IOHIDRequestAccess(request: u32) -> bool;
}

// IOHIDRequestType: kIOHIDRequestTypePostEvent = 0, kIOHIDRequestTypeListenEvent = 1
const IOHID_REQUEST_TYPE_LISTEN_EVENT: u32 = 1;
// IOHIDAccessType: kIOHIDAccessTypeGranted = 0, kIOHIDAccessTypeDenied = 1, kIOHIDAccessTypeUnknown = 2
const IOHID_ACCESS_TYPE_GRANTED: u32 = 0;

/// Whether the app holds the **Input Monitoring** grant (`kTCCServiceListenEvent`).
///
/// This — not Accessibility — is the permission a HID-level `CGEventTapCreate`
/// (used by rdev to capture global keys/clicks/scroll) requires on macOS 10.15+.
/// Checking `AXIsProcessTrusted()` for input capture is a bug: Accessibility can be
/// granted while Input Monitoring is not, leaving the event tap dead but the UI green.
pub fn has_input_monitoring() -> bool {
    unsafe { IOHIDCheckAccess(IOHID_REQUEST_TYPE_LISTEN_EVENT) == IOHID_ACCESS_TYPE_GRANTED }
}

/// Prompt the user for Input Monitoring (shows the system dialog the first time).
pub fn request_input_monitoring() -> bool {
    unsafe { IOHIDRequestAccess(IOHID_REQUEST_TYPE_LISTEN_EVENT) }
}

pub fn check_permissions() -> Result<crate::PermissionsStatus, String> {
    let accessibility = unsafe { AXIsProcessTrusted() };
    let screen_recording = unsafe { CGPreflightScreenCaptureAccess() };
    let input_monitoring = has_input_monitoring();

    // Test Automation (AppleScript / System Events)
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg("tell application \"System Events\" to get name of first process whose frontmost is true")
        .output();

    let automation = match output {
        Ok(out) => out.status.success() && !out.stdout.is_empty(),
        Err(_) => false,
    };

    Ok(crate::PermissionsStatus {
        requires_permissions: true,
        accessibility,
        screen_recording,
        input_monitoring,
        automation,
    })
}

pub fn open_input_monitoring_settings(app: &tauri::AppHandle) -> Result<(), String> {
    // Fire the system prompt once (no-op if already decided), then open the pane.
    let _ = request_input_monitoring();
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(
            "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent",
            None::<&str>,
        )
        .map_err(|e| e.to_string())
}

pub fn open_accessibility_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(
            "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
            None::<&str>,
        )
        .map_err(|e| e.to_string())
}

pub fn open_screen_recording_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(
            "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture",
            None::<&str>,
        )
        .map_err(|e| e.to_string())
}

pub fn open_automation_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(
            "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation",
            None::<&str>,
        )
        .map_err(|e| e.to_string())
}
