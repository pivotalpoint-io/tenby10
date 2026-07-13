pub fn check_permissions() -> Result<crate::PermissionsStatus, String> {
    Ok(crate::PermissionsStatus {
        requires_permissions: false,
        accessibility: true,
        screen_recording: true,
        input_monitoring: true,
        automation: true,
    })
}

pub fn open_accessibility_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path("ms-settings:privacy", None::<&str>)
        .map_err(|e| e.to_string())
}

pub fn open_screen_recording_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path("ms-settings:privacy", None::<&str>)
        .map_err(|e| e.to_string())
}

pub fn open_automation_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path("ms-settings:privacy", None::<&str>)
        .map_err(|e| e.to_string())
}

pub fn open_input_monitoring_settings(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path("ms-settings:privacy", None::<&str>)
        .map_err(|e| e.to_string())
}
