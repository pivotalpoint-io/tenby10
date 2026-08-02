use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::db::Database;

// Icon will be included and encoded at runtime

/// Start the debug HTTP dashboard on a background thread, bound to loopback.
///
/// **Not started by the installed app** (#40). The activity dashboard renders
/// in-app from Tauri IPC, so this exists only as a triage escape hatch for the
/// standalone `daemon` binary, gated behind [`crate::env::debug_http_enabled`].
///
/// It is unauthenticated: while enabled, anything that can reach loopback — any
/// local process or OS user on the machine — can read the blurred screenshots and
/// the activity CSV it serves. Keep it off unless actively debugging.
pub fn start_dashboard_server(db: Arc<Database>, port: u16) {
    let db_state = Arc::clone(&db);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime for web server");

        rt.block_on(async move {
            let mut screenshots_dir = crate::env::get_app_home();
            screenshots_dir.push("screenshots");

            // Read-only triage surface. The config read/write and mock-enroll routes
            // were removed (#40): they mutated state — including secret-bearing
            // config — over an unauthenticated port, and had no diagnostic value now
            // that the app configures itself over Tauri IPC.
            //
            // No CORS layer either. This previously ran `CorsLayer::permissive()`,
            // which let any origin read these responses; the dashboard HTML is served
            // from this same origin and needs no cross-origin access.
            let app = Router::new()
                .route("/", get(serve_dashboard_html))
                .route("/api/data", get(get_dashboard_data))
                .route("/api/pending", get(get_pending_slots))
                .route("/api/slot_details", get(get_slot_details))
                .route("/api/export", get(export_csv))
                .nest_service(
                    "/screenshots",
                    tower_http::services::ServeDir::new(screenshots_dir),
                )
                .with_state(db_state);

            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            println!("[Dashboard] Starting server on http://{}", addr);

            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    if let Err(err) = axum::serve(listener, app).await {
                        eprintln!("[Dashboard] Server error: {}", err);
                    }
                }
                Err(err) => {
                    eprintln!("[Dashboard] Failed to bind to address: {}", err);
                }
            }
        });
    });
}

/// Handler to fetch slot summaries from SQLite.
async fn get_dashboard_data(State(db): State<Arc<Database>>) -> impl IntoResponse {
    // We run the blocking SQLite queries in a spawn_blocking call
    let data_res = tokio::task::spawn_blocking(move || db.get_recent_slot_summaries(1000)).await;

    match data_res {
        Ok(Ok(slots)) => Json(serde_json::json!({ "slots": slots })).into_response(),
        _ => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Error querying database",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SlotDetailsQuery {
    start: i64,
}

async fn get_slot_details(
    State(db): State<Arc<Database>>,
    axum::extract::Query(params): axum::extract::Query<SlotDetailsQuery>,
) -> impl IntoResponse {
    let slot_start = params.start;
    let details_res =
        tokio::task::spawn_blocking(move || db.get_slot_minute_details(slot_start)).await;

    match details_res {
        Ok(Ok(details)) => Json(details).into_response(),
        _ => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Error querying database",
        )
            .into_response(),
    }
}

async fn get_pending_slots(State(db): State<Arc<Database>>) -> impl IntoResponse {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let current_slot_start = timestamp - (timestamp % 600);

    let slots = db
        .get_unaggregated_slots(current_slot_start)
        .unwrap_or_default();
    Json(serde_json::json!({
        "pending_slots": slots
    }))
}

#[derive(serde::Deserialize)]
struct ExportQuery {
    range: Option<String>,
    start: Option<i64>,
    end: Option<i64>,
}

/// Handler to export telemetry as a CSV file.
async fn export_csv(
    axum::extract::Query(params): axum::extract::Query<ExportQuery>,
    State(db): State<Arc<Database>>,
) -> impl IntoResponse {
    let range_str = params.range.unwrap_or_else(|| "24h".to_string());

    let rows_res = tokio::task::spawn_blocking(move || {
        db.export_minute_logs_csv(&range_str, params.start, params.end)
    })
    .await;

    let csv_data = match rows_res {
        Ok(Ok(data)) => data,
        _ => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Database read failure",
            )
                .into_response();
        }
    };

    let headers = [
        (axum::http::header::CONTENT_TYPE, "text/csv"),
        (
            axum::http::header::CONTENT_DISPOSITION,
            "attachment; filename=\"tenby10_logs.csv\"",
        ),
    ];

    (headers, csv_data).into_response()
}

// The `get_settings` / `save_settings` handlers were removed in #40. Reading the
// agent config here served it straight from `load_config`, which overlays keychain
// material onto the returned struct, and the write side accepted a whole config
// from any caller. The app reads and writes config over Tauri IPC instead, so this
// surface had no remaining consumer.

/// Serves the single-page web dashboard HTML.
async fn serve_dashboard_html() -> impl IntoResponse {
    let favicon_bytes = include_bytes!("favicon.png");
    let logo_bytes = include_bytes!("logo.png");
    let font_bytes = include_bytes!("outfit-variable.woff2");
    let favicon_b64 = general_purpose::STANDARD.encode(favicon_bytes);
    let logo_b64 = general_purpose::STANDARD.encode(logo_bytes);
    let font_b64 = general_purpose::STANDARD.encode(font_bytes);
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>tenby10 Local Dashboard</title>
    <link rel="icon" type="image/png" href="data:image/png;base64,{favicon_b64}">
    <style>
        @font-face {
            font-family: 'Outfit';
            src: url('data:font/woff2;base64,{font_b64}') format('woff2');
            font-weight: 300 800;
            font-style: normal;
            font-display: swap;
        }
        @keyframes pulse {
            0% { opacity: 0.6; }
            50% { opacity: 0.3; }
            100% { opacity: 0.6; }
        }
        :root {
            color-scheme: dark;
            --bg-base: #0f111a;
            --bg-card: rgba(22, 25, 41, 0.65);
            --border-card: rgba(255, 255, 255, 0.08);
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        /* Glassmorphism Background Gradients */
        body::before {
            content: '';
            position: absolute;
            top: -20%;
            left: -20%;
            width: 80%;
            height: 80%;
            background: radial-gradient(circle, rgba(16, 185, 129, 0.08) 0%, rgba(0,0,0,0) 70%);
            z-index: -1;
            pointer-events: none;
        }

        body::after {
            content: '';
            position: absolute;
            bottom: -20%;
            right: -20%;
            width: 80%;
            height: 80%;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.08) 0%, rgba(0,0,0,0) 70%);
            z-index: -1;
            pointer-events: none;
        }

        header {
            padding: 1.5rem 3rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-card);
            backdrop-filter: blur(12px);
            background: rgba(15, 17, 26, 0.4);
            z-index: 5;
        }

        .logo-section h1 {
            font-weight: 800;
            font-size: 1.6rem;
            letter-spacing: -1px;
            color: #f3f4f6;
        }

        .logo-section h1 .logo-accent {
            color: #2dd4bf;
        }

        .logo-section p {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .status-badge {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-green);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 0.4rem 0.8rem;
            border-radius: 50px;
            font-size: 0.75rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-badge::before {
            content: '';
            width: 8px;
            height: 8px;
            background-color: var(--accent-green);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px var(--accent-green);
        }

        .branded-icon {
            width: 32px;
            height: 32px;
            object-fit: contain;
            opacity: 0.95;
            filter: drop-shadow(0 0 8px rgba(16, 185, 129, 0.3));
        }

        /* Dashboard Layout */
        main {
            flex: 1;
            max-width: 1450px;
            width: 100%;
            margin: 0 auto;
            padding: 2.5rem 3rem;
            display: flex;
            gap: 2.5rem;
            flex-wrap: wrap;
        }

        .main-content {
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        /* Glassmorphism Cards */
        .glass-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 20px;
            padding: 1.8rem;
            backdrop-filter: blur(20px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
            transition: border-color 0.3s ease;
        }

        .glass-card:hover {
            border-color: rgba(255, 255, 255, 0.15);
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.8rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-desc {
            font-size: 0.82rem;
            color: var(--text-muted);
            line-height: 1.4;
            margin-bottom: 1rem;
        }

        /* Metrics grid in sidebar */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.8rem;
            margin-top: 0.5rem;
        }

        .metric-item {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 1rem 0.5rem;
            text-align: center;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .metric-value {
            font-size: 1.25rem;
            font-weight: 800;
            color: var(--accent-green);
        }

        .metric-label {
            font-size: 0.65rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* AI Scribe sidebar layout */
        .scribe-card {
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }

        .scribe-btn {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            border: none;
            color: white;
            padding: 0.8rem;
            border-radius: 10px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.25);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

        .scribe-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(16, 185, 129, 0.35);
        }

        .scribe-btn:disabled {
            background: #374151;
            color: #9ca3af;
            cursor: not-allowed;
            box-shadow: none;
        }

        .scribe-output {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--border-card);
            border-radius: 10px;
            padding: 1rem;
            font-family: inherit;
            font-size: 0.82rem;
            line-height: 1.45;
            color: #d1d5db;
            min-height: 180px;
            max-height: 250px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
        }

        .scribe-output::-webkit-scrollbar {
            width: 6px;
        }
        .scribe-output::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
        }
        .scribe-output::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }
        .scribe-output::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        /* Collapsible Day Sections */
        .day-section {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            overflow: hidden;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(20px);
            transition: border-color 0.3s ease;
        }

        .day-section:hover {
            border-color: rgba(255, 255, 255, 0.15);
        }

        .day-header {
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
            cursor: pointer;
            user-select: none;
        }

        .day-header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .day-title {
            font-size: 1.15rem;
            font-weight: 800;
            letter-spacing: -0.5px;
        }

        .day-badges {
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .badge {
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 600;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .badge-focus {
            background: rgba(255, 255, 255, 0.03);
        }
        .badge-focus.green {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-green);
            border-color: rgba(16, 185, 129, 0.2);
        }
        .badge-focus.yellow {
            background: rgba(245, 158, 11, 0.1);
            color: var(--accent-yellow);
            border-color: rgba(245, 158, 11, 0.2);
        }
        .badge-focus.red {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-red);
            border-color: rgba(239, 68, 68, 0.2);
        }

        .badge-time {
            background: rgba(59, 130, 246, 0.1);
            color: #3b82f6;
            border-color: rgba(59, 130, 246, 0.2);
        }

        .toggle-icon {
            font-size: 0.8rem;
            color: var(--text-muted);
            transition: transform 0.3s ease;
            margin-left: 0.3rem;
            display: inline-block;
        }

        .day-section.expanded .toggle-icon {
            transform: rotate(90deg);
        }

        /* 24x6 Tabular Grid */
        .day-content {
            display: none;
            padding: 1.5rem;
            border-top: 1px solid var(--border-card);
            background: rgba(0, 0, 0, 0.12);
            overflow-x: auto;
        }

        .day-section.expanded .day-content {
            display: block;
        }

        .day-grid-container {
            min-width: 820px;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .hour-row {
            display: grid;
            grid-template-columns: 100px repeat(6, 1fr);
            gap: 0.8rem;
            align-items: stretch;
        }

        .grid-headers {
            border-bottom: 1px solid var(--border-card);
            padding-bottom: 0.5rem;
            margin-bottom: 0.8rem;
            font-size: 0.75rem;
            font-weight: 800;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .hour-label-header {
            padding-left: 0.5rem;
        }

        .col-header {
            text-align: center;
        }

        .hour-label {
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-muted);
            padding-left: 0.5rem;
        }

        /* Compact Slot Card styling */
        .slot-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-card);
            border-radius: 10px;
            padding: 0.6rem 0.8rem;
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
            position: relative;
            overflow: hidden;
            transition: all 0.2s ease;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.15);
            height: 145px;
            justify-content: space-between;
        }

        .slot-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }

        .slot-card.green::before { background-color: var(--accent-green); }
        .slot-card.yellow::before { background-color: var(--accent-yellow); }
        .slot-card.red::before { background-color: var(--accent-red); }

        .slot-compact-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .slot-compact-min {
            font-size: 0.7rem;
            font-weight: 800;
            color: var(--text-muted);
        }

        .slot-compact-score {
            font-size: 0.9rem;
            font-weight: 800;
        }

        .slot-compact-score.green { color: var(--accent-green); }
        .slot-compact-score.yellow { color: var(--accent-yellow); }
        .slot-compact-score.red { color: var(--accent-red); }

        .slot-compact-stats {
            font-size: 0.65rem;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            min-height: 3.6rem;
            flex-grow: 1;
        }

        .view-screen-compact-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-card);
            color: var(--text-muted);
            padding: 0.25rem;
            border-radius: 4px;
            font-size: 0.65rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            text-align: center;
            transition: all 0.2s ease;
        }

        .view-screen-compact-btn:hover {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-main);
            border-color: rgba(255, 255, 255, 0.15);
        }

        /* Offline Slot Card style */
        .slot-card.offline-card {
            opacity: 0.25;
            border: 1px dashed var(--border-card);
            background: transparent;
            box-shadow: none;
            cursor: default;
        }

        .slot-card.offline-card::before {
            display: none;
        }

        .offline-text {
            font-size: 0.6rem;
            color: var(--text-muted);
            text-align: center;
            display: block;
        }

        /* 24h Hourly Heatmap Bar styling */
        .heatmap-bar {
            display: grid;
            grid-template-columns: repeat(24, 1fr);
            gap: 8px;
            margin-top: 0.4rem;
        }

        .heatmap-cell {
            aspect-ratio: 1.6;
            background: rgba(255, 255, 255, 0.04);
            border-radius: 4px;
            border: 1px solid rgba(255, 255, 255, 0.04);
            position: relative;
            cursor: pointer;
        }

        .heatmap-cell.green {
            background: var(--accent-green);
            border-color: rgba(16, 185, 129, 0.3);
        }
        .heatmap-cell.yellow {
            background: var(--accent-yellow);
            border-color: rgba(245, 158, 11, 0.3);
        }
        .heatmap-cell.red {
            background: var(--accent-red);
            border-color: rgba(239, 68, 68, 0.3);
        }

        /* Heatmap Tooltip */
        .heatmap-cell::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 135%;
            left: 50%;
            transform: translateX(-50%);
            background: #10121d;
            color: #f3f4f6;
            padding: 0.4rem 0.6rem;
            border-radius: 6px;
            font-size: 0.65rem;
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.15s, visibility 0.15s;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.6);
            border: 1px solid var(--border-card);
            pointer-events: none;
        }

        .heatmap-cell:hover::after {
            opacity: 1;
            visibility: visible;
        }

        .heatmap-labels {
            display: flex;
            justify-content: space-between;
            font-size: 0.65rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
            padding: 0 2px;
        }

        .empty-timeline {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        /* Native dialog styling for blurred screenshots */
        .glass-dialog {
            background: rgba(15, 17, 26, 0.95);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            padding: 1.5rem;
            max-width: min(1000px, 95vw);
            max-height: 85vh;
            margin: auto;
            backdrop-filter: blur(20px);
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7);
            color: var(--text-main);
        }

        .glass-dialog::backdrop {
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(8px);
        }

        .dialog-content {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .dialog-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .dialog-header h3 {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .close-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 1.4rem;
            cursor: pointer;
        }

        .close-btn:hover {
            color: var(--text-main);
        }

        #screenshot-img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            border: 1px solid var(--border-card);
        }

        /* Two-column layout in dialog */
        .dialog-body-grid {
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            gap: 1.5rem;
            margin-top: 1rem;
        }
        @media (max-width: 768px) {
            .dialog-body-grid {
                grid-template-columns: 1fr;
            }
        }
        .dialog-details-container {
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
            max-height: 480px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }
        .dialog-details-container::-webkit-scrollbar {
            width: 6px;
        }
        .dialog-details-container::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
        }
        .dialog-details-container::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }
        .dialog-details-container::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        .detail-item-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-card);
            border-radius: 8px;
            padding: 0.6rem 0.8rem;
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
            transition: border-color 0.2s ease;
        }
        .detail-item-card:hover {
            border-color: rgba(255, 255, 255, 0.12);
        }
        .detail-item-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .detail-item-time {
            font-size: 0.75rem;
            font-weight: 800;
            color: var(--accent-green);
        }
        .detail-item-inputs {
            font-size: 0.7rem;
            color: var(--text-muted);
        }
        .detail-item-app {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-main);
        }
        .detail-item-title {
            font-size: 0.75rem;
            color: var(--text-muted);
            word-break: break-word;
            line-height: 1.3;
        }

        /* Navigation and Day View Styles */
        .nav-btn {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-card);
            color: var(--text-main);
            padding: 0.55rem 1.1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .nav-btn:hover:not(:disabled) {
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(255, 255, 255, 0.15);
        }
        .nav-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        .distracted-card {
            background: repeating-linear-gradient(
                -45deg,
                rgba(239, 68, 68, 0.05),
                rgba(239, 68, 68, 0.05) 10px,
                rgba(0, 0, 0, 0.15) 10px,
                rgba(0, 0, 0, 0.15) 20px
            ) !important;
            border-color: rgba(239, 68, 68, 0.3) !important;
        }
        .custom-date-picker {
            background: rgba(15, 17, 26, 0.6);
            border: 1px solid var(--border-card);
            color: var(--text-main);
            padding: 0.5rem 0.8rem;
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.85rem;
            font-weight: 600;
            outline: none;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .custom-date-picker:focus {
            border-color: var(--accent-green);
            box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.15);
        }
        ::-webkit-calendar-picker-indicator {
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="15" viewBox="0 0 24 24"><path fill="%23ffffff" d="M20 3h-1V1h-2v2H7V1H5v2H4c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 18H4V8h16v13z"/></svg>');
            cursor: pointer;
        }
        .day-view-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 20px;
            padding: 2rem;
            backdrop-filter: blur(20px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
            margin-top: 1rem;
        }
        .day-view-header-detail {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2.5rem;
            position: sticky;
            top: 0;
            z-index: 20;
            background: rgba(15, 17, 26, 0.85); /* Slightly transparent to see scroll */
            padding: 1rem 1rem;
            margin: -1rem -1rem 2.5rem -1rem;
            border-radius: 12px;
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-card);
        }
        .day-view-title-group {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }
        .day-view-title {
            font-size: 1.4rem;
            font-weight: 800;
            letter-spacing: -0.5px;
        }
        .day-view-meta {
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        .day-view-badges {
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }
        
        .view-tab.active {
            background: rgba(255,255,255,0.1) !important;
            color: var(--text-main) !important;
        }
        .view-tab {
            color: var(--text-muted) !important;
        }
        
        .month-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 10px;
            margin-top: 1rem;
        }
        .month-day-cell {
            aspect-ratio: 1;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 0.5rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .month-day-cell:hover {
            border-color: rgba(255,255,255,0.2);
            transform: translateY(-2px);
        }
        .month-day-header {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            font-weight: 800;
        }
        .month-day-stats {
            font-size: 0.7rem;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .month-day-cell.green { border-bottom: 3px solid var(--accent-green); }
        .month-day-cell.yellow { border-bottom: 3px solid var(--accent-yellow); }
        .month-day-cell.red { border-bottom: 3px solid var(--accent-red); }
        
        .week-day-header {
            text-align: center;
            font-size: 0.8rem;
            font-weight: 800;
            color: var(--text-muted);
            padding-bottom: 0.5rem;
        }
    </style>
</head>
<body>

    <header>
        <div class="logo-section" style="display: flex; align-items: center; gap: 1rem;">
            <img src="data:image/png;base64,{logo_b64}" alt="tenby10 icon" class="branded-icon" />
            <div>
                <h1>tenby<span class="logo-accent">10</span></h1>
                <p>Privacy-First local productivity ledger</p>
            </div>
        </div>
        <div style="display: flex; gap: 1rem; align-items: center;">
            <button class="nav-btn" onclick="openExportModal()">📥 Export Data</button>
            <div class="status-badge">Active Local Agent</div>
        </div>
    </header>

    <main style="width: 100%; max-width: 1400px; margin: 0 auto; padding: 2.5rem; display: flex; flex-direction: column; gap: 2rem;">
        <!-- Top Metrics Row -->
        <div style="display: flex; gap: 2rem; width: 100%;">
            <div class="glass-card" style="flex: 1; display: flex; justify-content: space-between; align-items: center; padding: 1.2rem 2.5rem;">
                <div class="metric-item" style="border: none; background: transparent; padding: 0;">
                    <span class="metric-value" id="stat-billable" style="font-size: 3rem; color: var(--accent-green);">-</span>
                    <span class="metric-label" id="label-billable" style="font-size: 1rem;">Billable Today</span>
                    <span class="metric-hint" id="hint-billable" style="font-size: 0.72rem; color: var(--text-muted);">&nbsp;</span>
                </div>
                <div class="metric-item" style="border: none; background: transparent; padding: 0;">
                    <span class="metric-value" id="stat-avg-focus" style="font-size: 2.5rem;">-</span>
                    <span class="metric-label" id="label-avg-focus" style="font-size: 1rem;">Avg Focus</span>
                    <span class="metric-hint" id="hint-avg-focus" style="font-size: 0.72rem; color: var(--text-muted);">&nbsp;</span>
                </div>
                <div class="metric-item" style="border: none; background: transparent; padding: 0;">
                    <span class="metric-value" id="stat-days-tracked" style="font-size: 2.5rem;">-</span>
                    <span class="metric-label" id="label-days-tracked" style="font-size: 1rem;">Days Run</span>
                    <span class="metric-hint" id="hint-days-tracked" style="font-size: 0.72rem; color: var(--text-muted);">&nbsp;</span>
                </div>
            </div>
        </div>

        <div class="main-content">
            <!-- Day Navigation Controls -->
            <div class="day-navigation" style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 16px; padding: 1rem 1.5rem; backdrop-filter: blur(20px); flex-wrap: wrap; gap: 1rem;">
                <div style="display: flex; gap: 1rem; align-items: center;">
                    <div style="display: flex; background: rgba(0,0,0,0.2); border-radius: 8px; padding: 2px;">
                        <button class="nav-btn view-tab" id="tab-monthly" onclick="switchView('monthly')" style="padding: 0.4rem 1rem; border: none; background: transparent;">Monthly</button>
                        <button class="nav-btn view-tab" id="tab-weekly" onclick="switchView('weekly')" style="padding: 0.4rem 1rem; border: none; background: transparent;">Weekly</button>
                        <button class="nav-btn view-tab active" id="tab-daily" onclick="switchView('daily')" style="padding: 0.4rem 1rem; border: none; background: transparent;">Daily</button>
                    </div>
                    <div style="display: flex; gap: 0.8rem;">
                        <button class="nav-btn" id="prev-day-btn" onclick="prevDay()">◀ Prev</button>
                        <button class="nav-btn" id="next-day-btn" onclick="nextDay()">Next ▶</button>
                    </div>
                </div>
                
                <div style="display: flex; align-items: center; gap: 1.5rem;">
                    <div id="week-start-container" style="display: flex; align-items: center; gap: 0.5rem; display: none;">
                        <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 600;">Week Start:</span>
                        <select id="week-start-select" onchange="updateWeekStart(this.value)" class="custom-date-picker" style="padding: 0.3rem 0.5rem; font-size: 0.75rem;">
                            <option value="1">Monday</option>
                            <option value="0">Sunday</option>
                        </select>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.8rem;">
                        <a href="javascript:void(0)" id="today-btn" onclick="navigateToToday()" style="font-size: 0.8rem; color: var(--accent-green); text-decoration: none; font-weight: 600; padding: 0.3rem 0.5rem; border-radius: 4px; background: rgba(16, 185, 129, 0.1);">Today</a>
                        <span id="date-picker-label" style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">Select Date:</span>
                        <input type="date" id="date-picker" onchange="datePickerChanged(this)" class="custom-date-picker" />
                    </div>
                </div>
            </div>

            <!-- Standalone Day Grid Card -->
            <div class="day-view-card" id="day-view-container">
                <div class="empty-timeline">Fetching database records...</div>
            </div>
            
            <div class="day-view-card" id="week-view-container" style="display: none;">
            </div>

            <div class="day-view-card" id="month-view-container" style="display: none;">
            </div>
        </div>

        <!-- Legend / Help Card moved to bottom -->
        <div class="glass-card" style="margin-top: 2rem;">
            <h2 class="section-title">💡 System Legend</h2>
            <div class="help-content" style="display:flex; flex-direction:column; gap:0.65rem; font-size:0.75rem; line-height:1.4;">
                <div style="display:flex; gap:8px; align-items:flex-start;">
                    <span class="badge" style="background:transparent; border:1px dashed var(--border-card); color:var(--text-muted); padding:1px 3px; font-size:0.6rem; min-width:55px; text-align:center;">Offline</span>
                    <p style="color:var(--text-muted); margin-top:2px;"><b>No telemetry:</b> The daemon was stopped, app closed, or computer asleep.</p>
                </div>
                <div style="display:flex; gap:8px; align-items:flex-start;">
                    <span class="badge badge-focus red" style="padding:1px 3px; font-size:0.6rem; min-width:55px; text-align:center;">Idle</span>
                    <p style="color:var(--text-muted); margin-top:2px;"><b>0% Focus:</b> Telemetry was active, but absolutely no user input (keystrokes or clicks) was registered.</p>
                </div>
                <div style="display:flex; gap:8px; align-items:flex-start;">
                    <span class="badge" style="background:rgba(59, 130, 246, 0.2); color:var(--accent-blue); border:1px solid rgba(59, 130, 246, 0.3); padding:1px 3px; font-size:0.6rem; min-width:55px; text-align:center;">Meeting</span>
                    <p style="color:var(--text-muted); margin-top:2px;"><b>100% Focus:</b> No inputs were registered, but the active window matched your Meeting Keywords.</p>
                </div>
                <div style="display:flex; gap:8px; align-items:flex-start;">
                    <span class="badge badge-focus red" style="padding:1px 3px; font-size:0.6rem; min-width:55px; text-align:center; background: repeating-linear-gradient(-45deg, rgba(239, 68, 68, 0.15), rgba(239, 68, 68, 0.15) 5px, transparent 5px, transparent 10px);">Distracted</span>
                    <p style="color:var(--text-muted); margin-top:2px;"><b>0% Focus:</b> Active user input was detected, but entirely within blacklisted applications.</p>
                </div>
            </div>
        </div>
    </main>

    <!-- Native screenshot & details modal dialog -->
    <dialog id="screenshot-dialog" class="glass-dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h3 id="dialog-slot-title">Slot Details</h3>
                <button class="close-btn" onclick="closeScreenshotDialog()">✕</button>
            </div>
            <div class="dialog-body-grid">
                <!-- Left: Screenshot -->
                <div style="display: flex; flex-direction: column; gap: 0.5rem; flex: 1.2;">
                    <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px;">Screen Capture</h4>
                    <img id="screenshot-img" src="" alt="Blurred Screen Capture" />
                </div>
                <!-- Right: Activity Details -->
                <div style="display: flex; flex-direction: column; gap: 0.5rem; flex: 1;">
                    <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px;">Minute-by-Minute Activity</h4>
                    <div id="dialog-llm-reasoning"></div>
                    <div class="dialog-details-container" id="dialog-details-list">
                        <div style="color: var(--text-muted); font-size: 0.8rem;">Loading activity details...</div>
                    </div>
                </div>
            </div>
        </div>
    </dialog>



    <!-- Export Modal -->
    <dialog id="export-dialog" class="glass-dialog" style="width: 450px;">
        <div class="dialog-content">
            <div class="dialog-header">
                <h3>Export Telemetry Data</h3>
                <button class="close-btn" onclick="closeExportModal()">✕</button>
            </div>
            <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 1rem;">
                <p style="font-size: 0.85rem; color: var(--text-muted);">Export a CSV containing your unaggregated, minute-by-minute telemetry logs.</p>
                
                <div style="display: flex; flex-direction: column; gap: 0.8rem; margin-top: 0.5rem;">
                    <label style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">Time Range</label>
                    <select id="export-range" onchange="document.getElementById('custom-range-inputs').style.display = this.value === 'custom' ? 'flex' : 'none'" class="custom-date-picker" style="width: 100%; padding: 0.5rem; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); color: var(--text-primary); border-radius: 4px;">
                        <option value="24h">Last 24 Hours</option>
                        <option value="7d">Last 7 Days</option>
                        <option value="30d">Last 30 Days (1 Month)</option>
                        <option value="all">All Time</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </div>
                
                <div id="custom-range-inputs" style="display: none; flex-direction: column; gap: 0.8rem; margin-top: 0.2rem;">
                    <div style="display: flex; gap: 1rem;">
                        <div style="flex: 1;">
                            <label style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600; display: block; margin-bottom: 0.3rem;">Start Date</label>
                            <input type="date" id="export-start" class="custom-date-picker" style="width: 100%; padding: 0.5rem; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); color: var(--text-primary); border-radius: 4px;">
                        </div>
                        <div style="flex: 1;">
                            <label style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600; display: block; margin-bottom: 0.3rem;">End Date</label>
                            <input type="date" id="export-end" class="custom-date-picker" style="width: 100%; padding: 0.5rem; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); color: var(--text-primary); border-radius: 4px;">
                        </div>
                    </div>
                </div>
                
                <button class="scribe-btn" id="export-btn" onclick="exportCsv()" style="margin-top: 0.5rem;">
                    <span>Download CSV</span>
                </button>
            </div>
        </div>
    </dialog>

    <script>
        let globalSlots = [];
        let daysMap = {};
        let availableDates = [];
        let currentDateKey = null;
        let currentViewMode = 'daily';
        let weekStartDay = parseInt(localStorage.getItem('weekStartDay') || '1', 10); // 1 = Monday, 0 = Sunday

        // Fetch dashboard data
        async function fetchDashboardData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                
                const pendingResponse = await fetch('/api/pending');
                const pendingData = await pendingResponse.json();
                
                globalSlots = data.slots;
                
                if (pendingData.pending_slots) {
                    pendingData.pending_slots.forEach(slotStart => {
                        globalSlots.push({
                            slot_start: slotStart,
                            is_pending: true,
                            focus_score: 0,
                            active_segments: 0,
                            idle_segments: 0,
                            total_keystrokes: 0,
                            total_clicks: 0,
                            app_categories: {},
                        });
                    });
                }
                
                processSlots();
                
                // Determine initial date
                const urlParams = getParamsFromUrl();
                if (urlParams.date) {
                    currentDateKey = urlParams.date;
                } else if (availableDates.length > 0) {
                    // Default to the most recent date with data
                    currentDateKey = availableDates[availableDates.length - 1];
                } else {
                    // Fallback to today's date in YYYY-MM-DD local format
                    const today = new Date();
                    const year = today.getFullYear();
                    const month = String(today.getMonth() + 1).padStart(2, '0');
                    const day = String(today.getDate()).padStart(2, '0');
                    currentDateKey = `${year}-${month}-${day}`;
                }
                
                if (urlParams.tab) {
                    currentViewMode = urlParams.tab;
                }
                
                document.getElementById('week-start-select').value = weekStartDay.toString();
                
                document.querySelectorAll('.view-tab').forEach(el => el.classList.remove('active'));
                const activeTab = document.getElementById(`tab-${currentViewMode}`);
                if (activeTab) activeTab.classList.add('active');
                
                document.getElementById('day-view-container').style.display = currentViewMode === 'daily' ? 'block' : 'none';
                document.getElementById('week-view-container').style.display = currentViewMode === 'weekly' ? 'block' : 'none';
                document.getElementById('month-view-container').style.display = currentViewMode === 'monthly' ? 'block' : 'none';
                
                renderCurrentView();
            } catch (err) {
                console.error("Error fetching dashboard data", err);
                document.getElementById('day-view-container').innerHTML = 
                    `<div class="empty-timeline">Failed to load data. Confirm SQLite has logged active hours.</div>`;
            }
        }

        function processSlots() {
            daysMap = {};
            globalSlots.forEach(slot => {
                const date = new Date(slot.slot_start * 1000);
                const year = date.getFullYear();
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                const dateKey = `${year}-${month}-${day}`;
                
                if (!daysMap[dateKey]) {
                    daysMap[dateKey] = {
                        dateKey: dateKey,
                        formattedDate: date.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
                        slots: [],
                        totalActiveSegments: 0,
                        // A slot is "logged" iff it holds >=1 productive minute (focus_score > 0).
                        // Active time = totalLoggedSlots * 10, so it reconstructs by counting
                        // 10-minute slots and matches the fat client's get_today_metrics exactly.
                        totalLoggedSlots: 0,
                        sumFocusScore: 0,
                    };
                }
                const entry = daysMap[dateKey];
                entry.slots.push(slot);
                entry.totalActiveSegments += slot.active_segments;
                if (slot.focus_score > 0) entry.totalLoggedSlots += 1;
                entry.sumFocusScore += slot.focus_score;
            });

            availableDates = Object.keys(daysMap).sort();
        }

        function getParamsFromUrl() {
            const params = new URLSearchParams(window.location.search);
            return {
                date: params.get('date'),
                tab: params.get('tab')
            };
        }

        function updateUrl() {
            const newUrl = window.location.protocol + "//" + window.location.host + window.location.pathname + '?date=' + currentDateKey + '&tab=' + currentViewMode;
            window.history.pushState({ path: newUrl }, '', newUrl);
        }

        function updateWeekStart(val) {
            weekStartDay = parseInt(val, 10);
            localStorage.setItem('weekStartDay', weekStartDay);
            renderCurrentView();
        }

        function switchView(mode) {
            currentViewMode = mode;
            document.querySelectorAll('.view-tab').forEach(el => el.classList.remove('active'));
            const activeTab = document.getElementById(`tab-${mode}`);
            if (activeTab) activeTab.classList.add('active');
            
            document.getElementById('day-view-container').style.display = mode === 'daily' ? 'block' : 'none';
            document.getElementById('week-view-container').style.display = mode === 'weekly' ? 'block' : 'none';
            document.getElementById('month-view-container').style.display = mode === 'monthly' ? 'block' : 'none';
            
            const todayBtn = document.getElementById('today-btn');
            const dateLabel = document.getElementById('date-picker-label');
            const datePicker = document.getElementById('date-picker');
            const weekStartContainer = document.getElementById('week-start-container');
            
            if (mode === 'daily') {
                todayBtn.innerText = 'Today';
                dateLabel.innerText = 'Select Date:';
                datePicker.type = 'date';
                weekStartContainer.style.display = 'none';
            } else if (mode === 'weekly') {
                todayBtn.innerText = 'This Week';
                dateLabel.innerText = 'Jump to Week of:';
                datePicker.type = 'date';
                weekStartContainer.style.display = 'flex';
            } else if (mode === 'monthly') {
                todayBtn.innerText = 'This Month';
                dateLabel.innerText = 'Select Month:';
                datePicker.type = 'month';
                weekStartContainer.style.display = 'flex';
            }
            
            updateUrl();
            renderCurrentView();
        }

        function navigateToDate(dateStr) {
            currentDateKey = dateStr;
            updateUrl();
            renderCurrentView();
        }

        function navigateToToday() {
            const today = new Date();
            const year = today.getFullYear();
            const month = String(today.getMonth() + 1).padStart(2, '0');
            const day = String(today.getDate()).padStart(2, '0');
            navigateToDate(`${year}-${month}-${day}`);
        }

        function stepDate(amount, unit) {
            const dateParts = currentDateKey.split('-');
            const current = new Date(parseInt(dateParts[0]), parseInt(dateParts[1]) - 1, parseInt(dateParts[2]));
            if (unit === 'day') {
                current.setDate(current.getDate() + amount);
            } else if (unit === 'month') {
                current.setMonth(current.getMonth() + amount);
            }
            const year = current.getFullYear();
            const month = String(current.getMonth() + 1).padStart(2, '0');
            const day = String(current.getDate()).padStart(2, '0');
            navigateToDate(`${year}-${month}-${day}`);
        }

        function prevDay() {
            if (currentViewMode === 'daily') {
                stepDate(-1, 'day');
            } else if (currentViewMode === 'weekly') {
                stepDate(-7, 'day');
            } else if (currentViewMode === 'monthly') {
                stepDate(-1, 'month');
            }
        }

        function nextDay() {
            if (currentViewMode === 'daily') {
                stepDate(1, 'day');
            } else if (currentViewMode === 'weekly') {
                stepDate(7, 'day');
            } else if (currentViewMode === 'monthly') {
                stepDate(1, 'month');
            }
        }

        function datePickerChanged(input) {
            if (input.value) {
                if (currentViewMode === 'monthly') {
                    navigateToDate(`${input.value}-01`);
                } else {
                    navigateToDate(input.value);
                }
            }
        }

        function getFormattedDate(dateKey) {
            const dateParts = dateKey.split('-');
            const date = new Date(dateParts[0], dateParts[1] - 1, dateParts[2]);
            return date.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        }

        // Handle browser Back/Forward navigation
        window.addEventListener('popstate', () => {
            const urlParams = getParamsFromUrl();
            let viewChanged = false;
            
            if (urlParams.date) {
                currentDateKey = urlParams.date;
                viewChanged = true;
            }
            if (urlParams.tab) {
                currentViewMode = urlParams.tab;
                document.querySelectorAll('.view-tab').forEach(el => el.classList.remove('active'));
                const activeTab = document.getElementById(`tab-${currentViewMode}`);
                if (activeTab) activeTab.classList.add('active');
                
                document.getElementById('day-view-container').style.display = currentViewMode === 'daily' ? 'block' : 'none';
                document.getElementById('week-view-container').style.display = currentViewMode === 'weekly' ? 'block' : 'none';
                document.getElementById('month-view-container').style.display = currentViewMode === 'monthly' ? 'block' : 'none';
                
                viewChanged = true;
            }
            if (viewChanged) {
                renderCurrentView();
            }
        });

        function escapeHtml(str) {
            if (!str) return '';
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function showScreenshot(timestamp, event) {
            if (event) event.stopPropagation();
            
            // Format start and end time for title
            const date = new Date(timestamp * 1000);
            const startStr = date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            const endDate = new Date((timestamp + 600) * 1000);
            const endStr = endDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            document.getElementById('dialog-slot-title').innerText = `Slot Details: ${startStr} - ${endStr}`;
            
            const img = document.getElementById('screenshot-img');
            img.src = `/screenshots/slot_${timestamp}.jpg`;
            img.onerror = () => {
                img.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600" viewBox="0 0 800 600"><rect width="800" height="600" fill="%23141624"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="22" fill="%236b7280">No blurred screen capture saved for this slot.</text></svg>';
            };
            
            // Render LLM Reasoning if available
            const slot = globalSlots.find(s => s.slot_start === timestamp);
            if (slot && slot.llm_reasoning) {
                document.getElementById('dialog-llm-reasoning').innerHTML = `
                    <div style="margin-bottom: 0.5rem; padding: 1rem; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px;">
                        <h4 style="font-size: 0.7rem; text-transform: uppercase; color: var(--accent-green); margin-bottom: 0.5rem;">AI Auditor Reasoning</h4>
                        <p style="font-size: 0.85rem; line-height: 1.4; color: #fff;">${escapeHtml(slot.llm_reasoning)}</p>
                    </div>
                `;
            } else {
                document.getElementById('dialog-llm-reasoning').innerHTML = '';
            }

            // Fetch and render minute-by-minute logs
            const listContainer = document.getElementById('dialog-details-list');
            listContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">Loading activity details...</div>`;
            
            fetch(`/api/slot_details?start=${timestamp}`)
                .then(res => res.json())
                .then(details => {
                    if (!details || details.length === 0) {
                        listContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: 2rem 0;">No active minute logs found for this slot.</div>`;
                        return;
                    }
                    
                    listContainer.innerHTML = details.map(item => {
                        const mDate = new Date(item.timestamp * 1000);
                        const mTimeStr = mDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
                        
                        let warningBadge = '';
                        if (item.low_entropy) {
                            warningBadge = `<span class="badge badge-focus red" style="font-size:0.6rem; padding: 1px 4px; margin-left: 6px;">⚠️ Tamper Flag</span>`;
                        }
                        
                        let stateColor = item.state === 'Productive' ? 'rgba(16, 185, 129, 0.2)' : 
                                         item.state === 'Meeting' ? 'rgba(59, 130, 246, 0.2)' :
                                         item.state === 'Waste' ? 'rgba(239, 68, 68, 0.2)' : 
                                         'rgba(156, 163, 175, 0.1)';
                        let stateText = item.state === 'Productive' ? 'var(--accent-green)' : 
                                        item.state === 'Meeting' ? 'var(--accent-blue)' :
                                        item.state === 'Waste' ? 'var(--accent-red)' : 
                                        'var(--text-muted)';
                        
                        return `
                            <div class="detail-item-card" style="border-left: 3px solid ${stateText};">
                                <div class="detail-item-meta" style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                                    <div>
                                        <span class="detail-item-time">${mTimeStr}${warningBadge}</span>
                                        <span class="badge" style="background: ${stateColor}; color: ${stateText}; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; margin-left: 8px;">${item.state}</span>
                                    </div>
                                    <span class="detail-item-inputs">Keys: ${item.keystroke_count} | Clicks: ${item.mouse_click_count} | Scrolls: ${item.scroll_event_count}</span>
                                </div>
                                <div class="detail-item-app">${escapeHtml(item.active_app_name)}</div>
                                <div class="detail-item-title">${escapeHtml(item.active_window_title)}</div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(err => {
                    console.error("Error fetching slot details:", err);
                    listContainer.innerHTML = `<div style="color: var(--accent-red); font-size: 0.8rem; text-align: center; padding: 2rem 0;">Failed to load activity details.</div>`;
                });
            
            const dialog = document.getElementById('screenshot-dialog');
            dialog.showModal();
        }

        function closeScreenshotDialog() {
            const dialog = document.getElementById('screenshot-dialog');
            dialog.close();
        }

        // Close modal dialog on backdrop click
        document.getElementById('screenshot-dialog').addEventListener('click', function(e) {
            if (e.target === this) {
                closeScreenshotDialog();
            }
        });

        function updateLifetimeStats() {
            if (!globalSlots || globalSlots.length === 0) {
                document.getElementById('stat-billable').innerText = '-';
                document.getElementById('stat-avg-focus').innerText = '-';
                document.getElementById('stat-days-tracked').innerText = '-';
                document.getElementById('hint-billable').innerHTML = '&nbsp;';
                document.getElementById('hint-avg-focus').innerHTML = '&nbsp;';
                document.getElementById('hint-days-tracked').innerHTML = '&nbsp;';
                return;
            }

            let sumFocus = 0;
            let countSlots = 0;
            let billableSlots = 0;
            let daysRun = 0;

            let labelBillable = 'Billable';
            let labelFocus = 'Avg Focus';
            let labelDays = 'Days Run';
            
            let relevantDays = [];
            
            if (currentViewMode === 'daily') {
                if (daysMap[currentDateKey]) relevantDays.push(daysMap[currentDateKey]);
                labelBillable = 'Billable Today';
                labelFocus = 'Focus Today';
                labelDays = 'Logged Slots';
            } else if (currentViewMode === 'weekly') {
                const start = getStartOfWeek(currentDateKey);
                for (let i = 0; i < 7; i++) {
                    const d = new Date(start);
                    d.setDate(d.getDate() + i);
                    const y = d.getFullYear();
                    const m = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    const key = `${y}-${m}-${day}`;
                    if (daysMap[key]) relevantDays.push(daysMap[key]);
                }
                labelBillable = 'Billable This Week';
                labelFocus = 'Focus This Week';
                labelDays = 'Active Days';
            } else if (currentViewMode === 'monthly') {
                const parts = currentDateKey.split('-');
                const y = parts[0];
                const m = parts[1];
                for (let d = 1; d <= 31; d++) {
                    const key = `${y}-${m}-${String(d).padStart(2, '0')}`;
                    if (daysMap[key]) relevantDays.push(daysMap[key]);
                }
                labelBillable = 'Billable This Month';
                labelFocus = 'Focus This Month';
                labelDays = 'Active Days';
            }
            
            relevantDays.forEach(day => {
                let dayHasSlots = false;
                day.slots.forEach(slot => {
                    // Logged slot: at least one productive minute (focus_score > 0).
                    if (slot.focus_score > 0) {
                        sumFocus += slot.focus_score;
                        countSlots += 1;
                        dayHasSlots = true;
                        // Billable slot: cleared the focus gate (>= 40, ADR 0012).
                        // Same rule as the fat client's billable hero.
                        if (slot.focus_score >= 40) billableSlots += 1;
                    }
                });
                if (dayHasSlots) daysRun += 1;
            });

            const avgFocus = countSlots > 0 ? Math.round(sumFocus / countSlots) : 0;
            // Hero metric = billable time, identical rule to the fat client:
            // billable slots (focus >= 40) x 10 minutes.
            const billableMins = billableSlots * 10;
            const bHours = Math.floor(billableMins / 60);
            const bMins = billableMins % 60;

            document.getElementById('stat-billable').innerText = billableMins > 0 ? (bHours > 0 ? `${bHours}h ${bMins}m` : `${bMins}m`) : (countSlots > 0 ? '0m' : '-');
            document.getElementById('stat-avg-focus').innerText = countSlots > 0 ? `${avgFocus}%` : '-';
            document.getElementById('stat-days-tracked').innerText = currentViewMode === 'daily' ? (countSlots > 0 ? countSlots : '-') : (daysRun > 0 ? daysRun : '-');

            document.getElementById('label-billable').innerText = labelBillable;
            document.getElementById('label-avg-focus').innerText = labelFocus;
            document.getElementById('label-days-tracked').innerText = labelDays;

            // Make the slot basis explicit. The billable hero's sub-line reports the
            // logged-slot count (matching the fat client's "N slots logged today");
            // focus averages over those same logged slots.
            const slotWord = countSlots === 1 ? 'slot' : 'slots';
            document.getElementById('hint-billable').innerHTML =
                countSlots > 0 ? `${countSlots} ${slotWord} logged` : '&nbsp;';
            document.getElementById('hint-avg-focus').innerHTML =
                countSlots > 0 ? `over ${countSlots} logged ${slotWord}` : '&nbsp;';
            // Daily: the value already IS the slot count, so clarify each is 10 min.
            // Weekly/monthly: the value is days, so annotate the total logged slots.
            document.getElementById('hint-days-tracked').innerHTML = currentViewMode === 'daily'
                ? (countSlots > 0 ? '10 min each' : '&nbsp;')
                : (countSlots > 0 ? `${countSlots} logged ${slotWord}` : '&nbsp;');
        }

        function renderCurrentView() {
            if (currentViewMode === 'daily') {
                renderDayView();
            } else if (currentViewMode === 'weekly') {
                renderWeeklyView();
            } else if (currentViewMode === 'monthly') {
                renderMonthlyView();
            }
        }

        function renderDayView() {
            const container = document.getElementById('day-view-container');
            const datePicker = document.getElementById('date-picker');
            datePicker.value = currentDateKey;

            const prevBtn = document.getElementById('prev-day-btn');
            const nextBtn = document.getElementById('next-day-btn');

            updateLifetimeStats();

            const day = daysMap[currentDateKey];
            
            // If there's no data for the day, render an empty/offline state
            if (!day || day.slots.length === 0) {
                renderEmptyDayView(currentDateKey);
                return;
            }

            let daySumFocus = 0;
            let dayCountSlots = 0;
            day.slots.forEach(slot => {
                // Logged slot: at least one productive minute (focus_score > 0).
                if (slot.focus_score > 0) {
                    daySumFocus += slot.focus_score;
                    dayCountSlots += 1;
                }
            });

            const avgFocus = dayCountSlots > 0 ? Math.round(daySumFocus / dayCountSlots) : 0;
            const activeMins = day.totalLoggedSlots * 10;
            const hours = Math.floor(activeMins / 60);
            const mins = activeMins % 60;
            const activeTimeStr = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
            
            let focusColorClass = 'red';
            if (avgFocus >= 80) focusColorClass = 'green';
            else if (avgFocus >= 40) focusColorClass = 'yellow';

            const dayParts = currentDateKey.split('-');
            const dayStart = new Date(dayParts[0], dayParts[1] - 1, dayParts[2]);
            dayStart.setHours(0, 0, 0, 0);
            const dayStartSecs = Math.floor(dayStart.getTime() / 1000);

            // Render Hourly Heatmap row (24 columns)
            const heatmapCells = Array(24).fill(null).map((_, hour) => {
                const ampm = hour >= 12 ? 'PM' : 'AM';
                const displayHour = hour % 12 === 0 ? 12 : hour % 12;
                const hourStr = `${displayHour} ${ampm}`;
                
                let sliversHtml = '';
                let activeCount = 0;
                let sumScore = 0;
                let isPending = false;
                let hasAnySlot = false;

                for (let c = 0; c < 6; c++) {
                    const targetStart = dayStartSecs + (hour * 3600) + (c * 600);
                    const slot = day.slots.find(s => s.slot_start === targetStart);

                    if (!slot) {
                        sliversHtml += `<div style="flex:1; border-radius:1px; background: rgba(255,255,255,0.06);"></div>`;
                    } else if (slot.is_pending) {
                        isPending = true;
                        hasAnySlot = true;
                        sliversHtml += `<div style="flex:1; border-radius:1px; opacity:0.6; background: repeating-linear-gradient(-45deg, rgba(255,255,255,0.1), rgba(255,255,255,0.1) 2px, transparent 2px, transparent 4px);"></div>`;
                    } else {
                        hasAnySlot = true;
                        activeCount++;
                        sumScore += slot.focus_score;
                        let bgColor = 'var(--accent-red)';
                        if (slot.focus_score >= 80) bgColor = 'var(--accent-green)';
                        else if (slot.focus_score >= 40) bgColor = 'var(--accent-yellow)';
                        sliversHtml += `<div style="flex:1; border-radius:1px; background: ${bgColor};"></div>`;
                    }
                }
                
                let tooltipStr = `${hourStr} - Offline`;
                if (activeCount > 0) {
                    const avgScore = Math.round(sumScore / activeCount);
                    tooltipStr = `${hourStr} - Avg Focus: ${avgScore}%`;
                } else if (isPending) {
                    tooltipStr = `${hourStr} - Ongoing`;
                } else if (hasAnySlot) {
                    tooltipStr = `${hourStr} - Idle`;
                }
                
                return `<div class="heatmap-cell" onclick="document.getElementById('hour-row-${currentDateKey}-${hour}').scrollIntoView({behavior: 'smooth'})" style="cursor:pointer; display:flex; gap:2px; padding:3px;" data-tooltip="${tooltipStr}">
                    ${sliversHtml}
                </div>`;
            }).join('');

            let hourRowsHtml = '';
            for (let h = 0; h < 24; h++) {
                const ampm = h >= 12 ? 'PM' : 'AM';
                const displayHour = h % 12 === 0 ? 12 : h % 12;
                const hourLabelStr = `${String(displayHour).padStart(2, '0')}:00 ${ampm}`;
                
                let slotsInHourHtml = '';

                for (let c = 0; c < 6; c++) {
                    const targetStart = dayStartSecs + (h * 3600) + (c * 600);
                    const slot = day.slots.find(s => s.slot_start === targetStart);

                    if (slot) {
                        if (slot.is_pending) {
                            slotsInHourHtml += `
                                <div class="slot-card compact-card" style="opacity: 0.6; border-style: dashed; animation: pulse 2s infinite;">
                                    <div class="slot-compact-header">
                                        <span class="slot-compact-min">:${c * 10}</span>
                                        <span class="slot-compact-score" style="color: var(--text-muted);">...</span>
                                    </div>
                                    <div style="flex-grow: 1; display: flex; align-items: center; justify-content: center;">
                                        <span class="offline-text" style="color: var(--text-primary);">Evaluating...</span>
                                    </div>
                                </div>
                            `;
                        } else {
                            const slotScore = slot.focus_score;
                            let slotColorClass = 'red';
                            if (slotScore >= 80) slotColorClass = 'green';
                            else if (slotScore >= 40) slotColorClass = 'yellow';

                            const categoriesTooltip = Object.entries(slot.app_categories || {})
                                .map(([cat, count]) => `${cat}: ${count}m`)
                                .join(', ') || 'No apps logged';
                                
                            const categoriesList = Object.entries(slot.app_categories || {})
                                .sort((a, b) => b[1] - a[1])
                                .map(([cat, count]) => `<span style="background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:4px;">${cat}: ${count}m</span>`)
                                .join('');

                            let statsHtml = categoriesList 
                                ? `<div style="font-size: 0.75rem; color: var(--text-muted); display:flex; flex-direction:column; align-items:flex-start; gap:4px; margin-top:2px;">${categoriesList}</div>` 
                                : `<span style="color:var(--text-muted); font-size: 0.75rem;">No apps logged</span>`;
                            
                            let isDistracted = false;

                            if (slotScore === 0 && !(slot.total_keystrokes === 0 && slot.total_clicks === 0)) {
                                isDistracted = true;
                            }
                            
                            let extraClasses = isDistracted ? ' distracted-card' : '';

                            slotsInHourHtml += `
                                <div class="slot-card compact-card ${slotColorClass}${extraClasses}" title="${categoriesTooltip}">
                                    <div class="slot-compact-header">
                                        <span class="slot-compact-min">:${c * 10}</span>
                                        <span class="slot-compact-score ${slotColorClass}">${slotScore}%</span>
                                    </div>
                                    <div class="slot-compact-stats">
                                        ${statsHtml}
                                    </div>
                                    <button class="view-screen-compact-btn" onclick="showScreenshot(${slot.slot_start}, event)">
                                        🖼️ View
                                    </button>
                                </div>
                            `;
                        }
                    } else {
                        slotsInHourHtml += `
                            <div class="slot-card compact-card offline-card">
                                <div class="slot-compact-header">
                                    <span class="slot-compact-min">:${c * 10}</span>
                                    <span class="slot-compact-score" style="color: var(--text-muted);">Offline</span>
                                </div>
                                <div class="slot-compact-stats">
                                    <span>-</span>
                                    <span>-</span>
                                </div>
                                <span class="offline-text">No Telemetry</span>
                            </div>
                        `;
                    }
                }

                hourRowsHtml += `
                    <div class="hour-row" id="hour-row-${currentDateKey}-${h}">
                        <div class="hour-label">${hourLabelStr}</div>
                        ${slotsInHourHtml}
                    </div>
                `;
            }

            container.innerHTML = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">${day.formattedDate}</span>
                        <span class="day-view-meta">Productivity stats compiled locally and encrypted.</span>
                    </div>
                    <div class="day-view-badges">
                        <span class="badge badge-focus ${focusColorClass}" style="font-size:0.85rem; padding: 0.35rem 0.75rem;">${avgFocus}% Focus</span>
                        <span class="badge badge-time" style="font-size:0.85rem; padding: 0.35rem 0.75rem;">${activeTimeStr} Active (${day.totalLoggedSlots} ${day.totalLoggedSlots === 1 ? 'slot' : 'slots'})</span>
                    </div>
                </div>

                <div style="margin-bottom: 2rem; background: rgba(0,0,0,0.15); border: 1px solid var(--border-card); border-radius: 12px; padding: 1.2rem;">
                    <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.8px; margin-bottom: 0.6rem;">24-Hour Focus Heatmap</h4>
                    <div class="heatmap-bar">
                        ${heatmapCells}
                    </div>
                    <div class="heatmap-labels">
                        <span>12 AM</span>
                        <span>6 AM</span>
                        <span>12 PM</span>
                        <span>6 PM</span>
                        <span>11 PM</span>
                    </div>
                </div>

                <div class="day-grid-container">
                    <div class="hour-row grid-headers" style="position: sticky; top: 90px; z-index: 15; background: rgba(15, 17, 26, 0.85); backdrop-filter: blur(12px); padding: 0.5rem; border-radius: 8px; margin: -0.5rem -0.5rem 0.5rem -0.5rem; border-bottom: 1px solid var(--border-card);">
                        <div class="hour-label-header">Hour</div>
                        <div class="col-header">:00</div>
                        <div class="col-header">:10</div>
                        <div class="col-header">:20</div>
                        <div class="col-header">:30</div>
                        <div class="col-header">:40</div>
                        <div class="col-header">:50</div>
                    </div>
                    ${hourRowsHtml}
                </div>
            `;
        }
        
        function getStartOfWeek(dateStr) {
            const dateParts = dateStr.split('-');
            const d = new Date(parseInt(dateParts[0]), parseInt(dateParts[1]) - 1, parseInt(dateParts[2]));
            const day = d.getDay();
            const diff = d.getDate() - day + (day === 0 && weekStartDay === 1 ? -6 : weekStartDay);
            const startOfWeek = new Date(d.setDate(diff));
            return startOfWeek;
        }

        function renderWeeklyView() {
            const container = document.getElementById('week-view-container');
            
            const startOfWeek = getStartOfWeek(currentDateKey);
            const startYear = startOfWeek.getFullYear();
            const startMonth = String(startOfWeek.getMonth() + 1).padStart(2, '0');
            const startDay = String(startOfWeek.getDate()).padStart(2, '0');
            const newDateKey = `${startYear}-${startMonth}-${startDay}`;
            
            if (currentDateKey !== newDateKey) {
                currentDateKey = newDateKey;
                updateUrl();
            }

            updateLifetimeStats();
            document.getElementById('date-picker').value = currentDateKey;
            const endOfWeek = new Date(startOfWeek);
            endOfWeek.setDate(endOfWeek.getDate() + 6);
            
            const startStr = startOfWeek.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            const endStr = endOfWeek.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            
            let html = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">Week of ${startStr} - ${endStr}</span>
                        <span class="day-view-meta">Weekly aggregate productivity overview.</span>
                    </div>
                </div>
                <div class="month-grid" style="margin-top: 0;">
            `;

            const weekNamesHTML = [];
            for (let i = 0; i < 7; i++) {
                const cur = new Date(startOfWeek);
                cur.setDate(cur.getDate() + i);
                weekNamesHTML.push(`<div class="week-day-header">${cur.toLocaleDateString('en-US', { weekday: 'short' })}</div>`);
            }
            html += weekNamesHTML.join('');
            
            const daysHTML = [];
            for (let i = 0; i < 7; i++) {
                const cur = new Date(startOfWeek);
                cur.setDate(cur.getDate() + i);
                const y = cur.getFullYear();
                const m = String(cur.getMonth() + 1).padStart(2, '0');
                const d = String(cur.getDate()).padStart(2, '0');
                const dKey = `${y}-${m}-${d}`;
                
                const dayName = cur.toLocaleDateString('en-US', { weekday: 'short' });
                daysHTML.push(renderDayCell(dKey, dayName, d));
            }

            html += daysHTML.join('') + `</div>`;
            container.innerHTML = html;
        }

        function renderMonthlyView() {
            const container = document.getElementById('month-view-container');
            
            const curDateParts = currentDateKey.split('-');
            const newDateKey = `${curDateParts[0]}-${curDateParts[1]}-01`;
            
            if (currentDateKey !== newDateKey) {
                currentDateKey = newDateKey;
                updateUrl();
            }

            updateLifetimeStats();
            
            const dateParts = currentDateKey.split('-');
            document.getElementById('date-picker').value = `${dateParts[0]}-${dateParts[1]}`;

            const year = parseInt(dateParts[0], 10);
            const month = parseInt(dateParts[1], 10) - 1;
            
            const firstDayOfMonth = new Date(year, month, 1);
            const lastDayOfMonth = new Date(year, month + 1, 0);
            
            const monthStr = firstDayOfMonth.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
            
            let html = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">${monthStr}</span>
                        <span class="day-view-meta">Monthly aggregate productivity overview.</span>
                    </div>
                </div>
                <div class="month-grid" style="margin-top: 0;">
            `;
            
            const weekNamesHTML = [];
            // generate 7 days from an arbitrary start date that matches weekStartDay
            // 2023-01-01 is a Sunday (0), 2023-01-02 is Monday (1)
            for (let i = 0; i < 7; i++) {
                const cur = new Date(2023, 0, 1 + weekStartDay + i);
                weekNamesHTML.push(`<div class="week-day-header">${cur.toLocaleDateString('en-US', { weekday: 'short' })}</div>`);
            }
            html += weekNamesHTML.join('');
            
            const firstDayOfWeek = firstDayOfMonth.getDay();
            let emptyCells = firstDayOfWeek - weekStartDay;
            if (emptyCells < 0) emptyCells += 7;
            
            for (let i = 0; i < emptyCells; i++) {
                html += `<div></div>`;
            }
            
            for (let d = 1; d <= lastDayOfMonth.getDate(); d++) {
                const cur = new Date(year, month, d);
                const y = cur.getFullYear();
                const mStr = String(cur.getMonth() + 1).padStart(2, '0');
                const dStr = String(cur.getDate()).padStart(2, '0');
                const dKey = `${y}-${mStr}-${dStr}`;
                
                html += renderDayCell(dKey, '', d);
            }
            
            html += `</div>`;
            container.innerHTML = html;
        }

        function renderDayCell(dateKey, headerText, dayNum) {
            const dayData = daysMap[dateKey];
            let avgFocus = 0;
            let activeTimeStr = '0m';
            let colorClass = '';
            
            if (dayData && dayData.totalLoggedSlots > 0) {
                let daySumFocus = 0;
                let dayCountSlots = 0;
                dayData.slots.forEach(slot => {
                    // Logged slot: at least one productive minute (focus_score > 0).
                    if (slot.focus_score > 0) {
                        daySumFocus += slot.focus_score;
                        dayCountSlots += 1;
                    }
                });

                avgFocus = dayCountSlots > 0 ? Math.round(daySumFocus / dayCountSlots) : 0;
                const activeMins = dayData.totalLoggedSlots * 10;
                const hours = Math.floor(activeMins / 60);
                const mins = activeMins % 60;
                activeTimeStr = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
                
                if (avgFocus >= 80) colorClass = 'green';
                else if (avgFocus >= 40) colorClass = 'yellow';
                else colorClass = 'red';
            }
            
            return `
                <div class="month-day-cell ${colorClass}" onclick="switchView('daily'); navigateToDate('${dateKey}');">
                    <div class="month-day-header">
                        <span>${headerText}</span>
                        <span style="color: var(--text-main);">${dayNum}</span>
                    </div>
                    <div class="month-day-stats">
                        ${dayData && dayData.totalLoggedSlots > 0 ? `
                            <span style="color: var(--accent-${colorClass === 'green' ? 'green' : (colorClass === 'yellow' ? 'yellow' : 'red')}); font-weight: 800; font-size: 0.9rem;">${avgFocus}%</span>
                            <span>${activeTimeStr}</span>
                        ` : `<span style="color: var(--text-muted); padding-top: 0.5rem; font-size: 0.7rem;">No data</span>`}
                    </div>
                </div>
            `;
        }

        function renderEmptyDayView(dateKey) {
            const container = document.getElementById('day-view-container');
            const formattedDate = getFormattedDate(dateKey);

            // Empty heatmap cells
            const heatmapCells = Array(24).fill(null).map((_, hour) => {
                const ampm = hour >= 12 ? 'PM' : 'AM';
                const displayHour = hour % 12 === 0 ? 12 : hour % 12;
                let slivers = '';
                for (let i = 0; i < 6; i++) {
                    slivers += `<div style="flex:1; border-radius:1px; background: rgba(255,255,255,0.06);"></div>`;
                }
                return `<div class="heatmap-cell" style="display:flex; gap:2px; padding:3px;" data-tooltip="${displayHour} ${ampm} - Offline">${slivers}</div>`;
            }).join('');

            // 24 offline rows
            let hourRowsHtml = '';
            for (let h = 0; h < 24; h++) {
                const ampm = h >= 12 ? 'PM' : 'AM';
                const displayHour = h % 12 === 0 ? 12 : h % 12;
                const hourLabelStr = `${String(displayHour).padStart(2, '0')}:00 ${ampm}`;
                
                let slotsInHourHtml = '';
                for (let c = 0; c < 6; c++) {
                    slotsInHourHtml += `
                        <div class="slot-card compact-card offline-card">
                            <div class="slot-compact-header">
                                <span class="slot-compact-min">:${c * 10}</span>
                                <span class="slot-compact-score" style="color: var(--text-muted);">Offline</span>
                            </div>
                            <div class="slot-compact-stats">
                                <span>-</span>
                                <span>-</span>
                            </div>
                            <span class="offline-text">No Telemetry</span>
                        </div>
                    `;
                }

                hourRowsHtml += `
                    <div class="hour-row">
                        <div class="hour-label">${hourLabelStr}</div>
                        ${slotsInHourHtml}
                    </div>
                `;
            }

            container.innerHTML = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">${formattedDate}</span>
                        <span class="day-view-meta">No activity data logged for this date.</span>
                    </div>
                    <div class="day-view-badges">
                        <span class="badge" style="font-size:0.85rem; padding: 0.35rem 0.75rem; background: rgba(255,255,255,0.02); color: var(--text-muted);">0% Focus</span>
                        <span class="badge badge-time" style="font-size:0.85rem; padding: 0.35rem 0.75rem; background: rgba(255,255,255,0.02); color: var(--text-muted);">0m Active</span>
                    </div>
                </div>

                <div style="margin-bottom: 2rem; background: rgba(0,0,0,0.15); border: 1px solid var(--border-card); border-radius: 12px; padding: 1.2rem;">
                    <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.8px; margin-bottom: 0.6rem;">24-Hour Focus Heatmap</h4>
                    <div class="heatmap-bar">
                        ${heatmapCells}
                    </div>
                    <div class="heatmap-labels">
                        <span>12 AM</span>
                        <span>6 AM</span>
                        <span>12 PM</span>
                        <span>6 PM</span>
                        <span>11 PM</span>
                    </div>
                </div>

                <div class="day-grid-container">
                    <div class="hour-row grid-headers" style="position: sticky; top: 90px; z-index: 15; background: rgba(15, 17, 26, 0.85); backdrop-filter: blur(12px); padding: 0.5rem; border-radius: 8px; margin: -0.5rem -0.5rem 0.5rem -0.5rem; border-bottom: 1px solid var(--border-card);">
                        <div class="hour-label-header">Hour</div>
                        <div class="col-header">:00</div>
                        <div class="col-header">:10</div>
                        <div class="col-header">:20</div>
                        <div class="col-header">:30</div>
                        <div class="col-header">:40</div>
                        <div class="col-header">:50</div>
                    </div>
                    ${hourRowsHtml}
                </div>
            `;
        }

        // Export CSV logic
        function openExportModal() { document.getElementById('export-dialog').showModal(); }
        function closeExportModal() { document.getElementById('export-dialog').close(); }

        async function exportCsv() {
            const btn = document.getElementById('export-btn');
            const range = document.getElementById('export-range').value;
            let urlParams = `?range=${range}`;
            if (range === 'custom') {
                const start = document.getElementById('export-start').value;
                const end = document.getElementById('export-end').value;
                if (!start || !end) {
                    alert('Please select both start and end dates.');
                    return;
                }
                const startTs = new Date(start).getTime() / 1000;
                // Add 86400 to include the entire end day
                const endTs = (new Date(end).getTime() / 1000) + 86400;
                urlParams += `&start=${startTs}&end=${endTs}`;
            }

            const originalText = btn.innerHTML;
            btn.innerHTML = '<span>Exporting...</span>';
            btn.disabled = true;
            try {
                const response = await fetch(`/api/export${urlParams}`);
                if (!response.ok) {
                    throw new Error(await response.text());
                }
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = `focus_logs_${range}.csv`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                closeExportModal();
            } catch (error) {
                alert('Failed to export CSV: ' + error.message);
            } finally {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        }



        // Initialize
        fetchDashboardData();
        // Poll database updates every 15 seconds
        setInterval(fetchDashboardData, 15000);
    </script>
</body>
</html>
"#.replace("{favicon_b64}", &favicon_b64).replace("{logo_b64}", &logo_b64).replace("{font_b64}", &font_b64);
    Html(html)
}

// `mock_cloud_enroll` and its `EnrollRequest` payload were removed in #40 — a stub
// enrollment endpoint left on an unauthenticated port, superseded by the real
// `enroll_agent` Tauri command.
