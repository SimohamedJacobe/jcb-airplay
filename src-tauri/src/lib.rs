// JCB AirPlay — lib.rs
// Tauri application library root. Wires together all backend modules and
// registers Tauri commands exposed to the frontend.

pub mod crypto;
pub mod dvr;
pub mod mdns;
pub mod media;
pub mod rtsp;

use crate::dvr::{DvrManager, DvrStatus, ExportStats, RecordingStats};
use crate::media::VideoStreamState;
use tauri::State;

/// Greet command — baseline smoke-test IPC endpoint.
///
/// # Arguments
/// * `name` – Caller-supplied name string.
///
/// # Returns
/// A greeting string.
#[tauri::command]
fn greet(name: &str) -> String {
    format!("JCB AirPlay says hello, {}! Ready to stream.", name)
}

/// Start the synthetic 60fps SMPTE YUV420p color-bar and radar generator.
#[tauri::command]
fn start_test_pattern(
    state: State<'_, VideoStreamState>,
    width: Option<u32>,
    height: Option<u32>,
) -> Result<(), String> {
    let w = width.unwrap_or(1920);
    let h = height.unwrap_or(1080);
    state.start_test_pattern(w, h);
    Ok(())
}

/// Stop the synthetic test pattern generator.
#[tauri::command]
fn stop_test_pattern(state: State<'_, VideoStreamState>) -> Result<(), String> {
    state.stop_test_pattern();
    Ok(())
}

/// Pull the latest packed video frame as a zero-copy binary IPC response.
#[tauri::command]
fn get_latest_video_frame(
    state: State<'_, VideoStreamState>,
) -> Result<tauri::ipc::Response, String> {
    let data = state.get_latest_frame().unwrap_or_default();
    Ok(tauri::ipc::Response::new(data))
}

/// Save an instant replay clip of retained stream history to an `.h264` file.
#[tauri::command]
async fn save_instant_replay(
    state: State<'_, DvrManager>,
    output_path: Option<String>,
) -> Result<ExportStats, String> {
    let dvr = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let p = output_path.unwrap_or_else(|| {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            format!("replay_{timestamp}.h264")
        });
        dvr.export_replay_clip(std::path::Path::new(&p))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Start continuous live recording to an `.h264` file.
#[tauri::command]
async fn start_recording(state: State<'_, DvrManager>, output_path: String) -> Result<(), String> {
    let dvr = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        dvr.start_live_recording(std::path::Path::new(&output_path))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Stop the active live recording session and finalize the clip file.
#[tauri::command]
async fn stop_recording(state: State<'_, DvrManager>) -> Result<RecordingStats, String> {
    let dvr = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        dvr.stop_live_recording().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Query the current DVR telemetry status (buffered seconds, bytes, IDR count, recording flag).
#[tauri::command]
fn get_dvr_status(state: State<'_, DvrManager>) -> Result<DvrStatus, String> {
    Ok(state.status())
}

/// Tauri application entry point.
///
/// Builds and runs the Tauri application with all plugin registrations,
/// command handlers, and module setup hooks.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(VideoStreamState::new())
        .manage(DvrManager::new())
        .setup(|app| {
            let handle = app.handle().clone();
            log::info!("JCB AirPlay {} starting up", handle.package_info().version);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            start_test_pattern,
            stop_test_pattern,
            get_latest_video_frame,
            save_instant_replay,
            start_recording,
            stop_recording,
            get_dvr_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running JCB AirPlay application");
}
