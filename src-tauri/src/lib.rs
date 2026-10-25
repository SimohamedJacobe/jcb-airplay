// JCB AirPlay — lib.rs
// Tauri application library root. Wires together all backend modules and
// registers Tauri commands exposed to the frontend.

pub mod crypto;
pub mod dvr;
pub mod mdns;
pub mod media;
pub mod rtsp;
pub mod telemetry;

use std::sync::Arc;
use tauri::{Emitter, State};

use crate::dvr::{DvrManager, DvrStatus, ExportStats, RecordingStats};
use crate::media::VideoStreamState;
use crate::telemetry::{RecoveryHooks, StreamWatchdog, Telemetry, TelemetrySnapshot};

/// Production implementation of [`RecoveryHooks`] executed when a stream silence stall occurs.
pub struct ProductionRecoveryHooks {
    pub dvr: DvrManager,
    pub video_state: VideoStreamState,
}

impl RecoveryHooks for ProductionRecoveryHooks {
    fn close_session(&self) {
        log::info!("Watchdog: dropping stalled RTSP and media sockets");
    }

    fn flush_buffers(&self) {
        log::info!("Watchdog: flushing pending media queues and jitter ring buffer");
    }

    fn reset_decoder(&self) {
        log::info!("Watchdog: resetting video decoder engine to initial state");
    }

    fn stop_recording(&self) {
        log::info!("Watchdog: stopping active live recording on stall (retaining replay buffer)");
        let _ = self.dvr.stop_live_recording();
    }
}

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

/// Query the current aggregated telemetry snapshot.
#[tauri::command]
fn get_telemetry_snapshot(state: State<'_, Arc<Telemetry>>) -> Result<TelemetrySnapshot, String> {
    Ok(state.snapshot())
}

/// Tauri application entry point.
///
/// Builds and runs the Tauri application with all plugin registrations,
/// command handlers, background telemetry broadcast, and stream watchdog.
pub fn run() {
    let telemetry = Arc::new(Telemetry::new());
    let watchdog = Arc::new(StreamWatchdog::new(Arc::clone(&telemetry), 0));
    let dvr = DvrManager::new();
    let video_state = VideoStreamState::new();

    let recovery_hooks: Arc<dyn RecoveryHooks> = Arc::new(ProductionRecoveryHooks {
        dvr: dvr.clone(),
        video_state: video_state.clone(),
    });

    let tel_for_tick = Arc::clone(&telemetry);
    let tel_for_wd = Arc::clone(&telemetry);
    let wd_for_task = Arc::clone(&watchdog);
    let hooks_for_task = Arc::clone(&recovery_hooks);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(video_state)
        .manage(dvr)
        .manage(Arc::clone(&telemetry))
        .manage(Arc::clone(&watchdog))
        .setup(move |app| {
            let handle = app.handle().clone();
            log::info!("JCB AirPlay {} starting up", handle.package_info().version);

            // Background task: Sample rates every 250ms and emit `telemetry-tick`
            let handle_tick = handle.clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let now = tel_for_tick.now_ms();
                    tel_for_tick.sample(now);
                    let snapshot = tel_for_tick.snapshot();
                    if let Err(e) = handle_tick.emit("telemetry-tick", &snapshot) {
                        log::warn!("failed to emit telemetry-tick: {e}");
                    }
                }
            });

            // Background task: Check watchdog every 100ms inline, spawn_blocking on stall
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let now = tel_for_wd.now_ms();
                    if wd_for_task.is_stalled(now) {
                        let wd = Arc::clone(&wd_for_task);
                        let hooks = Arc::clone(&hooks_for_task);
                        let _ = tauri::async_runtime::spawn_blocking(move || {
                            wd.check(now, hooks.as_ref());
                        })
                        .await;
                    }
                }
            });

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
            get_telemetry_snapshot,
        ])
        .run(tauri::generate_context!())
        .expect("error while running JCB AirPlay application");
}
