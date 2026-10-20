// JCB AirPlay — lib.rs
// Tauri application library root. Wires together all backend modules and
// registers Tauri commands exposed to the frontend.

pub mod crypto;
pub mod dvr;
pub mod mdns;
pub mod media;
pub mod rtsp;

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

/// Tauri application entry point.
///
/// Builds and runs the Tauri application with all plugin registrations,
/// command handlers, and module setup hooks.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = app.handle().clone();
            log::info!("JCB AirPlay {} starting up", handle.package_info().version);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running JCB AirPlay application");
}
