// JCB AirPlay — main.rs
// Entry point for the Tauri desktop application process.
// Prevents an extra console window on Windows in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    jcb_airplay_lib::run();
}
