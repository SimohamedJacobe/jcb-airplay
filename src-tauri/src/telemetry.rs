// JCB AirPlay — telemetry.rs
// Lock-free telemetry module and stream watchdog for AirPlay mirroring.
//
// Responsibilities:
//   • Maintain lock-free, atomic counters for hot-path metrics: frames_total, bytes_total,
//     dropped_frames, decode_latency_us, jitter_us, resolution, dvr buffer ms, recording state.
//   • Track connection state machine (`Idle`, `Handshake`, `Streaming`, `Recovering`) using
//     atomic compare-and-swap transitions.
//   • Provide `sample(now_ms)` sliding-window rate estimation using 2s history checkpoints
//     with integer math and rounding to nearest 2 decimal places.
//   • Provide `StreamWatchdog` monitoring stream silence (>1500ms in `Streaming`), triggering
//     mockable recovery hooks and clean state reset to `Idle`.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Connection lifecycle states for an AirPlay mirroring session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    /// No session active; ready for new connection.
    Idle,
    /// Cryptographic handshake and RTSP SETUP/RECORD in progress.
    Handshake,
    /// Active media streaming underway.
    Streaming,
    /// Stream stalled or recovering; cleaning up resources before returning to Idle.
    Recovering,
}

impl ConnectionState {
    /// Convert state to integer representation.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Handshake => 1,
            Self::Streaming => 2,
            Self::Recovering => 3,
        }
    }

    /// Map integer value to connection state; unknown values map to `Idle`.
    #[must_use]
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Handshake,
            2 => Self::Streaming,
            3 => Self::Recovering,
            _ => Self::Idle,
        }
    }
}

/// Real-time snapshot of telemetry metrics formatted for UI rendering and IPC events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Instantaneous frame rate in frames per second.
    pub fps: f64,
    /// Instantaneous video bit rate in Megabits per second (1 Mbps = 1,000,000 bits/s).
    pub bitrate_mbps: f64,
    /// Moving frame decode latency in milliseconds.
    pub decode_latency_ms: f64,
    /// Inter-arrival packet jitter in milliseconds (RFC 3550 EWMA).
    pub jitter_ms: f64,
    /// Total dropped frames due to congestion or late arrival.
    pub dropped_frames: u64,
    /// Video stream width in pixels.
    pub width: u32,
    /// Video stream height in pixels.
    pub height: u32,
    /// Connected Apple device friendly name or model.
    pub connected_device_name: String,
    /// Current connection lifecycle state.
    pub connection_state: ConnectionState,
    /// Depth of the retained DVR instant-replay buffer in seconds.
    pub dvr_buffer_secs: f64,
    /// Whether continuous live disk recording is currently running.
    pub is_recording: bool,
}

/// Lock-free telemetry aggregator holding high-frequency atomics and sliding-window rate sampler.
pub struct Telemetry {
    base_instant: Instant,

    // Hot-path atomic metrics (written via Relaxed ordering)
    pub frames_total: AtomicU64,
    pub bytes_total: AtomicU64,
    pub dropped_frames: AtomicU64,
    pub decode_latency_us: AtomicU64,
    pub jitter_us: AtomicU64,
    pub width: AtomicU32,
    pub height: AtomicU32,
    pub dvr_buffer_ms: AtomicU64,
    pub is_recording: AtomicBool,

    // Atomic connection state
    state: AtomicU8,

    // Scaled rate metrics stored as integers * 100 (e.g. 1275 = 12.75 Mbps, 3333 = 33.33 fps)
    fps_x100: AtomicU64,
    mbps_x100: AtomicU64,

    // Cold-path device metadata and rate checkpoints
    connected_device_name: Mutex<String>,
    checkpoints: Mutex<VecDeque<(u64, u64, u64)>>, // (ts_ms, frames_total, bytes_total)
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    /// Construct a new [`Telemetry`] instance with default base instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base_instant: Instant::now(),
            frames_total: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            dropped_frames: AtomicU64::new(0),
            decode_latency_us: AtomicU64::new(0),
            jitter_us: AtomicU64::new(0),
            width: AtomicU32::new(0),
            height: AtomicU32::new(0),
            dvr_buffer_ms: AtomicU64::new(0),
            is_recording: AtomicBool::new(false),
            state: AtomicU8::new(ConnectionState::Idle.to_u8()),
            fps_x100: AtomicU64::new(0),
            mbps_x100: AtomicU64::new(0),
            connected_device_name: Mutex::new(String::new()),
            checkpoints: Mutex::new(VecDeque::new()),
        }
    }

    /// Return monotonic runtime timestamp in milliseconds relative to initialization.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.base_instant.elapsed().as_millis() as u64
    }

    /// Retrieve the current connection state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Transition connection state from `current` to `next` using atomic compare-exchange.
    ///
    /// # Errors
    /// Returns `Err(actual)` if the current state differed from `current`.
    pub fn transition_state(
        &self,
        current: ConnectionState,
        next: ConnectionState,
    ) -> Result<ConnectionState, ConnectionState> {
        self.state
            .compare_exchange(
                current.to_u8(),
                next.to_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| next)
            .map_err(ConnectionState::from_u8)
    }

    /// Attempt to initiate a new session via `Idle -> Handshake`.
    ///
    /// If this caller wins the transition, it executes [`Self::reset_session`].
    pub fn try_start_session(&self) -> bool {
        if self
            .transition_state(ConnectionState::Idle, ConnectionState::Handshake)
            .is_ok()
        {
            self.reset_session();
            true
        } else {
            false
        }
    }

    /// Reset all metrics counters, device name, and sampler history.
    pub fn reset_session(&self) {
        self.frames_total.store(0, Ordering::Relaxed);
        self.bytes_total.store(0, Ordering::Relaxed);
        self.dropped_frames.store(0, Ordering::Relaxed);
        self.decode_latency_us.store(0, Ordering::Relaxed);
        self.jitter_us.store(0, Ordering::Relaxed);
        self.fps_x100.store(0, Ordering::Relaxed);
        self.mbps_x100.store(0, Ordering::Relaxed);
        self.width.store(0, Ordering::Relaxed);
        self.height.store(0, Ordering::Relaxed);
        self.dvr_buffer_ms.store(0, Ordering::Relaxed);
        self.is_recording.store(false, Ordering::Relaxed);

        if let Ok(mut name) = self.connected_device_name.lock() {
            name.clear();
        }
        if let Ok(mut q) = self.checkpoints.lock() {
            q.clear();
        }
    }

    /// Set connected sender device name.
    pub fn set_device_name(&self, name: &str) {
        if let Ok(mut dev) = self.connected_device_name.lock() {
            *dev = name.to_string();
        }
    }

    /// Set active video stream resolution.
    pub fn set_resolution(&self, width: u32, height: u32) {
        self.width.store(width, Ordering::Relaxed);
        self.height.store(height, Ordering::Relaxed);
    }

    /// Update DVR buffer depth and live recording status.
    pub fn set_dvr_status(&self, buffer_ms: u64, is_recording: bool) {
        self.dvr_buffer_ms.store(buffer_ms, Ordering::Relaxed);
        self.is_recording.store(is_recording, Ordering::Relaxed);
    }

    /// Record an incoming decoded video frame and its compressed H.264 byte count.
    pub fn record_frame(&self, payload_bytes: usize) {
        self.frames_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_total
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    /// Record a frame dropped due to congestion or late gatekeeper threshold.
    pub fn record_dropped_frame(&self) {
        self.dropped_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// Record frame decode duration in microseconds.
    pub fn record_decode_latency_us(&self, latency_us: u64) {
        self.decode_latency_us.store(latency_us, Ordering::Relaxed);
    }

    /// Directly record measured jitter in microseconds.
    pub fn record_jitter(&self, jitter_us: u64) {
        self.jitter_us.store(jitter_us, Ordering::Relaxed);
    }

    /// Update inter-arrival packet jitter using standard RFC 3550 EWMA algorithm.
    ///
    /// J_new = J_old + (|D| - J_old) / 16 (in integer math).
    pub fn update_jitter(&self, transit_diff_us: i64) {
        let abs_d = transit_diff_us.unsigned_abs();
        let old_j = self.jitter_us.load(Ordering::Relaxed);
        let new_j = if abs_d >= old_j {
            old_j + (abs_d - old_j) / 16
        } else {
            old_j - (old_j - abs_d) / 16
        };
        self.jitter_us.store(new_j, Ordering::Relaxed);
    }

    /// Sample sliding-window transfer rates against checkpoints.
    ///
    /// Keeps checkpoints within the last 2 seconds, trimming older entries.
    /// Rates are computed against the newest checkpoint at or before `now_ms - 1000`
    /// (or the oldest checkpoint if none exist $\le \text{now\_ms} - 1000$).
    ///
    /// Math uses u128 scaling before division with rounding to nearest 2 decimal places:
    /// `fps_x100 = (Δframes * 100_000 + Δt / 2) / Δt`
    /// `mbps_x100 = (Δbytes * 800 + (Δt * 1000) / 2) / (Δt * 1000)`
    pub fn sample(&self, now_ms: u64) {
        let cur_frames = self.frames_total.load(Ordering::Relaxed);
        let cur_bytes = self.bytes_total.load(Ordering::Relaxed);

        let mut q = match self.checkpoints.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Trim checkpoints older than 2s
        while let Some(front) = q.front() {
            if now_ms.saturating_sub(front.0) > 2000 {
                q.pop_front();
            } else {
                break;
            }
        }

        // If history was cleared or any counter went backwards, reset history
        if q.iter().any(|cp| cur_frames < cp.1 || cur_bytes < cp.2) {
            q.clear();
        }

        if q.is_empty() {
            q.push_back((now_ms, cur_frames, cur_bytes));
            self.fps_x100.store(0, Ordering::Relaxed);
            self.mbps_x100.store(0, Ordering::Relaxed);
            return;
        }

        // Find newest checkpoint at or before now_ms - 1000, else oldest
        let target_ts = now_ms.saturating_sub(1000);
        let baseline = q
            .iter()
            .rev()
            .find(|cp| cp.0 <= target_ts)
            .copied()
            .unwrap_or_else(|| *q.front().expect("non-empty queue"));

        let dt_ms = now_ms.saturating_sub(baseline.0);
        let dframes = cur_frames.saturating_sub(baseline.1);
        let dbytes = cur_bytes.saturating_sub(baseline.2);

        if dt_ms == 0 {
            self.fps_x100.store(0, Ordering::Relaxed);
            self.mbps_x100.store(0, Ordering::Relaxed);
        } else {
            // fps_x100 = (Δframes * 100_000 + dt / 2) / dt
            let num_fps = (dframes as u128) * 100_000;
            let denom_fps = dt_ms as u128;
            let fps_calc = (num_fps + denom_fps / 2) / denom_fps;
            self.fps_x100.store(fps_calc as u64, Ordering::Relaxed);

            // mbps_x100 = (Δbytes * 800 + (dt * 1000) / 2) / (dt * 1000)
            let num_mbps = (dbytes as u128) * 800;
            let denom_mbps = (dt_ms as u128) * 1000;
            let mbps_calc = (num_mbps + denom_mbps / 2) / denom_mbps;
            self.mbps_x100.store(mbps_calc as u64, Ordering::Relaxed);
        }

        // Record current checkpoint
        if q.back().map_or(true, |last| last.0 != now_ms) {
            q.push_back((now_ms, cur_frames, cur_bytes));
        } else if let Some(last) = q.back_mut() {
            *last = (now_ms, cur_frames, cur_bytes);
        }
    }

    /// Capture an atomic, zero-allocation snapshot of current telemetry metrics.
    #[must_use]
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let fps = (self.fps_x100.load(Ordering::Relaxed) as f64) / 100.0;
        let bitrate_mbps = (self.mbps_x100.load(Ordering::Relaxed) as f64) / 100.0;
        let decode_latency_ms = (self.decode_latency_us.load(Ordering::Relaxed) as f64) / 1000.0;
        let jitter_ms = (self.jitter_us.load(Ordering::Relaxed) as f64) / 1000.0;
        let dropped_frames = self.dropped_frames.load(Ordering::Relaxed);
        let width = self.width.load(Ordering::Relaxed);
        let height = self.height.load(Ordering::Relaxed);

        let connected_device_name = self
            .connected_device_name
            .lock()
            .map_or_else(|p| p.into_inner().clone(), |g| g.clone());

        let connection_state = self.state();
        let dvr_buffer_secs = (self.dvr_buffer_ms.load(Ordering::Relaxed) as f64) / 1000.0;
        let is_recording = self.is_recording.load(Ordering::Relaxed);

        TelemetrySnapshot {
            fps,
            bitrate_mbps,
            decode_latency_ms,
            jitter_ms,
            dropped_frames,
            width,
            height,
            connected_device_name,
            connection_state,
            dvr_buffer_secs,
            is_recording,
        }
    }
}

// ─── Stream Silence Watchdog & Recovery ──────────────────────────────────────

/// Trait defining mockable hooks executed when a stream silence stall occurs.
pub trait RecoveryHooks: Send + Sync {
    /// Drop active RTSP and media stream sockets while keeping server listener running.
    fn close_session(&self);
    /// Flush pending media and jitter ring buffers.
    fn flush_buffers(&self);
    /// Reset decoder engine back to initial SPS-awaiting state.
    fn reset_decoder(&self);
    /// Stop active live recording and finalize file output.
    fn stop_recording(&self);
}

/// Watchdog monitoring stream silence and driving automated stall recovery.
pub struct StreamWatchdog {
    telemetry: Arc<Telemetry>,
    last_activity_ms: AtomicU64,
}

impl StreamWatchdog {
    /// Construct a new [`StreamWatchdog`] tracking the specified [`Telemetry`].
    #[must_use]
    pub fn new(telemetry: Arc<Telemetry>, initial_ms: u64) -> Self {
        Self {
            telemetry,
            last_activity_ms: AtomicU64::new(initial_ms),
        }
    }

    /// Touch watchdog to record stream activity timestamp.
    ///
    /// Must be called for all media packets, keepalives, and RTSP control requests.
    pub fn touch(&self, now_ms: u64) {
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Read-only check whether the stream is currently stalled.
    ///
    /// Returns `true` if state is `Streaming` and no activity was recorded for > 1500ms.
    #[must_use]
    pub fn is_stalled(&self, now_ms: u64) -> bool {
        let state = self.telemetry.state();
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        state == ConnectionState::Streaming && now_ms.saturating_sub(last) > 1500
    }

    /// Check watchdog status and trigger atomic session recovery if stalled.
    ///
    /// If stalled, attempts `Streaming -> Recovering`. The winning thread executes
    /// recovery hooks once and transitions state to `Idle`.
    ///
    /// Returns `true` if this caller executed recovery, or `false` otherwise.
    pub fn check(&self, now_ms: u64, hooks: &dyn RecoveryHooks) -> bool {
        if !self.is_stalled(now_ms) {
            return false;
        }

        // Only the thread that successfully transitions Streaming -> Recovering performs recovery
        if self
            .telemetry
            .transition_state(ConnectionState::Streaming, ConnectionState::Recovering)
            .is_err()
        {
            return false;
        }

        // Execute recovery hooks in sequence (best-effort, never panicking)
        hooks.close_session();
        hooks.flush_buffers();
        hooks.reset_decoder();
        hooks.stop_recording();

        // Always conclude in Idle via compare_exchange so a newer state is never overwritten
        let _ = self
            .telemetry
            .transition_state(ConnectionState::Recovering, ConnectionState::Idle);

        true
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::thread;

    #[test]
    fn test_invalid_state_value_maps_to_idle() {
        assert_eq!(ConnectionState::from_u8(0), ConnectionState::Idle);
        assert_eq!(ConnectionState::from_u8(1), ConnectionState::Handshake);
        assert_eq!(ConnectionState::from_u8(2), ConnectionState::Streaming);
        assert_eq!(ConnectionState::from_u8(3), ConnectionState::Recovering);
        assert_eq!(ConnectionState::from_u8(4), ConnectionState::Idle);
        assert_eq!(ConnectionState::from_u8(42), ConnectionState::Idle);
        assert_eq!(ConnectionState::from_u8(255), ConnectionState::Idle);
    }

    #[test]
    fn test_snapshot_serialization() {
        let telemetry = Telemetry::new();
        telemetry.set_device_name("iPhone 15 Pro");
        telemetry.set_resolution(1920, 1080);
        telemetry.record_frame(50_000);
        telemetry.record_decode_latency_us(4_500);
        telemetry.record_jitter(250);
        telemetry.set_dvr_status(15_000, true);

        let snap = telemetry.snapshot();
        assert_eq!(snap.connected_device_name, "iPhone 15 Pro");
        assert_eq!(snap.width, 1920);
        assert_eq!(snap.height, 1080);
        assert_eq!(snap.dropped_frames, 0);
        assert_eq!(snap.decode_latency_ms, 4.5);
        assert_eq!(snap.dvr_buffer_secs, 15.0);
        assert!(snap.is_recording);

        let json = serde_json::to_string(&snap).expect("JSON serialization must succeed");
        let deserialized: TelemetrySnapshot =
            serde_json::from_str(&json).expect("JSON deserialization must succeed");
        assert_eq!(snap, deserialized);
    }

    #[test]
    fn test_concurrent_counters() {
        let telemetry = Arc::new(Telemetry::new());
        let threads = 4;
        let increments_per_thread = 10_000;
        let mut handles = Vec::new();

        for _ in 0..threads {
            let t = Arc::clone(&telemetry);
            handles.push(thread::spawn(move || {
                for _ in 0..increments_per_thread {
                    t.record_frame(1);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread join must succeed");
        }

        assert_eq!(
            telemetry.frames_total.load(Ordering::Relaxed),
            40_000,
            "Concurrent frame count must be exactly 40,000"
        );
        assert_eq!(
            telemetry.bytes_total.load(Ordering::Relaxed),
            40_000,
            "Concurrent bytes count must be exactly 40,000"
        );
    }

    #[test]
    fn test_idle_to_handshake_succeeds_once_and_second_attempt_fails() {
        let telemetry = Telemetry::new();
        assert_eq!(telemetry.state(), ConnectionState::Idle);

        assert!(
            telemetry.try_start_session(),
            "First transition from Idle to Handshake must succeed"
        );
        assert_eq!(telemetry.state(), ConnectionState::Handshake);

        assert!(
            !telemetry.try_start_session(),
            "Second transition attempt while in Handshake must fail"
        );
    }

    #[test]
    fn test_after_reset_session_sample_never_gives_inflated_or_negative_rates() {
        let telemetry = Telemetry::new();
        telemetry.sample(0);
        telemetry.record_frame(1_000_000);
        telemetry.sample(1000);

        let snap_before = telemetry.snapshot();
        assert!(snap_before.bitrate_mbps > 0.0);

        telemetry.reset_session();
        let snap_reset = telemetry.snapshot();
        assert_eq!(snap_reset.fps, 0.0);
        assert_eq!(snap_reset.bitrate_mbps, 0.0);
        assert_eq!(snap_reset.dropped_frames, 0);
        assert_eq!(snap_reset.connected_device_name, "");

        // Sample at 1500 after reset — must not produce inflated or negative rate
        telemetry.sample(1500);
        let snap_after = telemetry.snapshot();
        assert_eq!(snap_after.fps, 0.0);
        assert_eq!(snap_after.bitrate_mbps, 0.0);
    }

    #[test]
    fn test_fractional_rates_precision() {
        // Test A: 1,593,750 bytes over 1000ms -> exactly 12.75 Mbps (stored as 1275)
        let tel_a = Telemetry::new();
        tel_a.sample(0);
        tel_a.bytes_total.store(1_593_750, Ordering::Relaxed);
        tel_a.sample(1000);
        assert_eq!(
            tel_a.mbps_x100.load(Ordering::Relaxed),
            1275,
            "Bitrate must round to exactly 1275 (12.75 Mbps)"
        );
        assert_eq!(tel_a.snapshot().bitrate_mbps, 12.75);

        // Test B: 10 frames over 300ms -> exactly 33.33 fps (stored as 3333)
        let tel_b = Telemetry::new();
        tel_b.sample(0);
        tel_b.frames_total.store(10, Ordering::Relaxed);
        tel_b.sample(300);
        assert_eq!(
            tel_b.fps_x100.load(Ordering::Relaxed),
            3333,
            "Framerate must round to exactly 3333 (33.33 fps)"
        );
        assert_eq!(tel_b.snapshot().fps, 33.33);
    }
}
