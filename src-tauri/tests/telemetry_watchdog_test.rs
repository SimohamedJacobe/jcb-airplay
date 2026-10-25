// JCB AirPlay — tests/telemetry_watchdog_test.rs
// Integration tests for real-time telemetry sampler and stream watchdog stall recovery.
//
// Verification goals:
//   a. Burst rate calculation: 120 frames @ 60fps (25,000 bytes/frame) sampled at 250ms intervals.
//      At t=1500, verify fps within 2% of 60.0 and bitrate within 2% of 12.0 Mbps.
//   b. Stall boundary: Silence at T+1500ms stays Streaming, T+1600ms recovers to Idle and runs hooks once.
//   c. TEARDOWN: Normal transition to Idle avoids watchdog recovery even after 5,000ms silence.
//   d. Re-arm: Re-established stream re-arms watchdog and recovers cleanly after second stall.
//   e. Reconnect race: Concurrent handshake attempt during recovery is rejected, then succeeds once Idle.

use jcb_airplay_lib::telemetry::{ConnectionState, RecoveryHooks, StreamWatchdog, Telemetry};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

struct CountingRecoveryHooks {
    pub close_session_count: AtomicUsize,
    pub flush_buffers_count: AtomicUsize,
    pub reset_decoder_count: AtomicUsize,
    pub stop_recording_count: AtomicUsize,
    pub race_telemetry: Option<Arc<Telemetry>>,
    pub race_attempt_result: AtomicBool,
}

impl CountingRecoveryHooks {
    fn new(race_telemetry: Option<Arc<Telemetry>>) -> Self {
        Self {
            close_session_count: AtomicUsize::new(0),
            flush_buffers_count: AtomicUsize::new(0),
            reset_decoder_count: AtomicUsize::new(0),
            stop_recording_count: AtomicUsize::new(0),
            race_telemetry,
            race_attempt_result: AtomicBool::new(false),
        }
    }

    fn assert_counts(&self, expected: usize) {
        assert_eq!(
            self.close_session_count.load(Ordering::SeqCst),
            expected,
            "close_session count mismatch"
        );
        assert_eq!(
            self.flush_buffers_count.load(Ordering::SeqCst),
            expected,
            "flush_buffers count mismatch"
        );
        assert_eq!(
            self.reset_decoder_count.load(Ordering::SeqCst),
            expected,
            "reset_decoder count mismatch"
        );
        assert_eq!(
            self.stop_recording_count.load(Ordering::SeqCst),
            expected,
            "stop_recording count mismatch"
        );
    }
}

impl RecoveryHooks for CountingRecoveryHooks {
    fn close_session(&self) {
        self.close_session_count.fetch_add(1, Ordering::SeqCst);
        if let Some(ref tel) = self.race_telemetry {
            // Reconnect race test: attempt to start session during recovery
            let won = tel.try_start_session();
            self.race_attempt_result.store(won, Ordering::SeqCst);
        }
    }

    fn flush_buffers(&self) {
        self.flush_buffers_count.fetch_add(1, Ordering::SeqCst);
    }

    fn reset_decoder(&self) {
        self.reset_decoder_count.fetch_add(1, Ordering::SeqCst);
    }

    fn stop_recording(&self) {
        self.stop_recording_count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_telemetry_burst_sampling_accuracy() {
    // a. Burst: sample(0) as baseline. Frame i (1..=120) arrives at i*1000/60 ms with 25,000 bytes.
    // Before each sample(t) at t = 250, 500, ..., 1500, record every frame with timestamp <= t.
    // At t=1500, assert fps within 2% of 60.0 and bitrate within 2% of 12.0 (25_000*8*60/1_000_000).
    let telemetry = Telemetry::new();
    telemetry.sample(0);

    let total_frames = 120u64;
    let bytes_per_frame = 25_000usize;
    let mut next_frame = 1u64;

    let sample_intervals = [250u64, 500, 750, 1000, 1250, 1500];

    for &t in &sample_intervals {
        while next_frame <= total_frames {
            let frame_ts = (next_frame * 1000) / 60;
            if frame_ts <= t {
                telemetry.record_frame(bytes_per_frame);
                next_frame += 1;
            } else {
                break;
            }
        }
        telemetry.sample(t);
    }

    let snap = telemetry.snapshot();
    let expected_fps = 60.0;
    let expected_mbps = (25_000.0 * 8.0 * 60.0) / 1_000_000.0; // 12.0 Mbps

    let fps_diff = (snap.fps - expected_fps).abs();
    let mbps_diff = (snap.bitrate_mbps - expected_mbps).abs();

    assert!(
        fps_diff <= expected_fps * 0.02,
        "FPS {} must be within 2% of expected {}",
        snap.fps,
        expected_fps
    );
    assert!(
        mbps_diff <= expected_mbps * 0.02,
        "Bitrate {} must be within 2% of expected {}",
        snap.bitrate_mbps,
        expected_mbps
    );
}

#[test]
fn test_watchdog_stall_boundary_and_rearm_lifecycle() {
    let telemetry = Arc::new(Telemetry::new());
    let hooks = CountingRecoveryHooks::new(None);

    // Transition to Streaming
    assert!(telemetry.try_start_session());
    assert_eq!(
        telemetry
            .transition_state(ConnectionState::Handshake, ConnectionState::Streaming)
            .expect("Handshake -> Streaming"),
        ConnectionState::Streaming
    );

    let t_start = 1000u64;
    let watchdog = StreamWatchdog::new(Arc::clone(&telemetry), t_start);

    // b. Stall boundary: last activity at T.
    // check(T+1500) is false and state stays Streaming.
    assert!(
        !watchdog.check(t_start + 1500, &hooks),
        "check(T+1500) must return false (not yet stalled)"
    );
    assert_eq!(telemetry.state(), ConnectionState::Streaming);
    hooks.assert_counts(0);

    // check(T+1600) is true, each hook ran exactly once, state is Idle.
    assert!(
        watchdog.check(t_start + 1600, &hooks),
        "check(T+1600) must trigger stall recovery"
    );
    assert_eq!(telemetry.state(), ConnectionState::Idle);
    hooks.assert_counts(1);

    // check(T+1700) is false and hook counts are unchanged.
    assert!(
        !watchdog.check(t_start + 1700, &hooks),
        "check(T+1700) while Idle must return false"
    );
    hooks.assert_counts(1);

    // c. TEARDOWN: after a normal Streaming -> Idle, check at +5,000ms runs no hooks.
    assert!(telemetry.try_start_session());
    assert!(telemetry
        .transition_state(ConnectionState::Handshake, ConnectionState::Streaming)
        .is_ok());
    // Normal TEARDOWN moves directly to Idle
    assert!(telemetry
        .transition_state(ConnectionState::Streaming, ConnectionState::Idle)
        .is_ok());

    assert!(
        !watchdog.check(t_start + 5000, &hooks),
        "check() after normal TEARDOWN must return false"
    );
    hooks.assert_counts(1); // counts remain 1 from previous recovery

    // d. Re-arm: at S = T+10_000 run Idle -> Handshake -> Streaming with a touch at S.
    let s = t_start + 10_000;
    assert!(telemetry.try_start_session());
    assert!(telemetry
        .transition_state(ConnectionState::Handshake, ConnectionState::Streaming)
        .is_ok());
    watchdog.touch(s);

    assert!(
        !watchdog.check(s, &hooks),
        "check(S) must be false right after touch"
    );
    assert!(
        !watchdog.check(s + 1500, &hooks),
        "check(S+1500) must be false"
    );
    assert_eq!(telemetry.state(), ConnectionState::Streaming);
    hooks.assert_counts(1);

    assert!(
        watchdog.check(s + 1600, &hooks),
        "check(S+1600) must trigger second stall recovery"
    );
    assert_eq!(telemetry.state(), ConnectionState::Idle);
    hooks.assert_counts(2); // each hook has now run exactly twice
}

#[test]
fn test_watchdog_reconnect_race_condition() {
    // e. Reconnect race: a mock hook tries Idle -> Handshake while recovery is running
    // and must see it fail; the same attempt succeeds afterward.
    let telemetry = Arc::new(Telemetry::new());
    let hooks = CountingRecoveryHooks::new(Some(Arc::clone(&telemetry)));

    assert!(telemetry.try_start_session());
    assert!(telemetry
        .transition_state(ConnectionState::Handshake, ConnectionState::Streaming)
        .is_ok());

    let t = 2000u64;
    let watchdog = StreamWatchdog::new(Arc::clone(&telemetry), t);

    // Trigger stall recovery: during close_session, hook attempts try_start_session()
    assert!(watchdog.check(t + 1600, &hooks));
    assert_eq!(telemetry.state(), ConnectionState::Idle);

    // Assert that the attempt during recovery FAILED because state was Recovering
    assert!(
        !hooks.race_attempt_result.load(Ordering::SeqCst),
        "Handshake attempt during Recovering state must fail"
    );

    // Afterward, when state is Idle, the same attempt must SUCCEED
    assert!(
        telemetry.try_start_session(),
        "Handshake attempt after recovery is finished must succeed"
    );
    assert_eq!(telemetry.state(), ConnectionState::Handshake);
}
