// JCB AirPlay — tests/dvr_clip_export.rs
// Integration test: Keyframe-aligned 30s instant replay buffer and live clip export.
//
// Verification goals:
//   • Feed SPS + PPS once, then 180 frames (30fps, 6s, IDR every 30 frames, each with distinct payload).
//   • Retention: 3s.
//   • Expected: GOPs 0-1 (frames 0-59) evicted, GOPs 2-5 (frames 60-179) retained.
//   • Assert: Evicted frames are absent; exported .h264 begins with 00 00 00 01 SPS, PPS, IDR;
//     the first retained frame is an IDR; and file bytes equal the independently built expected sequence.

use jcb_airplay_lib::dvr::{DvrManager, LiveRecorder, RollingDvrBuffer};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_dvr_clip_export_eviction_and_bitstream_exactness() {
    let dir = tempdir().expect("failed to create temporary test directory");
    let export_path = dir.path().join("replay_clip_test.h264");

    // Timescale: 90 kHz ticks / second (standard H.264 video clock)
    // 30 fps -> 3,000 ticks per frame
    // Retention: 3 seconds = 270,000 ticks
    let timescale = 90_000u32;
    let ticks_per_frame = 3_000u64;
    let retention_ticks = 3u64 * (timescale as u64);

    let buffer = RollingDvrBuffer::new(retention_ticks, usize::MAX, timescale);

    // 1. Parameter Sets (fed once at start)
    // SPS: NAL type 7 (0x67)
    let sps_nal = vec![
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0xAB, 0xCD, 0xEF, 0x01,
    ];
    // PPS: NAL type 8 (0x68)
    let pps_nal = vec![
        0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80, 0x12, 0x34, 0x56, 0x78,
    ];

    buffer.push_nal(&sps_nal, 0).expect("pushing SPS failed");
    buffer.push_nal(&pps_nal, 0).expect("pushing PPS failed");

    // 2. Generate 180 frames (30fps, 6.0 seconds total, IDR every 30 frames)
    // GOP 0: frames 0..30    (IDR at frame 0, t = 0)
    // GOP 1: frames 30..60   (IDR at frame 30, t = 90_000)
    // GOP 2: frames 60..90   (IDR at frame 60, t = 180_000)
    // GOP 3: frames 90..120  (IDR at frame 90, t = 270_000)
    // GOP 4: frames 120..150 (IDR at frame 120, t = 360_000)
    // GOP 5: frames 150..180 (IDR at frame 150, t = 450_000)
    let total_frames = 180usize;
    let mut frames = Vec::with_capacity(total_frames);

    for i in 0..total_frames {
        let is_idr = i % 30 == 0;
        let nal_type_byte = if is_idr { 0x65 } else { 0x61 }; // 5 for IDR, 1 for non-IDR
        let frame_idx_low = (i & 0xFF) as u8;
        let frame_idx_high = ((i >> 8) & 0xFF) as u8;

        // Each frame has a distinct, recognizable payload pattern
        let mut frame_data = vec![
            0x00,
            0x00,
            0x00,
            0x01,
            nal_type_byte,
            frame_idx_low,
            frame_idx_high,
            0xA5,
            0x5A,
            0x11,
            0x22,
            0x33,
            0x44,
        ];
        frame_data.extend_from_slice(&(i as u32).to_le_bytes());

        let timestamp = (i as u64) * ticks_per_frame;
        buffer
            .push_nal(&frame_data, timestamp)
            .expect("pushing frame failed");
        frames.push(frame_data);
    }

    // 3. Verify GOP eviction logic:
    // When frame 179 (t = 537_000) arrived:
    // GOP 1 start (90_000) + retention (270_000) = 360_000 <= 537_000 -> GOP 0 evicted.
    // GOP 2 start (180_000) + retention (270_000) = 450_000 <= 537_000 -> GOP 1 evicted.
    // GOP 3 start (270_000) + retention (270_000) = 540_000 > 537_000 -> GOP 2 retained.
    // Therefore: GOPs 0 and 1 (frames 0..59) evicted, GOPs 2, 3, 4, 5 (frames 60..179) retained!
    assert_eq!(
        buffer.gop_count(),
        4,
        "Buffer must contain exactly 4 retained GOPs (GOPs 2, 3, 4, 5)"
    );

    // 4. Export retained replay clip
    let stats = buffer
        .export_replay_clip(&export_path)
        .expect("exporting replay clip failed");

    assert!(export_path.exists(), "Exported .h264 file must exist");

    // The temporary `<path>.tmp` file must have been cleanly renamed and not exist
    let tmp_path = export_path.with_file_name("replay_clip_test.h264.tmp");
    assert!(
        !tmp_path.exists(),
        "Temporary .tmp file must not remain on disk"
    );

    let file_bytes = fs::read(&export_path).expect("reading exported file failed");
    assert_eq!(file_bytes.len(), stats.bytes);

    // 5. Independently construct the expected sequence:
    // [SPS][PPS] followed by frames 60..180
    let mut expected_sequence = Vec::new();
    expected_sequence.extend_from_slice(&sps_nal);
    expected_sequence.extend_from_slice(&pps_nal);
    for f in &frames[60..180] {
        expected_sequence.extend_from_slice(f);
    }

    // 6. Assert content equality: Byte-for-byte exact match
    assert_eq!(
        file_bytes, expected_sequence,
        "Exported file bytes must match independently built packet sequence byte-for-byte"
    );

    // 7. Assert file begins with 00 00 00 01 SPS, PPS, IDR
    // Start code 1: SPS
    assert_eq!(&file_bytes[0..4], &[0x00, 0x00, 0x00, 0x01]);
    assert_eq!(file_bytes[4] & 0x1F, 7, "First NAL must be SPS");

    // Start code 2: PPS
    let sps_len = sps_nal.len();
    assert_eq!(&file_bytes[sps_len..sps_len + 4], &[0x00, 0x00, 0x00, 0x01]);
    assert_eq!(file_bytes[sps_len + 4] & 0x1F, 8, "Second NAL must be PPS");

    // Start code 3: IDR
    let sps_pps_len = sps_len + pps_nal.len();
    assert_eq!(
        &file_bytes[sps_pps_len..sps_pps_len + 4],
        &[0x00, 0x00, 0x00, 0x01]
    );
    assert_eq!(
        file_bytes[sps_pps_len + 4] & 0x1F,
        5,
        "Third NAL must be IDR keyframe"
    );

    // 8. Assert first retained frame is frame 60 (an IDR)
    let first_frame_len = frames[60].len();
    assert_eq!(
        &file_bytes[sps_pps_len..sps_pps_len + first_frame_len],
        &frames[60][..],
        "First retained frame in bitstream must be frame 60 IDR"
    );

    // 9. Assert evicted frames (frames 0..59) are completely absent from the exported file
    for i in 0..60 {
        let frame_payload = &frames[i][5..]; // skip 4-byte start code + 1-byte header
        let found = file_bytes
            .windows(frame_payload.len())
            .any(|window| window == frame_payload);
        assert!(
            !found,
            "Evicted frame {} must not be present in exported replay file",
            i
        );
    }
}

#[test]
fn test_live_recorder_and_dvr_manager_e2e() {
    let dir = tempdir().expect("failed to create temporary test directory");
    let rec_path = dir.path().join("live_stream_recording.h264");

    let recorder = LiveRecorder::default();
    recorder
        .start_live_recording(&rec_path)
        .expect("start_live_recording failed");

    let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E];
    let pps = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80];
    let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x11, 0x22, 0x33];
    let non_idr = vec![0x00, 0x00, 0x00, 0x01, 0x61, 0x44, 0x55, 0x66];

    // Non-IDR before IDR is skipped
    recorder.push_nal(&non_idr, 100);

    // Feed SPS, PPS, IDR, then subsequent non-IDR
    recorder.push_nal(&sps, 200);
    recorder.push_nal(&pps, 200);
    recorder.push_nal(&idr, 200);
    recorder.push_nal(&non_idr, 300);

    let stats = recorder
        .stop_live_recording()
        .expect("stop_live_recording failed");

    assert!(rec_path.exists());
    let file_bytes = fs::read(&rec_path).expect("reading recorded file failed");
    assert_eq!(file_bytes.len(), stats.bytes);

    let mut expected = Vec::new();
    expected.extend_from_slice(&sps);
    expected.extend_from_slice(&pps);
    expected.extend_from_slice(&idr);
    expected.extend_from_slice(&non_idr);

    assert_eq!(file_bytes, expected);

    // DvrManager integration check
    let manager = DvrManager::new();
    manager.push_nal(&sps, 0).expect("manager push SPS failed");
    manager.push_nal(&pps, 0).expect("manager push PPS failed");
    manager.push_nal(&idr, 0).expect("manager push IDR failed");

    let status = manager.status();
    assert_eq!(status.idr_count, 1);
    assert!(!status.is_recording);
}
