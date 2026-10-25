// Outside Judge Integration Test: src-tauri/tests/smpte_generator_test.rs
//
// Validates Step 8 — 60fps SMPTE YUV420p Pattern Generator & Packed Binary Pipe
// for "JCB AirPlay" (jcb-airplay).
//
// Test coverage:
// 1. Exact ITU-R BT.709 luma/chroma plane byte lengths for standard landscape (1080p).
// 2. Exact ITU-R BT.709 luma/chroma plane byte lengths for iPhone portrait (1080x1920 / 9:16).
// 3. Animated radar and scanline cursor progression across sequential frame offsets.
// 4. Zero-copy packed binary frame serialization/deserialization and header bounds.
// 5. VideoStreamState async thread management (start/stop/pull).

use jcb_airplay_lib::media::{
    generate_smpte_frame, DecodedFrame, VideoStreamState, PACKED_FRAME_HEADER_LEN,
    PACKED_FRAME_MAGIC, SMPTE_BT709_COLORS,
};

#[test]
fn test_smpte_generator_landscape_1080p_plane_lengths_and_geometry() {
    let width = 1920u32;
    let height = 1080u32;
    let frame = generate_smpte_frame(width, height, 0);

    assert_eq!(frame.width, 1920);
    assert_eq!(frame.height, 1080);
    assert_eq!(frame.y_stride, 1920);
    assert_eq!(frame.uv_stride, 960);

    // Exact Planar YUV420p plane sizes:
    // Y = width * height
    // U = (width / 2) * (height / 2)
    // V = (width / 2) * (height / 2)
    let expected_y_len = (width * height) as usize;
    let expected_uv_len = ((width / 2) * (height / 2)) as usize;

    assert_eq!(frame.y_plane.len(), expected_y_len);
    assert_eq!(frame.u_plane.len(), expected_uv_len);
    assert_eq!(frame.v_plane.len(), expected_uv_len);
    assert!(frame.is_valid_yuv420p());

    // Verify radar scanline at column 0
    assert_eq!(frame.y_plane[0], 240);

    // Verify first color bar (75% White) outside radar scanline (col 20) matches SMPTE BT.709 color specification
    let test_col = 20usize;
    let white = &SMPTE_BT709_COLORS[0];
    assert_eq!(frame.y_plane[test_col], white.y);
    assert_eq!(frame.u_plane[test_col / 2], white.u);
    assert_eq!(frame.v_plane[test_col / 2], white.v);
}

#[test]
fn test_smpte_generator_iphone_portrait_plane_lengths_and_geometry() {
    // iPhone Screen Mirroring Native Portrait Resolution: 1080x1920 (9:16)
    let width = 1080u32;
    let height = 1920u32;
    let frame = generate_smpte_frame(width, height, 0);

    assert_eq!(frame.width, 1080);
    assert_eq!(frame.height, 1920);
    assert_eq!(frame.y_stride, 1080);
    assert_eq!(frame.uv_stride, 540);

    let expected_y_len = (width * height) as usize;
    let expected_uv_len = ((width / 2) * (height / 2)) as usize;

    assert_eq!(frame.y_plane.len(), expected_y_len);
    assert_eq!(frame.u_plane.len(), expected_uv_len);
    assert_eq!(frame.v_plane.len(), expected_uv_len);
    assert!(frame.is_valid_yuv420p());
}

#[test]
fn test_smpte_generator_moving_radar_offsets() {
    let width = 1280u32;
    let height = 720u32;

    let frame_0 = generate_smpte_frame(width, height, 0);
    let frame_15 = generate_smpte_frame(width, height, 15);
    let frame_30 = generate_smpte_frame(width, height, 30);
    let frame_60 = generate_smpte_frame(width, height, 60);

    // Each sequential frame must have distinct luma bytes due to the horizontal scanline
    // and rotating radar sweep moving across the display.
    assert_ne!(
        frame_0.y_plane, frame_15.y_plane,
        "Radar position at index 0 must differ from index 15"
    );
    assert_ne!(
        frame_15.y_plane, frame_30.y_plane,
        "Radar position at index 15 must differ from index 30"
    );
    assert_ne!(
        frame_30.y_plane, frame_60.y_plane,
        "Radar position at index 30 must differ from index 60"
    );

    // Verify timestamp increments properly with 60fps cadence
    assert_eq!(frame_0.timestamp_ntp, 0);
    assert_eq!(frame_60.timestamp_ntp, 1_000_000); // 1 second = 1,000,000 us
}

#[test]
fn test_packed_frame_binary_payload_header_and_planes() {
    let width = 640u32;
    let height = 360u32;
    let frame = generate_smpte_frame(width, height, 120);

    let packed = frame.to_packed_bytes();

    // Verify 28-byte binary header
    assert_eq!(packed.len(), PACKED_FRAME_HEADER_LEN + (640 * 360) + (320 * 180 * 2));
    assert_eq!(&packed[0..4], &PACKED_FRAME_MAGIC);

    let parsed_width = u32::from_le_bytes(packed[4..8].try_into().unwrap());
    let parsed_height = u32::from_le_bytes(packed[8..12].try_into().unwrap());
    let parsed_ts = u64::from_le_bytes(packed[12..20].try_into().unwrap());
    let parsed_y_stride = u32::from_le_bytes(packed[20..24].try_into().unwrap());
    let parsed_uv_stride = u32::from_le_bytes(packed[24..28].try_into().unwrap());

    assert_eq!(parsed_width, 640);
    assert_eq!(parsed_height, 360);
    assert_eq!(parsed_ts, (120 * 1_000_000) / 60);
    assert_eq!(parsed_y_stride, 640);
    assert_eq!(parsed_uv_stride, 320);

    // Verify full roundtrip deserialization into DecodedFrame
    let recovered = DecodedFrame::from_packed_bytes(&packed).expect("from_packed_bytes failed");
    assert_eq!(recovered.width, frame.width);
    assert_eq!(recovered.height, frame.height);
    assert_eq!(recovered.y_plane, frame.y_plane);
    assert_eq!(recovered.u_plane, frame.u_plane);
    assert_eq!(recovered.v_plane, frame.v_plane);
    assert!(recovered.is_valid_yuv420p());
}

#[tokio::test]
async fn test_video_stream_state_start_stop_and_frame_pull() {
    let state = VideoStreamState::new();
    assert!(!state.is_running());
    assert!(state.get_latest_frame().is_none());

    // Start 60fps generator
    state.start_test_pattern(640, 360);
    assert!(state.is_running());

    // Allow generator loop to produce frames
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let frame_opt = state.get_latest_frame();
    assert!(frame_opt.is_some(), "Stream state must contain generated frame");
    let frame_bytes = frame_opt.unwrap();
    assert_eq!(&frame_bytes[0..4], &PACKED_FRAME_MAGIC);

    // Stop generator
    state.stop_test_pattern();
    assert!(!state.is_running());
}
