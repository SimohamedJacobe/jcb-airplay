// Outside Judge Integration Test: src-tauri/tests/decoder_pipeline_test.rs
//
// Validates Step 7 — Low-Latency H.264 Video Decoder Pipeline & Jitter Gatekeeper
// for "JCB AirPlay" (jcb-airplay).
//
// Test coverage:
// 1. Burst of 120 Annex-B H.264 packets (SPS/PPS, IDR keyframes, non-IDR slices)
//    under simulated queue congestion:
//    - Non-reference frames (nal_ref_idc == 0 / non-IDR) shed during simulated backlog.
//    - Keyframes (IDR / SPS / PPS) NEVER dropped, even under severe queue congestion.
//    - Output DecodedFrame buffers contain valid planar YUV420p plane dimensions:
//      Y = width * height, U = (width/2) * (height/2), V = (width/2) * (height/2).
//    - Decoder telemetry metrics: frames_decoded, frames_dropped_late, keyframes_processed,
//      and avg_decode_us.
// 2. SPS dimension parser standards conformance across multiple resolutions
//    (4K 3840x2160, 1080p 1920x1080, 720p 1280x720, 480p 854x480, 360p 640x360).
// 3. Jitter Gatekeeper latency budget controller enforcing 2-frame ceiling (33.3ms at 60fps).
// 4. End-to-end integration: AES-128-CTR encrypted AVCC packets → Assembler → Gatekeeper → Decoder.

use jcb_airplay_lib::{
    crypto::StreamKey,
    media::{
        build_test_sps, parse_sps_dimensions, AirPlayStreamHeader, AnnexBFrame, DecodedFrame,
        H264AnnexBAssembler, H264DecoderEngine, JitterGatekeeper, SoftwareH264DecoderEngine,
        StreamPacket, StreamPayloadType, ANNEXB_START_CODE, DEFAULT_LATENCY_CEILING_US,
    },
};

// ─── Helper: construct an Annex-B packet with specified NAL byte and payload ──

fn build_annexb_packet(nal_byte: u8, payload_len: usize) -> AnnexBFrame {
    let mut data = Vec::with_capacity(4 + 1 + payload_len);
    data.extend_from_slice(&ANNEXB_START_CODE);
    data.push(nal_byte);
    // Fill payload deterministically
    for i in 0..payload_len {
        data.push((i & 0xFF) as u8);
    }
    AnnexBFrame::from_annexb(data)
}

// ─── Test 1: 120-Packet Burst with Simulated Queue Congestion ─────────────────

#[test]
fn test_decoder_pipeline_120_packet_burst_with_congestion() {
    let mut decoder = SoftwareH264DecoderEngine::new();

    // 1. Initialize decoder with 1080p SPS
    let sps_annexb = build_test_sps(1920, 1080);
    let mut sps_pps_data = sps_annexb;
    sps_pps_data.extend_from_slice(&ANNEXB_START_CODE);
    sps_pps_data.extend_from_slice(&[0x68, 0xCE, 0x38, 0x80]); // PPS
    let config_frame = AnnexBFrame::from_annexb(sps_pps_data);

    let config_res = decoder
        .decode_frame(&config_frame, 0)
        .expect("config decode");
    assert!(
        config_res.is_none(),
        "Parameter sets alone must produce no picture"
    );
    assert_eq!(
        decoder.dimensions(),
        Some((1920, 1080)),
        "SPS dimensions must update decoder to 1920x1080"
    );

    let mut gatekeeper = JitterGatekeeper::new(decoder);
    assert_eq!(gatekeeper.max_queue_depth(), 2);
    assert_eq!(gatekeeper.latency_ceiling_us(), DEFAULT_LATENCY_CEILING_US);

    let mut total_keyframes_sent = 0u64;
    let mut keyframe_indices = Vec::new();
    let mut decoded_frames: Vec<DecodedFrame> = Vec::new();

    // 2. Generate and process burst of 120 packets
    for i in 1..=120 {
        let timestamp_ntp = (i as u64) * 16_666; // ~60fps cadence (16.666 ms per frame)

        // Queue congestion simulation:
        // Indices 20..=45: backlog of 6 packets (exceeds 2-frame ceiling)
        // Indices 70..=95: backlog of 8 packets (exceeds 2-frame ceiling)
        // Other indices: normal backlog of 1 packet (healthy)
        let queue_depth = if (20..=45).contains(&i) {
            6
        } else if (70..=95).contains(&i) {
            8
        } else {
            1
        };

        // Frame type pattern:
        // Keyframes at intervals (e.g., frames 1, 30, 60, 90).
        // Note: Frames 30 and 90 fall directly inside the simulated congestion intervals!
        let is_keyframe_slot = i == 1 || i == 30 || i == 60 || i == 90;

        let frame = if is_keyframe_slot {
            total_keyframes_sent += 1;
            keyframe_indices.push(i);
            // IDR keyframe: nal_ref_idc = 3, nal_unit_type = 5 (0x65)
            build_annexb_packet(0x65, 512)
        } else if i % 2 == 0 {
            // Non-reference slice: nal_ref_idc = 0, nal_unit_type = 1 (0x01)
            build_annexb_packet(0x01, 256)
        } else {
            // Reference slice: nal_ref_idc = 2, nal_unit_type = 1 (0x41)
            build_annexb_packet(0x41, 256)
        };

        let result = gatekeeper
            .process_frame(&frame, timestamp_ntp, queue_depth)
            .expect("process_frame failed");

        if let Some(decoded) = result {
            // Validate Planar YUV420p Geometry for every decoded frame:
            // Y = width * height
            // U = (width/2) * (height/2)
            // V = (width/2) * (height/2)
            assert_eq!(
                decoded.width, 1920,
                "Decoded frame width must match SPS width"
            );
            assert_eq!(
                decoded.height, 1080,
                "Decoded frame height must match SPS height"
            );
            assert_eq!(
                decoded.y_stride, 1920,
                "Y stride must equal frame width"
            );
            assert_eq!(
                decoded.uv_stride, 960,
                "UV stride must equal frame width / 2"
            );
            assert_eq!(
                decoded.y_plane.len(),
                1920 * 1080,
                "Y plane size must equal width * height"
            );
            assert_eq!(
                decoded.u_plane.len(),
                (1920 / 2) * (1080 / 2),
                "U plane size must equal (width/2) * (height/2)"
            );
            assert_eq!(
                decoded.v_plane.len(),
                (1920 / 2) * (1080 / 2),
                "V plane size must equal (width/2) * (height/2)"
            );
            assert!(
                decoded.is_valid_yuv420p(),
                "is_valid_yuv420p() must return true"
            );
            assert_eq!(
                decoded.timestamp_ntp, timestamp_ntp,
                "NTP timestamp must be preserved"
            );

            decoded_frames.push(decoded);
        }
    }

    let telemetry = gatekeeper.telemetry();

    // 3. Verify Gatekeeper Assertions:
    // a) Keyframes were NEVER dropped, even under backlog:
    assert_eq!(
        telemetry.keyframes_processed, total_keyframes_sent,
        "Every IDR keyframe must be processed and never shed by gatekeeper"
    );
    assert_eq!(
        telemetry.keyframes_processed, 4,
        "Exactly 4 keyframes must have been processed"
    );

    // b) Non-reference frames were shed during simulated congestion:
    assert!(
        telemetry.frames_dropped_late > 0,
        "Gatekeeper must shed late/non-reference frames during backlog"
    );

    // c) Telemetry consistency:
    let total_slice_frames = 120u64;
    assert_eq!(
        telemetry.frames_decoded + telemetry.frames_dropped_late,
        total_slice_frames,
        "Sum of decoded + dropped frames must equal total slice frames sent"
    );

    // d) Decode time metric:
    assert!(
        telemetry.avg_decode_us >= 0.0,
        "Average decode time must be non-negative"
    );
    assert!(
        !decoded_frames.is_empty(),
        "At least one frame must have been decoded"
    );
}

// ─── Test 2: SPS Dimension Parser Standards Conformance ───────────────────────

#[test]
fn test_sps_dimension_parsing_standards_conformance() {
    let test_cases = [
        (3840u32, 2160u32, "4K UHD"),
        (1920, 1080, "1080p FHD"),
        (1280, 720, "720p HD"),
        (854, 480, "480p SD"),
        (640, 360, "360p Low-res"),
    ];

    for &(w, h, label) in &test_cases {
        let sps = build_test_sps(w, h);
        let parsed = parse_sps_dimensions(&sps);
        assert_eq!(
            parsed,
            Some((w, h)),
            "SPS dimension parser failed for {label} ({w}x{h})"
        );
    }

    // Malformed / truncated SPS rejection
    assert_eq!(
        parse_sps_dimensions(&[]),
        None,
        "Empty SPS must return None"
    );
    assert_eq!(
        parse_sps_dimensions(&[0x67, 0x42]),
        None,
        "Truncated SPS must return None"
    );
    assert_eq!(
        parse_sps_dimensions(&[0x00, 0x00, 0x00, 0x01, 0x67]),
        None,
        "Start-code only SPS must return None"
    );
}

// ─── Test 3: Jitter Gatekeeper Latency Budget Controller ───────────────────────

#[test]
fn test_jitter_gatekeeper_latency_budget_controller() {
    let decoder = SoftwareH264DecoderEngine::new();
    let mut gatekeeper = JitterGatekeeper::with_budget(decoder, 2, 33_333);

    let idr_frame = build_annexb_packet(0x65, 128); // Keyframe
    let non_ref_frame = build_annexb_packet(0x01, 128); // Non-reference slice

    // Case 1: Healthy packet within budget (queue_depth=1, latency=10ms < 33.3ms)
    let res1 = gatekeeper
        .process_frame_with_latency(&non_ref_frame, 1000, 1, 10_000)
        .unwrap();
    assert!(res1.is_some(), "Healthy packet must be admitted");
    assert_eq!(gatekeeper.telemetry().frames_decoded, 1);
    assert_eq!(gatekeeper.telemetry().frames_dropped_late, 0);

    // Case 2: Packet exceeds latency ceiling (latency=40ms > 33.3ms), even with queue_depth=1
    let res2 = gatekeeper
        .process_frame_with_latency(&non_ref_frame, 2000, 1, 40_000)
        .unwrap();
    assert!(res2.is_none(), "Late packet must be shed");
    assert_eq!(gatekeeper.telemetry().frames_dropped_late, 1);

    // Case 3: IDR Keyframe exceeds latency ceiling (latency=50ms > 33.3ms)
    // Keyframes MUST NOT be shed!
    let res3 = gatekeeper
        .process_frame_with_latency(&idr_frame, 3000, 1, 50_000)
        .unwrap();
    assert!(
        res3.is_some(),
        "Keyframes must NEVER be shed even if latency budget exceeded"
    );
    assert_eq!(gatekeeper.telemetry().keyframes_processed, 1);
    assert_eq!(gatekeeper.telemetry().frames_decoded, 2);
    assert_eq!(gatekeeper.telemetry().frames_dropped_late, 1);
}

// ─── Test 4: End-to-End Pipeline (AES-CTR → Assembler → Gatekeeper → Decoder) ─

#[test]
fn test_end_to_end_crypto_assembler_gatekeeper_pipeline() {
    let key = StreamKey::from_bytes(&[0x33u8; 16], &[0x77u8; 16]).unwrap();
    let mut assembler = H264AnnexBAssembler::new().with_stream_key(&key);
    let decoder = SoftwareH264DecoderEngine::new();
    let mut gatekeeper = JitterGatekeeper::new(decoder);

    // 1. CodecConfig packet (SPS + PPS)
    let sps = build_test_sps(1280, 720);
    // sps has Annex-B start code, strip it to create raw SPS for AVCC
    let sps_raw = &sps[4..];
    let pps_raw = &[0x68u8, 0xCE, 0x38, 0x80];

    let mut avcc_record = vec![0x01u8, 0x42, 0x00, 0x1F, 0xFF, 0xE1];
    avcc_record.extend(&(sps_raw.len() as u16).to_be_bytes());
    avcc_record.extend_from_slice(sps_raw);
    avcc_record.push(0x01); // numPPS
    avcc_record.extend(&(pps_raw.len() as u16).to_be_bytes());
    avcc_record.extend_from_slice(pps_raw);

    let config_header = AirPlayStreamHeader {
        payload_size: avcc_record.len() as u32,
        payload_type: StreamPayloadType::CodecConfig,
        payload_option: 0,
        timestamp_ntp: 0,
        source_width: 1280.0,
        source_height: 720.0,
        display_width: 1280.0,
        display_height: 720.0,
        reserved1: [0; 16],
        reserved2: [0; 80],
    };

    let config_packet = StreamPacket {
        header: config_header,
        payload: avcc_record,
    };

    let config_out = gatekeeper
        .process_packet(&mut assembler, config_packet, 1)
        .expect("process codec config packet");
    assert!(config_out.is_none());

    // 2. Encrypt an AVCC IDR video packet using reference CTR keystream
    let idr_slice_nal = &[0x65u8, 0x88, 0x84, 0x00, 0x55, 0xAA];
    let mut avcc_video = Vec::new();
    avcc_video.extend(&(idr_slice_nal.len() as u32).to_be_bytes());
    avcc_video.extend_from_slice(idr_slice_nal);

    // Encrypt plaintext AVCC video with sender CTR processor
    let mut sender_cipher = jcb_airplay_lib::media::CtrStreamProcessor::new(&key);
    let mut encrypted_payload = avcc_video;
    sender_cipher.apply(&mut encrypted_payload);

    let video_header = AirPlayStreamHeader {
        payload_size: encrypted_payload.len() as u32,
        payload_type: StreamPayloadType::VideoBitstream,
        payload_option: 0,
        timestamp_ntp: 90_000,
        source_width: 1280.0,
        source_height: 720.0,
        display_width: 1280.0,
        display_height: 720.0,
        reserved1: [0; 16],
        reserved2: [0; 80],
    };

    let video_packet = StreamPacket {
        header: video_header,
        payload: encrypted_payload,
    };

    // Process through gatekeeper
    let decoded = gatekeeper
        .process_packet(&mut assembler, video_packet, 1)
        .expect("process video packet")
        .expect("decoded frame expected");

    assert_eq!(decoded.width, 1280);
    assert_eq!(decoded.height, 720);
    assert!(decoded.is_valid_yuv420p());
    assert_eq!(gatekeeper.telemetry().keyframes_processed, 1);
    assert_eq!(gatekeeper.telemetry().frames_decoded, 1);
}
