// Outside Judge Integration Test: src-tauri/tests/nal_assembler_test.rs
//
// Validates Step 6 — Continuous AES-128-CTR Stream Processing &
// H.264 Annex-B NAL Assembler — for JCB AirPlay.
//
// Test coverage:
// 1. AVCDecoderConfigurationRecord exact byte-level SPS/PPS extraction and Annex-B formatting.
// 2. AVCC-to-Annex-B NAL unit conversion with correct start codes and NAL classification.
// 3. Multi-NAL AVCC frame containing SEI + IDR (verifies SPS/PPS prepend at IDR boundary).
// 4. AES-128-CTR keystream continuity across packet chunks: encrypt-then-decrypt through
//    the assembler pipeline, verifying exact plaintext recovery byte-for-byte.
// 5. Deterministic rejection of malformed AVCDecoderConfigurationRecord inputs.
// 6. Truncated AVCC packet graceful handling (no panic).
// 7. End-to-end: SPS/PPS config → encrypted AVCC IDR frame → Annex-B recovery.

use jcb_airplay_lib::{
    crypto::StreamKey,
    media::{
        AnnexBFrame, CtrStreamProcessor, H264AnnexBAssembler, MediaError, NalUnitType,
        ANNEXB_START_CODE,
    },
};

// ─── Helper: build a minimal valid AVCDecoderConfigurationRecord ──────────────

fn build_avcc_record(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut record = vec![
        0x01u8, // configurationVersion
        0x42,   // AVCProfileIndication: Baseline
        0x00,   // profile_compatibility
        0x1F,   // AVCLevelIndication: 3.1
        0xFF,   // 0xFF = 0b111111_11 -> lengthSizeMinusOne = 3 (4-byte lengths)
        0xE1,   // 0xE1 = 0b111_00001 -> numSPS = 1
    ];
    record.extend(&(sps.len() as u16).to_be_bytes());
    record.extend_from_slice(sps);
    record.push(0x01); // numPPS = 1
    record.extend(&(pps.len() as u16).to_be_bytes());
    record.extend_from_slice(pps);
    record
}

// ─── Helper: wrap NAL unit in AVCC 4-byte big-endian length prefix ────────────

fn avcc_wrap(nal_data: &[u8]) -> Vec<u8> {
    let mut out = (nal_data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(nal_data);
    out
}

// ─── Test 1: Exact AVCDecoderConfigurationRecord SPS/PPS extraction ──────────

#[test]
fn test_avcc_decoder_config_record_exact_sps_pps_extraction() {
    // Realistic H.264 Baseline SPS and PPS parameter sets.
    let sps: &[u8] = &[0x67, 0x42, 0x00, 0x1F, 0xD0, 0x0A, 0x09, 0x0B, 0xE8];
    let pps: &[u8] = &[0x68, 0xCE, 0x38, 0x80];

    let record = build_avcc_record(sps, pps);
    let mut asm = H264AnnexBAssembler::new();
    asm.process_codec_config(&record)
        .expect("AVCDecoderConfigurationRecord parse failed");

    assert!(
        asm.has_codec_config(),
        "has_codec_config() must be true after successful parse"
    );

    // Verify cached SPS: must be exactly [0x00 0x00 0x00 0x01] + sps bytes
    let mut expected_sps_annexb = Vec::with_capacity(4 + sps.len());
    expected_sps_annexb.extend_from_slice(&ANNEXB_START_CODE);
    expected_sps_annexb.extend_from_slice(sps);
    assert_eq!(
        asm.cached_sps(),
        expected_sps_annexb.as_slice(),
        "Annex-B SPS mismatch"
    );

    // Verify cached PPS: must be exactly [0x00 0x00 0x00 0x01] + pps bytes
    let mut expected_pps_annexb = Vec::with_capacity(4 + pps.len());
    expected_pps_annexb.extend_from_slice(&ANNEXB_START_CODE);
    expected_pps_annexb.extend_from_slice(pps);
    assert_eq!(
        asm.cached_pps(),
        expected_pps_annexb.as_slice(),
        "Annex-B PPS mismatch"
    );

    // Verify raw start code prefix bytes are exactly 0x00 0x00 0x00 0x01
    assert_eq!(
        &asm.cached_sps()[0..4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "SPS missing Annex-B start code"
    );
    assert_eq!(
        &asm.cached_pps()[0..4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "PPS missing Annex-B start code"
    );
}

// ─── Test 2: Malformed AVCDecoderConfigurationRecord rejection ────────────────

#[test]
fn test_avcc_decoder_config_record_rejection_cases() {
    let mut asm = H264AnnexBAssembler::new();

    // Case 1: too short (< 6 bytes)
    let result = asm.process_codec_config(&[0x01, 0x42, 0x00, 0x1F, 0xFF]);
    assert!(
        matches!(result, Err(MediaError::AvccMalformed(_))),
        "expected AvccMalformed for short payload"
    );

    // Case 2: wrong configurationVersion
    let mut bad_ver = build_avcc_record(b"\x67\x42", b"\x68\xCE");
    bad_ver[0] = 0x02; // version 2 is not supported
    assert!(matches!(
        asm.process_codec_config(&bad_ver),
        Err(MediaError::AvccMalformed(_))
    ));

    // Case 3: unsupported NAL length size (3-byte instead of 4-byte)
    let mut bad_len = build_avcc_record(b"\x67\x42", b"\x68\xCE");
    bad_len[4] = 0xFE; // 0xFE & 0x03 = 2, length_size = 3 (not 4)
    assert!(matches!(
        asm.process_codec_config(&bad_len),
        Err(MediaError::AvccMalformed(_))
    ));

    // Case 4: numSPS = 0 (no SPS entries)
    let mut no_sps = build_avcc_record(b"\x67\x42", b"\x68\xCE");
    no_sps[5] = 0xE0; // low 5 bits = 0 -> numSPS = 0
    assert!(matches!(
        asm.process_codec_config(&no_sps),
        Err(MediaError::AvccMalformed(_))
    ));

    // Case 5: truncated SPS data (claims more bytes than available)
    let mut truncated_sps = vec![0x01u8, 0x42, 0x00, 0x1F, 0xFF, 0xE1];
    truncated_sps.extend(&100u16.to_be_bytes()); // claims 100-byte SPS
    truncated_sps.extend(&[0x67, 0x42]); // only 2 bytes present
    assert!(matches!(
        asm.process_codec_config(&truncated_sps),
        Err(MediaError::AvccMalformed(_))
    ));
}

// ─── Test 3: AVCC Multi-NAL frame with SEI + IDR: exact Annex-B byte stream ──

#[test]
fn test_avcc_multi_nal_sei_plus_idr_frame() {
    let sps: &[u8] = &[0x67, 0x42, 0x00, 0x1F, 0xD0, 0x0A, 0x09];
    let pps: &[u8] = &[0x68, 0xCE, 0x38, 0x80];
    // SEI NAL (type 6)
    let sei_nal: &[u8] = &[0x06, 0x00, 0x04, 0x85, 0x00, 0x80, 0x00];
    // IDR NAL (type 5)
    let idr_nal: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x33, 0xC4, 0x80];

    let record = build_avcc_record(sps, pps);
    let mut asm = H264AnnexBAssembler::new();
    asm.process_codec_config(&record).unwrap();

    // Build AVCC frame: SEI NAL then IDR NAL
    let mut payload: Vec<u8> = Vec::new();
    payload.extend(avcc_wrap(sei_nal));
    payload.extend(avcc_wrap(idr_nal));

    let frame = asm.process_video_bitstream(&mut payload).unwrap();

    // Frame must be classified as a keyframe (contains IDR)
    assert!(frame.is_keyframe, "frame must be keyframe due to IDR NAL");

    // Must contain exactly 2 NAL units: SEI + IDR
    assert_eq!(frame.nal_units.len(), 2);
    assert_eq!(frame.nal_units[0].nal_type, NalUnitType::Sei);
    assert_eq!(frame.nal_units[1].nal_type, NalUnitType::IdrSlice);
    assert_eq!(frame.nal_units[0].length, sei_nal.len());
    assert_eq!(frame.nal_units[1].length, idr_nal.len());

    // Verify exact byte layout:
    // [SEI start code][SEI data][SPS start code][SPS data][PPS start code][PPS data][IDR start code][IDR data]
    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(&ANNEXB_START_CODE);
    expected.extend_from_slice(sei_nal);
    // SPS + PPS prepended before IDR
    expected.extend_from_slice(&ANNEXB_START_CODE);
    expected.extend_from_slice(sps);
    expected.extend_from_slice(&ANNEXB_START_CODE);
    expected.extend_from_slice(pps);
    expected.extend_from_slice(&ANNEXB_START_CODE);
    expected.extend_from_slice(idr_nal);

    assert_eq!(
        frame.data, expected,
        "Annex-B byte stream does not match expected layout"
    );

    // Verify start codes at expected offsets within frame.data
    let sei_nal_offset = frame.nal_units[0].offset;
    let idr_nal_offset = frame.nal_units[1].offset;

    assert_eq!(
        &frame.data[sei_nal_offset..sei_nal_offset + 4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "SEI start code missing at reported offset"
    );
    assert_eq!(
        &frame.data[idr_nal_offset..idr_nal_offset + 4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "IDR start code missing at reported offset"
    );

    // Verify NAL data follows start code correctly
    assert_eq!(
        &frame.data[sei_nal_offset + 4..sei_nal_offset + 4 + sei_nal.len()],
        sei_nal,
        "SEI NAL data mismatch"
    );
    assert_eq!(
        &frame.data[idr_nal_offset + 4..idr_nal_offset + 4 + idr_nal.len()],
        idr_nal,
        "IDR NAL data mismatch"
    );
}

// ─── Test 4: AES-128-CTR keystream continuity across packet chunks ────────────

#[test]
fn test_aes_ctr_keystream_continuity_multi_packet() {
    let key = StreamKey::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                      0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
                                    &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                      0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
        .expect("valid StreamKey");

    // Known plaintext: a 256-byte sequence
    let plaintext: Vec<u8> = (0..=255u8).collect();

    // Reference: encrypt entire 256-byte buffer in one CTR pass
    let mut ref_proc = CtrStreamProcessor::new(&key);
    let mut reference_ciphertext = plaintext.clone();
    ref_proc.apply(&mut reference_ciphertext);

    // Verify encryption is not identity (cipher actually transforms data)
    assert_ne!(reference_ciphertext, plaintext, "CTR must transform plaintext");

    // Now use a fresh CtrStreamProcessor with same key/IV, applied in 4 uneven chunks
    // This simulates 4 successive video bitstream TCP packets arriving from the iPhone.
    let mut chunk_proc = CtrStreamProcessor::new(&key);
    let mut c1 = plaintext[0..64].to_vec();
    let mut c2 = plaintext[64..100].to_vec();
    let mut c3 = plaintext[100..200].to_vec();
    let mut c4 = plaintext[200..256].to_vec();

    chunk_proc.apply(&mut c1);
    chunk_proc.apply(&mut c2);
    chunk_proc.apply(&mut c3);
    chunk_proc.apply(&mut c4);

    let mut chunked_ciphertext = c1;
    chunked_ciphertext.extend(c2);
    chunked_ciphertext.extend(c3);
    chunked_ciphertext.extend(c4);

    assert_eq!(
        chunked_ciphertext, reference_ciphertext,
        "CTR keystream continuity FAIL: chunk-wise result differs from single-pass"
    );
    assert_eq!(
        chunk_proc.bytes_processed(),
        256,
        "bytes_processed counter incorrect"
    );

    // Verify decryption is the inverse (apply CTR to ciphertext restores plaintext)
    let mut decrypt_proc = CtrStreamProcessor::new(&key);
    let mut recovered = reference_ciphertext.clone();
    decrypt_proc.apply(&mut recovered);
    assert_eq!(
        recovered, plaintext,
        "CTR decrypt must recover original plaintext"
    );
}

// ─── Test 5: End-to-end: encrypt AVCC IDR → assembler decrypts → Annex-B ─────

#[test]
fn test_end_to_end_encrypted_avcc_idr_to_annexb() {
    let stream_key = StreamKey::from_bytes(
        &[0x42u8; 16],
        &[0x13, 0x37, 0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF,
          0x42, 0x42, 0x42, 0x42, 0xCA, 0xFE, 0xBA, 0xBE],
    )
    .expect("valid StreamKey");

    let sps: &[u8] = &[0x67, 0x42, 0x00, 0x1F, 0xD0, 0x0A, 0x09];
    let pps: &[u8] = &[0x68, 0xCE, 0x38, 0x80];

    // Non-IDR plaintext NAL payload
    let non_idr_plaintext: Vec<u8> = vec![0x61u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11];
    // IDR plaintext NAL payload
    let idr_plaintext: Vec<u8> = vec![0x65u8, 0x88, 0x84, 0x01, 0x02, 0x03, 0x04, 0x05];

    // Simulate: two consecutive AVCC packets arrive from iOS.
    // Packet 1: non-IDR wrapped in AVCC
    let mut pkt1 = avcc_wrap(&non_idr_plaintext);
    // Packet 2: IDR wrapped in AVCC
    let mut pkt2 = avcc_wrap(&idr_plaintext);

    // Encrypt both packets' AVCC data with continuous CTR (as iPhone would send)
    let mut encrypt_proc = CtrStreamProcessor::new(&stream_key);
    encrypt_proc.apply(&mut pkt1);
    encrypt_proc.apply(&mut pkt2);

    // Set up assembler with the same stream key and SPS/PPS
    let record = build_avcc_record(sps, pps);
    let mut asm = H264AnnexBAssembler::new().with_stream_key(&stream_key);
    asm.process_codec_config(&record).unwrap();

    // Process encrypted packet 1 (non-IDR)
    let frame1: AnnexBFrame = asm.process_video_bitstream(&mut pkt1).unwrap();
    assert!(!frame1.is_keyframe);
    assert_eq!(frame1.nal_units.len(), 1);
    let nal1 = &frame1.nal_units[0];
    assert_eq!(nal1.nal_type, NalUnitType::NonIdrSlice);

    // Verify decrypted NAL data matches original plaintext
    let recovered_nal1 = &frame1.data[nal1.offset + 4..nal1.offset + 4 + nal1.length];
    assert_eq!(
        recovered_nal1, non_idr_plaintext.as_slice(),
        "non-IDR NAL: decrypted payload mismatch"
    );

    // Verify start code is present
    assert_eq!(
        &frame1.data[nal1.offset..nal1.offset + 4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "non-IDR start code missing"
    );

    // Process encrypted packet 2 (IDR — continuous CTR must continue from packet 1's position)
    let frame2: AnnexBFrame = asm.process_video_bitstream(&mut pkt2).unwrap();
    assert!(frame2.is_keyframe);
    assert_eq!(frame2.nal_units.len(), 1);
    let nal2 = &frame2.nal_units[0];
    assert_eq!(nal2.nal_type, NalUnitType::IdrSlice);

    // Verify decrypted IDR NAL data matches original plaintext
    let recovered_nal2 = &frame2.data[nal2.offset + 4..nal2.offset + 4 + nal2.length];
    assert_eq!(
        recovered_nal2, idr_plaintext.as_slice(),
        "IDR NAL: decrypted payload mismatch (CTR continuity broken?)"
    );

    // Verify SPS + PPS were prepended before the IDR NAL
    let sps_annexb_len = 4 + sps.len();
    let pps_annexb_len = 4 + pps.len();
    let idr_nal_start = sps_annexb_len + pps_annexb_len;
    assert!(
        frame2.data.len() >= idr_nal_start + 4 + idr_plaintext.len(),
        "IDR frame too short to contain SPS+PPS+IDR"
    );
    // Verify SPS start code at offset 0
    assert_eq!(
        &frame2.data[0..4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "SPS start code missing at frame2 offset 0"
    );
    // Verify SPS data
    assert_eq!(
        &frame2.data[4..4 + sps.len()],
        sps,
        "SPS data mismatch in IDR frame"
    );
    // Verify PPS start code
    assert_eq!(
        &frame2.data[sps_annexb_len..sps_annexb_len + 4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "PPS start code missing"
    );
    // Verify PPS data
    assert_eq!(
        &frame2.data[sps_annexb_len + 4..sps_annexb_len + 4 + pps.len()],
        pps,
        "PPS data mismatch in IDR frame"
    );
    // Verify IDR start code
    assert_eq!(
        &frame2.data[idr_nal_start..idr_nal_start + 4],
        &[0x00u8, 0x00, 0x00, 0x01],
        "IDR start code missing at expected offset"
    );
}

// ─── Test 6: Non-IDR multi-NAL frame with multiple slice types ────────────────

#[test]
fn test_multi_nal_non_idr_frame_classification() {
    let mut asm = H264AnnexBAssembler::new();

    // Build an AVCC frame with 3 NAL units: SEI + NonIDR + NonIDR
    let sei: &[u8] = &[0x06, 0x05, 0xFF, 0xFF, 0xC4];
    let slice1: &[u8] = &[0x61, 0x11, 0x22, 0x33];
    let slice2: &[u8] = &[0x61, 0xAA, 0xBB, 0xCC];

    let mut payload: Vec<u8> = Vec::new();
    payload.extend(avcc_wrap(sei));
    payload.extend(avcc_wrap(slice1));
    payload.extend(avcc_wrap(slice2));

    let frame = asm.process_video_bitstream(&mut payload).unwrap();

    assert!(!frame.is_keyframe, "frame must NOT be keyframe (no IDR)");
    assert_eq!(frame.nal_units.len(), 3);
    assert_eq!(frame.nal_units[0].nal_type, NalUnitType::Sei);
    assert_eq!(frame.nal_units[1].nal_type, NalUnitType::NonIdrSlice);
    assert_eq!(frame.nal_units[2].nal_type, NalUnitType::NonIdrSlice);
    assert_eq!(frame.nal_units[0].length, sei.len());
    assert_eq!(frame.nal_units[1].length, slice1.len());
    assert_eq!(frame.nal_units[2].length, slice2.len());

    // Verify each reported offset has the Annex-B start code
    for nal in &frame.nal_units {
        assert_eq!(
            &frame.data[nal.offset..nal.offset + 4],
            &[0x00u8, 0x00, 0x00, 0x01],
            "start code missing at offset {} for {:?}",
            nal.offset,
            nal.nal_type
        );
    }

    // Verify total frame byte length
    let expected_len = (4 + sei.len()) + (4 + slice1.len()) + (4 + slice2.len());
    assert_eq!(frame.data.len(), expected_len);
}

// ─── Test 7: Truncated AVCC packet — graceful handling, no panic ──────────────

#[test]
fn test_truncated_avcc_packet_no_panic() {
    let mut asm = H264AnnexBAssembler::new();

    // Exact truncation: length prefix claims 1000 bytes but only 10 follow
    let mut payload: Vec<u8> = 1000u32.to_be_bytes().to_vec();
    payload.extend(&[0x65u8; 10]);
    let frame = asm.process_video_bitstream(&mut payload).unwrap();
    assert!(frame.nal_units.is_empty(), "truncated NAL must produce empty NAL list");
    assert!(frame.data.is_empty(), "truncated NAL frame data must be empty");
    assert!(!frame.is_keyframe);

    // Zero-length NAL prefix (degenerate case)
    let mut zero_len_payload: Vec<u8> = 0u32.to_be_bytes().to_vec();
    zero_len_payload.push(0x65);
    let frame2 = asm.process_video_bitstream(&mut zero_len_payload).unwrap();
    assert!(frame2.nal_units.is_empty());

    // Empty payload (zero bytes)
    let mut empty = Vec::new();
    let frame3 = asm.process_video_bitstream(&mut empty).unwrap();
    assert!(frame3.nal_units.is_empty());
    assert!(frame3.data.is_empty());
}

// ─── Test 8: NalUnit offset integrity — offsets index valid start codes ───────

#[test]
fn test_nal_unit_offsets_index_valid_start_codes() {
    let sps: &[u8] = &[0x27, 0x42, 0x00, 0x1F];
    let pps: &[u8] = &[0x28, 0xCE, 0x38];
    let idr: &[u8] = &[0x65, 0xB8, 0x04, 0x00];
    let non_idr: &[u8] = &[0x41, 0x9A, 0x03];

    let record = build_avcc_record(sps, pps);
    let mut asm = H264AnnexBAssembler::new();
    asm.process_codec_config(&record).unwrap();

    // Frame: IDR + NonIDR
    let mut payload: Vec<u8> = Vec::new();
    payload.extend(avcc_wrap(idr));
    payload.extend(avcc_wrap(non_idr));

    let frame = asm.process_video_bitstream(&mut payload).unwrap();

    assert!(frame.is_keyframe);
    assert_eq!(frame.nal_units.len(), 2);

    for nal in &frame.nal_units {
        // Every recorded offset must be within bounds
        assert!(
            nal.offset + 4 + nal.length <= frame.data.len(),
            "NAL unit {:?} at offset {} + 4 + {} overflows frame.data.len() = {}",
            nal.nal_type,
            nal.offset,
            nal.length,
            frame.data.len()
        );
        // Every start code at the reported offset must be exactly 0x00 0x00 0x00 0x01
        assert_eq!(
            &frame.data[nal.offset..nal.offset + 4],
            &[0x00u8, 0x00, 0x00, 0x01],
            "start code mismatch at offset {} for {:?}",
            nal.offset,
            nal.nal_type
        );
        // NAL data byte following start code must match the original NAL first byte
        let expected_first_byte = match nal.nal_type {
            NalUnitType::IdrSlice => idr[0],
            NalUnitType::NonIdrSlice => non_idr[0],
            _ => unreachable!(),
        };
        assert_eq!(
            frame.data[nal.offset + 4],
            expected_first_byte,
            "NAL first byte mismatch for {:?}",
            nal.nal_type
        );
    }
}
