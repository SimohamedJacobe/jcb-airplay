//! JCB AirPlay — Integration test: crypto vectors
//!
//! Deterministic Outside Judge test suite verifying the multi-phase
//! `PairSetup -> PairVerify -> SessionKeyDerivation -> AES-128-CTR Roundtrip`
//! pipeline, byte-for-byte accuracy, and negative failure modes without panicking.

use ed25519_dalek::SigningKey;
use jcb_airplay_lib::crypto::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, CryptoError, PairSetupHandler, PairVerifyClient,
    PairVerifyHandler, PairVerifyState, SessionKeySetup, StreamKey,
};

#[test]
fn test_full_pipeline_pair_setup_verify_session_derivation_aes_ctr() {
    // 1. Deterministic Identity Setup
    let client_ed_seed = [0x11u8; 32];
    let server_ed_seed = [0x22u8; 32];
    let client_signing_key = SigningKey::from_bytes(&client_ed_seed);
    let server_signing_key = SigningKey::from_bytes(&server_ed_seed);

    let client_ed_pub = client_signing_key.verifying_key().to_bytes();
    let server_ed_pub = server_signing_key.verifying_key().to_bytes();

    // 2. PairSetup Stage
    let mut setup_handler = PairSetupHandler::with_signing_key(server_signing_key.clone());
    assert_eq!(setup_handler.public_key(), server_ed_pub);

    let setup_response = setup_handler
        .handle_setup(&client_ed_pub)
        .expect("PairSetup must succeed with 32-byte client public key");
    assert_eq!(
        setup_response.len(),
        32,
        "PairSetup response must be 32 bytes"
    );
    assert_eq!(
        setup_response, server_ed_pub,
        "PairSetup response must match server public key"
    );
    assert_eq!(
        setup_handler.client_public_key(),
        Some(client_ed_pub),
        "Server must store client public identity"
    );

    // 3. PairVerify Stage
    let mut server_verify = PairVerifyHandler::new(server_signing_key.clone());
    assert_eq!(server_verify.state(), PairVerifyState::Unverified);

    let mut client_verify = PairVerifyClient::new(
        client_signing_key.clone(),
        server_signing_key.verifying_key(),
    );

    // Client generates Phase 1 packet (68 bytes)
    let phase1_pkt = client_verify.build_phase1_request();
    assert_eq!(phase1_pkt.len(), 68);

    // Server processes Phase 1 packet and returns 96 bytes
    let phase1_resp = server_verify
        .handle_phase1(&phase1_pkt)
        .expect("Server Phase 1 must succeed");
    assert_eq!(phase1_resp.len(), 96);
    assert_eq!(server_verify.state(), PairVerifyState::Phase1Complete);

    // Client processes Phase 1 response and generates Phase 2 packet (68 bytes)
    let phase2_pkt = client_verify
        .process_phase1_response(&phase1_resp)
        .expect("Client Phase 1 processing and signature verification must succeed");
    assert_eq!(phase2_pkt.len(), 68);

    // Server processes Phase 2 packet and verifies client signature
    let phase2_resp = server_verify
        .handle_phase2(&phase2_pkt)
        .expect("Server Phase 2 client signature verification must succeed");
    assert_eq!(phase2_resp.len(), 4);
    assert_eq!(server_verify.state(), PairVerifyState::Verified);

    // Assert that client and server computed identical 32-byte shared secrets
    assert_eq!(
        client_verify.shared_secret(),
        server_verify.shared_secret(),
        "Derived X25519 shared secret must match byte-for-byte between client and server"
    );

    // 4. SessionKeySetup Stage (Challenge/Response & Key Parameter derivation)
    let mut session_setup = SessionKeySetup::new();

    // Step 1: 16-byte challenge exchange
    let client_challenge = [0x5Au8; 16];
    let challenge_response = session_setup
        .handle_challenge(&client_challenge)
        .expect("16-byte challenge must succeed");
    assert_eq!(challenge_response.len(), 16);

    // Step 2: 72-byte session parameter block exchange
    let mut param_block_72 = [0x00u8; 72];
    param_block_72[0..32].copy_from_slice(&server_verify.shared_secret());
    // Fill remaining parameters
    for i in 32..72 {
        param_block_72[i] = (i as u8).wrapping_mul(3);
    }

    let stream_key = session_setup
        .handle_key_exchange(&param_block_72)
        .expect("72-byte session key exchange must succeed");

    // Manually compute expected key and IV using SHA-512 salted hashing
    let expected_key = StreamKey::derive_from_seed(&server_verify.shared_secret());
    assert_eq!(
        stream_key.key, expected_key.key,
        "Derived AES-128 key must match SHA-512 salted derivation byte-for-byte"
    );
    assert_eq!(
        stream_key.iv, expected_key.iv,
        "Derived IV must match SHA-512 salted derivation byte-for-byte"
    );

    // 5. AES-128-CTR Video Payload Roundtrip
    let plaintext_nal_unit = vec![
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0x10, 0xFF, 0xFE, 0x01, 0x02, 0x03, 0x04,
        0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34, 0x56, 0x78,
    ];

    let mut encrypted_buffer = plaintext_nal_unit.clone();
    let seq_num = 42u16;

    // Sender encrypts buffer
    stream_key
        .encrypt_payload(&mut encrypted_buffer, seq_num)
        .expect("Encryption must succeed");
    assert_ne!(
        encrypted_buffer, plaintext_nal_unit,
        "Ciphertext must differ from plaintext"
    );

    // Receiver decrypts buffer
    stream_key
        .decrypt_payload(&mut encrypted_buffer, seq_num)
        .expect("Decryption must succeed");
    assert_eq!(
        encrypted_buffer, plaintext_nal_unit,
        "AES-128-CTR decryption must restore original NAL payload byte-for-byte"
    );
}

#[test]
fn test_session_key_setup_164_byte_frame() {
    let session_setup = SessionKeySetup::new();
    let mut param_block_164 = [0x77u8; 164];
    param_block_164[0..16].copy_from_slice(b"JCB-AirPlay-Seed");

    let stream_key = session_setup
        .handle_key_exchange(&param_block_164)
        .expect("164-byte frame exchange must succeed");

    let expected = StreamKey::derive_from_seed(&param_block_164[0..32]);
    assert_eq!(stream_key.key, expected.key);
    assert_eq!(stream_key.iv, expected.iv);
}

#[test]
fn test_pair_verify_tampered_signature_fails_cleanly() {
    let client_signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let server_signing_key = SigningKey::from_bytes(&[0x44u8; 32]);

    let mut server_verify = PairVerifyHandler::new(server_signing_key.clone());
    let mut client_verify =
        PairVerifyClient::new(client_signing_key, server_signing_key.verifying_key());

    let phase1_pkt = client_verify.build_phase1_request();
    let phase1_resp = server_verify
        .handle_phase1(&phase1_pkt)
        .expect("Phase 1 ok");

    let mut phase2_pkt = client_verify
        .process_phase1_response(&phase1_resp)
        .expect("Client phase 1 ok");

    // Tamper with one byte in the encrypted signature payload
    phase2_pkt[10] ^= 0xFF;

    let result = server_verify.handle_phase2(&phase2_pkt);
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed(_))),
        "Tampered signature must return SignatureVerificationFailed, got: {:?}",
        result
    );
    assert_ne!(
        server_verify.state(),
        PairVerifyState::Verified,
        "State must not transition to Verified on tampered signature"
    );
}

#[test]
fn test_pair_verify_invalid_packet_lengths() {
    let server_signing_key = SigningKey::from_bytes(&[0x55u8; 32]);
    let mut server_verify = PairVerifyHandler::new(server_signing_key);

    // Truncated Phase 1
    let short_phase1 = vec![0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB];
    let res1 = server_verify.handle_phase1(&short_phase1);
    assert!(
        matches!(
            res1,
            Err(CryptoError::InvalidPacketLength {
                expected: 68,
                got: 6
            })
        ),
        "Expected InvalidPacketLength error, got: {:?}",
        res1
    );

    // Truncated Phase 2
    let short_phase2 = vec![0x00, 0x00, 0x00, 0x00];
    let res2 = server_verify.handle_phase2(&short_phase2);
    // Before phase 1 complete, state check or length check fails cleanly
    assert!(res2.is_err());
}

#[test]
fn test_pair_verify_out_of_order_execution() {
    let server_signing_key = SigningKey::from_bytes(&[0x66u8; 32]);
    let mut server_verify = PairVerifyHandler::new(server_signing_key);

    // Call Phase 2 before Phase 1
    let dummy_phase2 = vec![0x00u8; 68];
    let res = server_verify.handle_phase2(&dummy_phase2);
    assert!(
        matches!(res, Err(CryptoError::InvalidState(_))),
        "Calling Phase 2 before Phase 1 must return InvalidState"
    );
}

#[test]
fn test_session_key_setup_invalid_lengths() {
    let mut session_setup = SessionKeySetup::new();

    // Invalid challenge length (e.g. 10 instead of 16)
    let bad_challenge = [0xAAu8; 10];
    let res_c = session_setup.handle_challenge(&bad_challenge);
    assert!(matches!(
        res_c,
        Err(CryptoError::InvalidPacketLength {
            expected: 16,
            got: 10
        })
    ));

    // Invalid parameter block length (e.g. 50 instead of 72 or 164)
    let bad_params = [0xBBu8; 50];
    let res_p = session_setup.handle_key_exchange(&bad_params);
    assert!(matches!(
        res_p,
        Err(CryptoError::InvalidPacketLength {
            expected: 72,
            got: 50
        })
    ));
}

#[test]
fn test_aes_cbc_padding_and_error_handling() {
    let key = [0x12u8; 16];
    let iv = [0x34u8; 16];
    let plaintext = b"Block cipher message for CBC test vector.";

    let ciphertext = aes128_cbc_encrypt(&key, &iv, plaintext).expect("CBC encrypt ok");
    let decrypted = aes128_cbc_decrypt(&key, &iv, &ciphertext).expect("CBC decrypt ok");
    assert_eq!(decrypted, plaintext);

    // Ciphertext with invalid length (not multiple of 16)
    let invalid_ct = vec![0x01, 0x02, 0x03];
    let err = aes128_cbc_decrypt(&key, &iv, &invalid_ct);
    assert!(matches!(err, Err(CryptoError::DecryptionFailed(_))));
}
