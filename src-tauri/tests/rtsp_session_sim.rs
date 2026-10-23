//! JCB AirPlay — Integration test: RTSP session simulation
//!
//! Outside Judge test suite that spins up the asynchronous RTSP control server
//! on an ephemeral port, connects a simulated iOS client over TCP, and verifies
//! the complete protocol lifecycle:
//!   `GET /info -> pair-setup -> pair-verify (1 & 2) -> fp-setup (1 & 2) -> SETUP -> RECORD -> GET_PARAMETER -> feedback -> TEARDOWN`

use ed25519_dalek::SigningKey;
use jcb_airplay_lib::crypto::PairVerifyClient;
use jcb_airplay_lib::rtsp::{decode_binary_plist, encode_binary_plist, RtspServer};
use plist::{Dictionary, Value};
use rand::rngs::OsRng;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Helper to parse raw RTSP response bytes.
fn parse_response(buf: &[u8]) -> Option<(u16, HashMap<String, String>, Vec<u8>, usize)> {
    let header_end = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        (pos, pos + 4)
    } else if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        (pos, pos + 2)
    } else {
        return None;
    };

    let header_str = std::str::from_utf8(&buf[..header_end.0]).ok()?;
    let mut lines = header_str.lines();
    let status_line = lines.next()?;
    let mut status_parts = status_line.split_whitespace();
    status_parts.next()?; // Skip RTSP/1.0
    let status_code: u16 = status_parts.next()?.parse().ok()?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let total = header_end.1 + content_len;
    if buf.len() < total {
        return None;
    }

    let body = buf[header_end.1..total].to_vec();
    Some((status_code, headers, body, total))
}

/// Helper to send an RTSP request and await the corresponding response.
async fn send_rtsp_request(
    stream: &mut TcpStream,
    method: &str,
    uri: &str,
    cseq: u32,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, HashMap<String, String>, Vec<u8>) {
    let mut req_bytes = Vec::new();
    let req_line = format!("{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n");
    req_bytes.extend_from_slice(req_line.as_bytes());

    for (k, v) in headers {
        req_bytes.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    if !body.is_empty() {
        req_bytes.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    req_bytes.extend_from_slice(b"\r\n");
    req_bytes.extend_from_slice(body);

    stream.write_all(&req_bytes).await.expect("write request");
    stream.flush().await.expect("flush request");

    let mut recv_buf = Vec::new();
    let mut chunk = [0u8; 2048];

    loop {
        let n = stream.read(&mut chunk).await.expect("read response");
        assert!(n > 0, "unexpected EOF from RTSP server");
        recv_buf.extend_from_slice(&chunk[..n]);

        if let Some((status, headers, body, _)) = parse_response(&recv_buf) {
            return (status, headers, body);
        }
    }
}

#[tokio::test]
async fn test_full_rtsp_airplay_handshake_simulation() {
    // 1. Start RTSP control server on ephemeral port (127.0.0.1:0)
    let bind_addr = "127.0.0.1:0".parse().unwrap();
    let server = RtspServer::start(bind_addr)
        .await
        .expect("start RTSP server");
    let server_addr = server.local_addr();

    // 2. Connect simulated iOS client over TCP
    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("connect to RTSP server");

    // 3. Step 1: GET /info
    let (status, headers, body) = send_rtsp_request(
        &mut stream,
        "GET",
        "/info",
        1,
        &[("User-Agent", "AirPlay/600.0")],
        &[],
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("1"));
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/x-apple-binary-plist")
    );

    let info_plist = decode_binary_plist(&body).expect("decode capabilities bplist");
    let info_dict = info_plist.as_dictionary().expect("must be dictionary");
    assert_eq!(
        info_dict.get("model").and_then(|v| v.as_string()),
        Some("AppleTV3,2"),
        "model must be AppleTV3,2"
    );
    assert_eq!(
        info_dict.get("features").and_then(|v| v.as_string()),
        Some("0x5A7FFFF7,0x1E"),
        "features bitmask must match screen mirroring profile"
    );
    assert_eq!(
        info_dict
            .get("statusFlags")
            .and_then(|v| v.as_signed_integer()),
        Some(4),
        "statusFlags must be 0x4"
    );

    let displays = info_dict
        .get("displays")
        .and_then(|v| v.as_array())
        .expect("displays array present");
    assert!(!displays.is_empty());
    let display0 = displays[0].as_dictionary().expect("display dict");
    assert_eq!(
        display0.get("width").and_then(|v| v.as_signed_integer()),
        Some(1920)
    );
    assert_eq!(
        display0.get("height").and_then(|v| v.as_signed_integer()),
        Some(1080)
    );
    assert_eq!(
        display0
            .get("refreshRate")
            .and_then(|v| v.as_signed_integer()),
        Some(60)
    );

    // 4. Step 2: POST /pair-setup
    let client_signing_key = SigningKey::generate(&mut OsRng);
    let client_ed_pub = client_signing_key.verifying_key().to_bytes();

    let (status, headers, body) = send_rtsp_request(
        &mut stream,
        "POST",
        "/pair-setup",
        2,
        &[("Content-Type", "application/octet-stream")],
        &client_ed_pub,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("2"));
    assert_eq!(body.len(), 32, "Server Ed25519 public key must be 32 bytes");
    let mut server_ed_pub_bytes = [0u8; 32];
    server_ed_pub_bytes.copy_from_slice(&body);
    let server_verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&server_ed_pub_bytes).unwrap();

    // 5. Step 3: POST /pair-verify Phase 1
    let mut client_verify = PairVerifyClient::new(client_signing_key.clone(), server_verifying_key);
    let phase1_pkt = client_verify.build_phase1_request();

    let (status, headers, body) = send_rtsp_request(
        &mut stream,
        "POST",
        "/pair-verify",
        3,
        &[("Content-Type", "application/octet-stream")],
        &phase1_pkt,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("3"));
    assert_eq!(body.len(), 96, "Phase 1 response must be 96 bytes");

    // 6. Step 4: POST /pair-verify Phase 2
    let phase2_pkt = client_verify
        .process_phase1_response(&body)
        .expect("Client phase 1 verification must succeed");

    let (status, headers, _body) = send_rtsp_request(
        &mut stream,
        "POST",
        "/pair-verify",
        4,
        &[("Content-Type", "application/octet-stream")],
        &phase2_pkt,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("4"));

    // 7. Step 5: POST /fp-setup Frame 1 (16-byte challenge)
    let client_challenge = [0x42u8; 16];
    let (status, headers, body) = send_rtsp_request(
        &mut stream,
        "POST",
        "/fp-setup",
        5,
        &[("Content-Type", "application/octet-stream")],
        &client_challenge,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("5"));
    assert_eq!(body.len(), 16, "fp-setup Frame 1 response must be 16 bytes");

    // 8. Step 6: POST /fp-setup Frame 2 (72-byte session parameter block)
    let param_block_72 = [0x33u8; 72];
    let (status, headers, _body) = send_rtsp_request(
        &mut stream,
        "POST",
        "/fp-setup",
        6,
        &[("Content-Type", "application/octet-stream")],
        &param_block_72,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("6"));

    // 9. Step 7: SETUP (Stream type 110 screen mirroring)
    let mut setup_stream = Dictionary::new();
    setup_stream.insert("type".into(), Value::Integer(110.into()));
    let mut setup_dict = Dictionary::new();
    setup_dict.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(setup_stream)]),
    );
    let setup_plist = encode_binary_plist(&Value::Dictionary(setup_dict)).unwrap();

    let (status, headers, body) = send_rtsp_request(
        &mut stream,
        "SETUP",
        "rtsp://127.0.0.1/stream",
        7,
        &[("Content-Type", "application/x-apple-binary-plist")],
        &setup_plist,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("7"));
    assert!(headers.contains_key("session"));
    assert!(headers.contains_key("audio-jack-status"));

    let setup_resp_plist = decode_binary_plist(&body).expect("decode SETUP response bplist");
    let setup_resp_dict = setup_resp_plist
        .as_dictionary()
        .expect("must be dictionary");
    let resp_streams = setup_resp_dict
        .get("streams")
        .and_then(|v| v.as_array())
        .expect("streams array in SETUP response");
    assert!(!resp_streams.is_empty());
    let stream0 = resp_streams[0].as_dictionary().expect("stream dict");
    assert_eq!(
        stream0.get("type").and_then(|v| v.as_signed_integer()),
        Some(110)
    );
    let data_port = stream0
        .get("dataPort")
        .and_then(|v| v.as_signed_integer())
        .expect("dataPort present");
    let event_port = stream0
        .get("eventPort")
        .and_then(|v| v.as_signed_integer())
        .expect("eventPort present");
    assert!(data_port > 0, "Allocated dataPort must be > 0");
    assert!(event_port > 0, "Allocated eventPort must be > 0");

    // 10. Step 8: RECORD
    let (status, headers, _body) = send_rtsp_request(
        &mut stream,
        "RECORD",
        "rtsp://127.0.0.1/stream",
        8,
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("8"));

    // 11. Step 9: GET_PARAMETER (Heartbeat)
    let (status, headers, _body) = send_rtsp_request(
        &mut stream,
        "GET_PARAMETER",
        "rtsp://127.0.0.1/stream",
        9,
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("9"));

    // 12. Step 10: POST /feedback
    let (status, headers, _body) =
        send_rtsp_request(&mut stream, "POST", "/feedback", 10, &[], &[]).await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("10"));

    // 13. Step 11: TEARDOWN
    let (status, headers, _body) = send_rtsp_request(
        &mut stream,
        "TEARDOWN",
        "rtsp://127.0.0.1/stream",
        11,
        &[],
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("cseq").map(|s| s.as_str()), Some("11"));

    // Stop server
    server.stop();
}
