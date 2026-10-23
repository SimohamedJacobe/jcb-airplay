// JCB AirPlay — rtsp.rs
// RTSP/1.0 session management and binary plist negotiation for AirPlay Screen Mirroring.
//
// Responsibilities:
//   • Asynchronous RTSP control server on TCP port 7000 (`tokio::net::TcpListener`).
//   • Handles `GET /info`, `POST /pair-setup`, `POST /pair-verify`, `POST /fp-setup`,
//     `SETUP`, `RECORD`, `GET_PARAMETER`, `SET_PARAMETER`, `FLUSH`, `TEARDOWN`, `POST /feedback`.
//   • Binary property list (`application/x-apple-binary-plist`) serialization and deserialization.
//   • Capabilities advertisement (AppleTV3,2, 1920x1080 @ 60fps, statusFlags 0x4, features 0x5A7FFFF7,0x1E).
//   • Dynamic mirroring video stream port allocation (stream type 110, dataPort & eventPort).
//   • Session-bound cryptographic handshake execution with `crypto.rs`.

use crate::crypto::{
    PairSetupHandler, PairVerifyHandler, PairVerifyState, SessionKeySetup, StreamKey,
};
use crate::mdns::get_deterministic_mac;
use ed25519_dalek::SigningKey;
use plist::{Dictionary, Value};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

/// Errors that can occur in the RTSP module.
#[derive(Debug, Error)]
pub enum RtspError {
    /// The received RTSP request was malformed.
    #[error("malformed RTSP request: {0}")]
    MalformedRequest(String),

    /// An unsupported RTSP method was received.
    #[error("unsupported RTSP method: {0}")]
    UnsupportedMethod(String),

    /// Plist serialization or deserialization error.
    #[error("binary plist error: {0}")]
    PlistError(String),

    /// Cryptographic handshake failure within the RTSP session.
    #[error("cryptographic error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    /// An I/O error occurred on the RTSP socket.
    #[error("RTSP I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// RTSP session state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session established.
    Idle,
    /// ANNOUNCE or preliminary setup received.
    Announced,
    /// SETUP complete; stream ports allocated and ready to receive media.
    Ready,
    /// RECORD active; media is flowing.
    Playing,
    /// Session torn down.
    Terminated,
}

/// A parsed RTSP/1.0 request frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspRequest {
    /// Request method (e.g. "GET", "POST", "SETUP", "RECORD", "TEARDOWN").
    pub method: String,
    /// Request URI (e.g. "/info", "/pair-setup", "rtsp://...").
    pub uri: String,
    /// Protocol version (e.g. "RTSP/1.0").
    pub version: String,
    /// Normalized lowercase header map.
    pub headers: HashMap<String, String>,
    /// Request payload body.
    pub body: Vec<u8>,
}

impl RtspRequest {
    /// Parses an RTSP request from raw bytes.
    ///
    /// Returns `Ok(Some((request, bytes_consumed)))` if a complete frame was read,
    /// or `Ok(None)` if the buffer is incomplete and more data is needed from the network.
    pub fn parse(buf: &[u8]) -> Result<Option<(Self, usize)>, RtspError> {
        // Look for the end of headers marker (\r\n\r\n or \n\n)
        let header_end = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            (pos, pos + 4)
        } else if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
            (pos, pos + 2)
        } else {
            return Ok(None);
        };

        let header_str = std::str::from_utf8(&buf[..header_end.0])
            .map_err(|e| RtspError::MalformedRequest(format!("invalid UTF-8 in headers: {e}")))?;

        let mut lines = header_str.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| RtspError::MalformedRequest("empty request".to_string()))?;

        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| RtspError::MalformedRequest("missing method".to_string()))?
            .to_string();
        let uri = parts
            .next()
            .ok_or_else(|| RtspError::MalformedRequest("missing URI".to_string()))?
            .to_string();
        let version = parts.next().unwrap_or("RTSP/1.0").to_string();

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let total_length = header_end.1 + content_length;
        if buf.len() < total_length {
            // Need more body bytes
            return Ok(None);
        }

        let body = buf[header_end.1..total_length].to_vec();

        Ok(Some((
            Self {
                method,
                uri,
                version,
                headers,
                body,
            },
            total_length,
        )))
    }

    /// Retrieves the CSeq header value if present.
    pub fn cseq(&self) -> Option<u32> {
        self.headers.get("cseq").and_then(|v| v.parse().ok())
    }
}

/// An RTSP/1.0 response frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspResponse {
    /// HTTP/RTSP status code (e.g. 200, 400, 404).
    pub status_code: u16,
    /// Status description text (e.g. "OK", "Not Found").
    pub status_text: String,
    /// Ordered list of response headers.
    pub headers: Vec<(String, String)>,
    /// Response payload bytes.
    pub body: Vec<u8>,
}

impl RtspResponse {
    /// Creates a standard 200 OK response with the given CSeq.
    pub fn ok(cseq: Option<u32>) -> Self {
        let mut headers = Vec::new();
        if let Some(cs) = cseq {
            headers.push(("CSeq".to_string(), cs.to_string()));
        }
        headers.push(("Server".to_string(), "AirTunes/220.68".to_string()));

        Self {
            status_code: 200,
            status_text: "OK".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    /// Sets the Content-Type and payload body.
    pub fn with_body(mut self, content_type: &str, body: Vec<u8>) -> Self {
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.headers
            .push(("Content-Length".to_string(), body.len().to_string()));
        self.body = body;
        self
    }

    /// Appends a custom header to the response.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Serializes the response to standard RTSP wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let status_line = format!("RTSP/1.0 {} {}\r\n", self.status_code, self.status_text);
        out.extend_from_slice(status_line.as_bytes());

        for (k, v) in &self.headers {
            let line = format!("{}: {}\r\n", k, v);
            out.extend_from_slice(line.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// Helper function to serialize a [`plist::Value`] into binary property list (`bplist00`) bytes.
pub fn encode_binary_plist(val: &Value) -> Result<Vec<u8>, RtspError> {
    let mut buf = Vec::new();
    val.to_writer_binary(&mut buf)
        .map_err(|e| RtspError::PlistError(format!("failed to serialize bplist: {e}")))?;
    Ok(buf)
}

/// Helper function to deserialize a binary property list from bytes.
pub fn decode_binary_plist(data: &[u8]) -> Result<Value, RtspError> {
    Value::from_reader(std::io::Cursor::new(data))
        .map_err(|e| RtspError::PlistError(format!("failed to parse bplist: {e}")))
}

/// Dynamically binds an available local UDP port.
pub fn allocate_local_udp_port() -> Result<u16, RtspError> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(RtspError::Io)?;
    let port = socket.local_addr().map_err(RtspError::Io)?.port();
    Ok(port)
}

/// Builds the AppleTV3,2 capabilities binary property list for `GET /info`.
pub fn build_capabilities_plist(device_id: &str, service_name: &str) -> Result<Vec<u8>, RtspError> {
    let mut root = Dictionary::new();

    root.insert("model".into(), Value::String("AppleTV3,2".into()));
    root.insert("srcvers".into(), Value::String("220.68".into()));
    root.insert("statusFlags".into(), Value::Integer(4.into()));
    root.insert("features".into(), Value::String("0x5A7FFFF7,0x1E".into()));
    root.insert("deviceID".into(), Value::String(device_id.into()));
    root.insert("name".into(), Value::String(service_name.into()));
    root.insert("vv".into(), Value::Integer(2.into()));
    root.insert("keepAliveSendStatsAsDisabled".into(), Value::Boolean(true));

    // Displays capability configuration (1920x1080 @ 60fps)
    let mut display = Dictionary::new();
    display.insert("width".into(), Value::Integer(1920.into()));
    display.insert("height".into(), Value::Integer(1080.into()));
    display.insert("widthPixels".into(), Value::Integer(1920.into()));
    display.insert("heightPixels".into(), Value::Integer(1080.into()));
    display.insert("refreshRate".into(), Value::Integer(60.into()));
    display.insert("overscanned".into(), Value::Boolean(false));
    display.insert("maxFPS".into(), Value::Integer(60.into()));
    display.insert("features".into(), Value::Integer(14.into()));
    root.insert(
        "displays".into(),
        Value::Array(vec![Value::Dictionary(display)]),
    );

    // Audio formats capability array
    let mut audio_desc = Dictionary::new();
    audio_desc.insert("type".into(), Value::Integer(100.into()));
    audio_desc.insert(
        "audioInputFormats".into(),
        Value::Integer(0x10000000.into()),
    );
    audio_desc.insert(
        "audioOutputFormats".into(),
        Value::Integer(0x10000000.into()),
    );
    root.insert(
        "audioFormats".into(),
        Value::Array(vec![Value::Dictionary(audio_desc)]),
    );

    encode_binary_plist(&Value::Dictionary(root))
}

/// An RTSP session representing an active connection from an AirPlay sender.
pub struct RtspSession {
    /// Unique session identifier string (from RTSP `Session:` header or generated).
    pub session_id: String,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Remote address of the AirPlay sender.
    pub peer_addr: SocketAddr,
    /// Server long-term Ed25519 identity key.
    pub signing_key: SigningKey,
    /// PairSetup handler.
    pub pair_setup: PairSetupHandler,
    /// PairVerify handler.
    pub pair_verify: PairVerifyHandler,
    /// SessionKeySetup handler.
    pub session_key_setup: SessionKeySetup,
    /// Bound AES-128 stream key derived during handshake.
    pub stream_key: Option<StreamKey>,
    /// Dynamically allocated local mirroring UDP data port (stream type 110).
    pub mirror_data_port: u16,
    /// Dynamically allocated local mirroring UDP event port.
    pub mirror_event_port: u16,
    /// Dynamically allocated local timing port.
    pub timing_port: u16,
    /// Hardware device ID.
    pub device_id: String,
    /// Friendly service name.
    pub service_name: String,
}

impl std::fmt::Debug for RtspSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspSession")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .field("peer_addr", &self.peer_addr)
            .field("mirror_data_port", &self.mirror_data_port)
            .field("mirror_event_port", &self.mirror_event_port)
            .finish()
    }
}

impl RtspSession {
    /// Create a new RTSP session in the `Idle` state.
    pub fn new(session_id: String, peer_addr: SocketAddr) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pair_setup = PairSetupHandler::with_signing_key(signing_key.clone());
        let pair_verify = PairVerifyHandler::new(signing_key.clone());
        let session_key_setup = SessionKeySetup::new();
        let device_id = get_deterministic_mac();

        Self {
            session_id,
            state: SessionState::Idle,
            peer_addr,
            signing_key,
            pair_setup,
            pair_verify,
            session_key_setup,
            stream_key: None,
            mirror_data_port: 0,
            mirror_event_port: 0,
            timing_port: 0,
            device_id,
            service_name: "JCB AirPlay".to_string(),
        }
    }

    /// Transition this session to the `Playing` state.
    pub fn play(&mut self) -> Result<(), RtspError> {
        match self.state {
            SessionState::Ready | SessionState::Announced => {
                self.state = SessionState::Playing;
                log::info!("RTSP session {} → Playing", self.session_id);
                Ok(())
            }
            ref s => Err(RtspError::MalformedRequest(format!(
                "PLAY not valid in state {:?}",
                s
            ))),
        }
    }

    /// Tear down the session.
    pub fn teardown(&mut self) {
        self.state = SessionState::Terminated;
        log::info!("RTSP session {} → Terminated", self.session_id);
    }

    /// Processes an incoming RTSP request and generates the protocol response.
    pub fn handle_request(&mut self, req: &RtspRequest) -> Result<RtspResponse, RtspError> {
        let cseq = req.cseq();

        match (req.method.as_str(), req.uri.as_str()) {
            ("GET", "/info") => {
                let plist_bytes = build_capabilities_plist(&self.device_id, &self.service_name)?;
                Ok(RtspResponse::ok(cseq)
                    .with_body("application/x-apple-binary-plist", plist_bytes))
            }

            ("POST", "/pair-setup") => {
                let server_pk = self.pair_setup.handle_setup(&req.body)?;
                Ok(RtspResponse::ok(cseq)
                    .with_body("application/octet-stream", server_pk))
            }

            ("POST", "/pair-verify") => {
                let resp_body = if self.pair_verify.state() == PairVerifyState::Unverified {
                    self.pair_verify.handle_phase1(&req.body)?
                } else {
                    self.pair_verify.handle_phase2(&req.body)?
                };

                let mut resp = RtspResponse::ok(cseq);
                if !resp_body.is_empty() {
                    resp = resp.with_body("application/octet-stream", resp_body);
                }
                Ok(resp)
            }

            ("POST", "/fp-setup") => {
                let resp_body = if req.body.len() == 16 {
                    self.session_key_setup.handle_challenge(&req.body)?
                } else {
                    // Frame 2 (72 or 164 bytes)
                    let stream_key = self.session_key_setup.handle_key_exchange(&req.body)?;
                    self.stream_key = Some(stream_key);
                    vec![0u8; 20]
                };

                Ok(RtspResponse::ok(cseq)
                    .with_body("application/octet-stream", resp_body))
            }

            ("SETUP", _) => {
                // Dynamically allocate mirroring video ports
                self.mirror_data_port = allocate_local_udp_port()?;
                self.mirror_event_port = allocate_local_udp_port()?;
                self.timing_port = allocate_local_udp_port()?;

                let mut stream_dict = Dictionary::new();
                stream_dict.insert("type".into(), Value::Integer(110.into())); // Screen mirroring stream type
                stream_dict.insert(
                    "dataPort".into(),
                    Value::Integer((self.mirror_data_port as i64).into()),
                );
                stream_dict.insert(
                    "eventPort".into(),
                    Value::Integer((self.mirror_event_port as i64).into()),
                );

                let mut resp_dict = Dictionary::new();
                resp_dict.insert(
                    "streams".into(),
                    Value::Array(vec![Value::Dictionary(stream_dict)]),
                );
                resp_dict.insert(
                    "eventPort".into(),
                    Value::Integer((self.mirror_event_port as i64).into()),
                );
                resp_dict.insert(
                    "timingPort".into(),
                    Value::Integer((self.timing_port as i64).into()),
                );

                let resp_plist = encode_binary_plist(&Value::Dictionary(resp_dict))?;
                self.state = SessionState::Ready;

                Ok(RtspResponse::ok(cseq)
                    .with_header("Session", &self.session_id)
                    .with_header("Audio-Jack-Status", "connected; type=analog")
                    .with_body("application/x-apple-binary-plist", resp_plist))
            }

            ("RECORD", _) => {
                self.play()?;
                Ok(RtspResponse::ok(cseq)
                    .with_header("Session", &self.session_id)
                    .with_header("Audio-Jack-Status", "connected; type=analog"))
            }

            ("GET_PARAMETER", _) | ("SET_PARAMETER", _) | ("FLUSH", _) => {
                Ok(RtspResponse::ok(cseq).with_header("Session", &self.session_id))
            }

            ("POST", "/feedback") => Ok(RtspResponse::ok(cseq)),

            ("TEARDOWN", _) => {
                self.teardown();
                Ok(RtspResponse::ok(cseq).with_header("Session", &self.session_id))
            }

            ("OPTIONS", _) => Ok(RtspResponse::ok(cseq).with_header(
                "Public",
                "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER",
            )),

            (method, uri) => Err(RtspError::UnsupportedMethod(format!(
                "{method} {uri}"
            ))),
        }
    }
}

/// Asynchronous RTSP control server.
pub struct RtspServer {
    local_addr: SocketAddr,
    shutdown_tx: broadcast::Sender<()>,
    server_task: tokio::task::JoinHandle<Result<(), RtspError>>,
}

impl RtspServer {
    /// Binds to the specified address (or `0.0.0.0:7000` / `127.0.0.1:0`) and starts the server task.
    pub async fn start(addr: SocketAddr) -> Result<Self, RtspError> {
        let listener = TcpListener::bind(addr).await.map_err(RtspError::Io)?;
        let local_addr = listener.local_addr().map_err(RtspError::Io)?;
        let (shutdown_tx, _) = broadcast::channel(1);

        let mut shutdown_rx = shutdown_tx.subscribe();
        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, peer_addr)) => {
                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(stream, peer_addr).await {
                                        log::debug!("RTSP connection from {peer_addr} closed: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                log::error!("TCP accept error: {e}");
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        log::info!("RTSP server on {local_addr} received shutdown signal");
                        break;
                    }
                }
            }
            Ok(())
        });

        Ok(Self {
            local_addr,
            shutdown_tx,
            server_task,
        })
    }

    /// Returns the local socket address the server is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Signals the server task to gracefully stop.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Waits for the server task to finish.
    pub async fn wait(self) -> Result<(), RtspError> {
        self.server_task
            .await
            .map_err(|e| RtspError::Io(std::io::Error::other(e)))?
    }
}

/// Asynchronously processes requests from a single client connection.
async fn handle_connection(mut stream: TcpStream, peer_addr: SocketAddr) -> Result<(), RtspError> {
    let session_id = format!("JCB-{}", peer_addr.port());
    let mut session = RtspSession::new(session_id, peer_addr);
    let mut buffer = Vec::with_capacity(4096);
    let mut read_buf = [0u8; 2048];

    loop {
        // Try parsing any complete request currently in the buffer
        if let Some((req, consumed)) = RtspRequest::parse(&buffer)? {
            let resp = session.handle_request(&req)?;
            stream.write_all(&resp.to_bytes()).await?;
            stream.flush().await?;

            buffer.drain(..consumed);

            if session.state == SessionState::Terminated {
                break;
            }
            continue;
        }

        // Read more bytes from the stream
        let n = stream.read(&mut read_buf).await?;
        if n == 0 {
            // Client closed connection
            break;
        }
        buffer.extend_from_slice(&read_buf[..n]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_session() -> RtspSession {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152);
        RtspSession::new("test-session-001".into(), addr)
    }

    #[test]
    fn new_session_starts_idle() {
        let session = make_session();
        assert_eq!(session.state, SessionState::Idle);
    }

    #[test]
    fn play_from_ready_transitions_to_playing() {
        let mut session = make_session();
        session.state = SessionState::Ready;
        assert!(session.play().is_ok());
        assert_eq!(session.state, SessionState::Playing);
    }

    #[test]
    fn play_from_idle_returns_error() {
        let mut session = make_session();
        assert!(session.play().is_err());
    }

    #[test]
    fn teardown_sets_terminated() {
        let mut session = make_session();
        session.teardown();
        assert_eq!(session.state, SessionState::Terminated);
    }

    #[test]
    fn test_bplist_capabilities_roundtrip() {
        let plist_bytes = build_capabilities_plist("48:A6:B8:11:22:33", "JCB Test")
            .expect("build capabilities plist");
        assert!(!plist_bytes.is_empty());

        let decoded = decode_binary_plist(&plist_bytes).expect("decode bplist");
        let dict = decoded.as_dictionary().expect("must be dictionary");

        assert_eq!(
            dict.get("model").and_then(|v| v.as_string()),
            Some("AppleTV3,2")
        );
        assert_eq!(
            dict.get("features").and_then(|v| v.as_string()),
            Some("0x5A7FFFF7,0x1E")
        );
        assert_eq!(
            dict.get("statusFlags").and_then(|v| v.as_signed_integer()),
            Some(4)
        );
    }

    #[test]
    fn test_rtsp_request_parsing() {
        let raw = b"GET /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n";
        let (req, consumed) = RtspRequest::parse(raw).unwrap().unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/info");
        assert_eq!(req.cseq(), Some(1));
    }
}
