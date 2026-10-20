// JCB AirPlay — rtsp.rs
// RTSP/1.0 session management and SDP negotiation.
//
// Responsibilities:
//   • Accept incoming RTSP connections from AirPlay senders.
//   • Handle OPTIONS / ANNOUNCE / SETUP / RECORD / PLAY / TEARDOWN methods.
//   • Parse SDP offers from the sender; produce SDP answers.
//   • Drive session state machine.

use thiserror::Error;

/// Errors that can occur in the RTSP module.
#[derive(Debug, Error)]
pub enum RtspError {
    /// The received RTSP request was malformed.
    #[error("malformed RTSP request: {0}")]
    MalformedRequest(String),

    /// An unsupported RTSP method was received.
    #[error("unsupported RTSP method: {0}")]
    UnsupportedMethod(String),

    /// An I/O error occurred on the RTSP socket.
    #[error("RTSP I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// RTSP session state machine states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// No session established.
    Idle,
    /// ANNOUNCE received; waiting for SETUP.
    Announced,
    /// SETUP complete; ready to receive media.
    Ready,
    /// PLAY active; media is flowing.
    Playing,
    /// Session torn down.
    Terminated,
}

/// An RTSP session representing one AirPlay stream.
#[derive(Debug)]
pub struct RtspSession {
    /// Unique session identifier string (from RTSP `Session:` header).
    pub session_id: String,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Remote address of the AirPlay sender.
    pub peer_addr: std::net::SocketAddr,
}

impl RtspSession {
    /// Create a new RTSP session in the `Idle` state.
    #[must_use]
    pub fn new(session_id: String, peer_addr: std::net::SocketAddr) -> Self {
        Self {
            session_id,
            state: SessionState::Idle,
            peer_addr,
        }
    }

    /// Transition this session to the `Playing` state.
    ///
    /// # Errors
    /// Returns [`RtspError`] if the current state does not permit a PLAY
    /// transition.
    pub fn play(&mut self) -> Result<(), RtspError> {
        match self.state {
            SessionState::Ready => {
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
}
