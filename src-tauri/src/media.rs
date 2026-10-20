// JCB AirPlay — media.rs
// H.264 / AAC frame pipeline and render surface bridge.
//
// Responsibilities:
//   • Demux incoming RTP payloads into H.264 NAL units and AAC ADTS frames.
//   • Maintain a frame queue with bounded depth to absorb jitter.
//   • Bridge decoded frames to a platform render surface (WGPU / DirectComposition)
//     for zero-copy display in the Tauri window.

use thiserror::Error;

/// Errors that can occur in the media pipeline.
#[derive(Debug, Error)]
pub enum MediaError {
    /// The RTP payload type is not recognised.
    #[error("unsupported RTP payload type: {0}")]
    UnsupportedPayloadType(u8),

    /// The frame data is malformed or truncated.
    #[error("malformed frame data")]
    MalformedFrame,

    /// The frame queue is full and the frame was dropped.
    #[error("frame queue overflow — frame dropped")]
    QueueOverflow,
}

/// RTP payload types used by AirPlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// H.264 video (dynamic PT 96 in AirPlay).
    H264 = 96,
    /// AAC-ELD audio (dynamic PT 110 in AirPlay).
    AacEld = 110,
}

impl TryFrom<u8> for PayloadType {
    type Error = MediaError;

    fn try_from(pt: u8) -> Result<Self, Self::Error> {
        match pt {
            96 => Ok(PayloadType::H264),
            110 => Ok(PayloadType::AacEld),
            other => Err(MediaError::UnsupportedPayloadType(other)),
        }
    }
}

/// A decoded media frame ready for rendering or DVR capture.
#[derive(Debug, Clone)]
pub struct MediaFrame {
    /// Whether this frame is a video key-frame (IDR) or audio frame.
    pub is_keyframe: bool,
    /// RTP timestamp (90 kHz clock for video, sample-rate clock for audio).
    pub timestamp: u32,
    /// The payload type of this frame.
    pub payload_type: PayloadType,
    /// Raw NAL unit data (H.264) or ADTS frame data (AAC).
    pub data: Vec<u8>,
}

impl MediaFrame {
    /// Construct a new media frame.
    #[must_use]
    pub fn new(
        payload_type: PayloadType,
        timestamp: u32,
        is_keyframe: bool,
        data: Vec<u8>,
    ) -> Self {
        Self {
            is_keyframe,
            timestamp,
            payload_type,
            data,
        }
    }
}

/// Parse an RTP payload into a [`MediaFrame`].
///
/// `pt` is the RTP payload type byte. `timestamp` is from the RTP header.
/// `payload` is the raw RTP payload bytes (after the header).
///
/// # Errors
/// Returns [`MediaError`] if the payload type is unsupported or the data is
/// malformed.
pub fn parse_rtp_frame(pt: u8, timestamp: u32, payload: &[u8]) -> Result<MediaFrame, MediaError> {
    let payload_type = PayloadType::try_from(pt)?;
    if payload.is_empty() {
        return Err(MediaError::MalformedFrame);
    }
    // TODO(step-4): implement real NAL-unit / ADTS demuxer.
    let is_keyframe = payload_type == PayloadType::H264 && payload[0] & 0x1F == 5;
    Ok(MediaFrame::new(
        payload_type,
        timestamp,
        is_keyframe,
        payload.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_type_from_u8_known_values() {
        assert_eq!(PayloadType::try_from(96).unwrap(), PayloadType::H264);
        assert_eq!(PayloadType::try_from(110).unwrap(), PayloadType::AacEld);
    }

    #[test]
    fn payload_type_from_u8_unknown_returns_error() {
        assert!(matches!(
            PayloadType::try_from(0),
            Err(MediaError::UnsupportedPayloadType(0))
        ));
    }

    #[test]
    fn parse_rtp_frame_empty_payload_returns_error() {
        let result = parse_rtp_frame(96, 0, &[]);
        assert!(matches!(result, Err(MediaError::MalformedFrame)));
    }

    #[test]
    fn parse_rtp_frame_h264_non_idr() {
        // NAL type 1 (non-IDR slice) — not a keyframe.
        let payload = vec![0x01u8; 16];
        let frame = parse_rtp_frame(96, 90000, &payload).unwrap();
        assert_eq!(frame.payload_type, PayloadType::H264);
        assert!(!frame.is_keyframe);
        assert_eq!(frame.timestamp, 90000);
    }

    #[test]
    fn parse_rtp_frame_h264_idr_is_keyframe() {
        // NAL type 5 (IDR) — keyframe.
        let payload = vec![0x05u8, 0x00, 0x00];
        let frame = parse_rtp_frame(96, 180000, &payload).unwrap();
        assert!(frame.is_keyframe);
    }
}
