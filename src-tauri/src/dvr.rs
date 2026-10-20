// JCB AirPlay — dvr.rs
// Zero-reencode DVR: ring-buffer pre-roll, keyframe-aligned clip extraction,
// and fragmented MP4 muxing.
//
// Responsibilities:
//   • Maintain a configurable-depth ring buffer of raw compressed frames
//     (H.264 NAL units + AAC ADTS).
//   • On clip-save command, find the nearest preceding IDR keyframe and emit
//     all frames from that point as a standards-compliant fragmented MP4.
//   • Never re-encode: output bitstream is identical to the captured input.

use crate::media::MediaFrame;
use thiserror::Error;

/// Errors that can occur in the DVR module.
#[derive(Debug, Error)]
pub enum DvrError {
    /// No keyframe was found in the buffer — cannot start a clean clip.
    #[error("no keyframe found in buffer; cannot start clip")]
    NoKeyframe,

    /// The requested clip duration exceeds what is available in the buffer.
    #[error("requested clip duration {requested}s exceeds buffer depth {available}s")]
    InsufficientBuffer {
        /// Requested duration in seconds.
        requested: u32,
        /// Available duration in seconds.
        available: u32,
    },

    /// An I/O error occurred while writing the clip file.
    #[error("DVR I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Maximum number of frames kept in the ring buffer (≈ 30 s at 60 fps).
pub const DEFAULT_RING_CAPACITY: usize = 1800;

/// A ring-buffer that retains the most recent compressed frames for pre-roll
/// DVR capture.
#[derive(Debug)]
pub struct RingBuffer {
    frames: std::collections::VecDeque<MediaFrame>,
    capacity: usize,
}

impl RingBuffer {
    /// Create a new ring buffer with the given frame capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            frames: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Push a frame into the ring buffer, evicting the oldest if at capacity.
    pub fn push(&mut self, frame: MediaFrame) {
        if self.frames.len() == self.capacity {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
    }

    /// Return the number of frames currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Return `true` if the buffer contains no frames.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Find the index of the most recent keyframe in the buffer.
    ///
    /// # Errors
    /// Returns [`DvrError::NoKeyframe`] if no keyframe exists.
    pub fn last_keyframe_index(&self) -> Result<usize, DvrError> {
        self.frames
            .iter()
            .enumerate()
            .rev()
            .find(|(_, f)| f.is_keyframe)
            .map(|(i, _)| i)
            .ok_or(DvrError::NoKeyframe)
    }

    /// Extract a slice of frames starting from the last keyframe.
    ///
    /// Returns a `Vec<&MediaFrame>` representing the clip to be muxed.
    ///
    /// # Errors
    /// Returns [`DvrError`] if no keyframe is found.
    pub fn extract_clip(&self) -> Result<Vec<&MediaFrame>, DvrError> {
        let start = self.last_keyframe_index()?;
        Ok(self.frames.iter().skip(start).collect())
    }
}

/// Write a clip to a file path as a fragmented MP4.
///
/// `frames` must begin with a keyframe. No re-encoding is performed;
/// the raw NAL / ADTS data is muxed directly.
///
/// # Errors
/// Returns [`DvrError`] on I/O failure.
pub fn write_clip<P: AsRef<std::path::Path>>(
    frames: &[&MediaFrame],
    path: P,
) -> Result<(), DvrError> {
    log::info!(
        "DVR: writing {} frames to {}",
        frames.len(),
        path.as_ref().display()
    );
    // TODO(step-5): implement real fMP4 mux using `mp4` or a custom writer.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::{MediaFrame, PayloadType};

    fn video_frame(timestamp: u32, is_keyframe: bool) -> MediaFrame {
        MediaFrame::new(PayloadType::H264, timestamp, is_keyframe, vec![0x01])
    }

    #[test]
    fn ring_buffer_starts_empty() {
        let buf = RingBuffer::new(10);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn ring_buffer_evicts_oldest_at_capacity() {
        let mut buf = RingBuffer::new(3);
        for i in 0..5u32 {
            buf.push(video_frame(i, false));
        }
        assert_eq!(buf.len(), 3, "buffer should cap at capacity");
    }

    #[test]
    fn last_keyframe_index_finds_correct_frame() {
        let mut buf = RingBuffer::new(10);
        buf.push(video_frame(0, false));
        buf.push(video_frame(1, true)); // keyframe at index 1
        buf.push(video_frame(2, false));
        let idx = buf.last_keyframe_index().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn last_keyframe_index_errors_when_no_keyframe() {
        let mut buf = RingBuffer::new(10);
        buf.push(video_frame(0, false));
        assert!(matches!(
            buf.last_keyframe_index(),
            Err(DvrError::NoKeyframe)
        ));
    }

    #[test]
    fn extract_clip_starts_at_keyframe() {
        let mut buf = RingBuffer::new(10);
        buf.push(video_frame(0, false));
        buf.push(video_frame(1, true));
        buf.push(video_frame(2, false));
        let clip = buf.extract_clip().unwrap();
        assert_eq!(clip.len(), 2, "clip should start from keyframe");
        assert!(clip[0].is_keyframe);
    }

    #[test]
    fn write_clip_empty_frames_succeeds() {
        let frames: Vec<&MediaFrame> = vec![];
        let tmp = std::env::temp_dir().join("jcb_airplay_test_clip.mp4");
        assert!(write_clip(&frames, &tmp).is_ok());
    }
}
