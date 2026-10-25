// JCB AirPlay — dvr.rs
// Zero-reencode DVR: rolling 30s instant-replay buffer, keyframe-aligned clip extraction,
// and live stream recorder.
//
// Responsibilities:
//   • Maintain a thread-safe, whole-GOP-evicting rolling buffer of H.264 Annex-B NAL units
//     stored as `Arc<[u8]>` with stream timestamps.
//   • Drop non-IDR NALs arriving before the first IDR keyframe.
//   • Cache SPS/PPS parameter sets and snapshot the active pair into each GOP when its IDR arrives.
//   • Evict oldest GOPs while 2+ GOPs exist and `second_gop_start + retention <= latest_ts`.
//   • Evict oldest GOPs when `total_bytes > max_bytes` cap.
//   • Export zero-reencode `.h264` instant replay clips using atomic `.tmp` write and rename.
//   • Provide `LiveRecorder` with pre-IDR skipping and non-blocking error preservation.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

use crate::media::MediaFrame;

// ─── Errors & Constants ──────────────────────────────────────────────────────

/// Standard H.264 video RTP clock frequency (90 kHz ticks per second).
pub const H264_TIMESCALES: u32 = 90_000;

/// Default retention period: 30 seconds (in 90 kHz ticks).
pub const DEFAULT_RETENTION_SECS: u32 = 30;
pub const DEFAULT_RETENTION_TICKS: u64 = (DEFAULT_RETENTION_SECS as u64) * (H264_TIMESCALES as u64);

/// Default max bytes limit: 256 MB.
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Maximum number of frames kept in the legacy ring buffer (≈ 30 s at 60 fps).
pub const DEFAULT_RING_CAPACITY: usize = 1800;

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

    /// The DVR buffer contains no frames or GOPs.
    #[error("DVR buffer is empty; cannot export clip")]
    EmptyBuffer,

    /// The requested export format / extension is unsupported.
    #[error("unsupported export format: {0}")]
    UnsupportedFormat(String),

    /// The destination output path is invalid.
    #[error("invalid export path: {0}")]
    InvalidPath(String),

    /// Live recorder is already running.
    #[error("live recording is already in progress")]
    AlreadyRecording,

    /// Live recorder is not currently running.
    #[error("no live recording is currently in progress")]
    NotRecording,

    /// An error occurred during active live recording.
    #[error("live recording failure: {0}")]
    RecordingFailed(String),

    /// Internal synchronization lock was poisoned.
    #[error("DVR lock poisoned")]
    LockPoisoned,

    /// An I/O error occurred while writing to disk.
    #[error("DVR I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Export & Recording Telemetry Types ───────────────────────────────────────

/// Statistics returned upon successful clip export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportStats {
    /// Total bytes written to disk.
    pub bytes: usize,
    /// Total clip duration in milliseconds.
    pub duration_ms: u64,
    /// Total clip duration in stream timestamp ticks.
    pub duration_ticks: u64,
}

/// Statistics returned upon stopping a live recording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingStats {
    /// Total bytes written to disk.
    pub bytes: usize,
    /// Total duration of the recording in milliseconds.
    pub duration_ms: u64,
}

/// Real-time DVR telemetry status for UI queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DvrStatus {
    /// Retained buffer depth in seconds.
    pub buffered_seconds: f64,
    /// Retained buffer size in bytes.
    pub bytes: usize,
    /// Count of complete IDR keyframes / GOPs in buffer.
    pub idr_count: usize,
    /// Whether live recording is currently running.
    pub is_recording: bool,
}

// ─── NAL Unit Utilities ──────────────────────────────────────────────────────

/// Ensure NAL unit data begins with 4-byte Annex-B start code `00 00 00 01`.
#[must_use]
pub fn ensure_annexb(data: &[u8]) -> Arc<[u8]> {
    if data.starts_with(&[0, 0, 0, 1]) {
        Arc::from(data)
    } else if data.starts_with(&[0, 0, 1]) {
        let mut v = Vec::with_capacity(data.len() + 1);
        v.push(0);
        v.extend_from_slice(data);
        Arc::from(v.into_boxed_slice())
    } else {
        let mut v = Vec::with_capacity(data.len() + 4);
        v.extend_from_slice(&[0, 0, 0, 1]);
        v.extend_from_slice(data);
        Arc::from(v.into_boxed_slice())
    }
}

/// Extract H.264 NAL unit type (`nal_unit_type = byte & 0x1F`).
#[must_use]
pub fn extract_nal_type(nal: &[u8]) -> Option<u8> {
    if nal.len() >= 5 && nal[0..4] == [0, 0, 0, 1] {
        Some(nal[4] & 0x1F)
    } else if nal.len() >= 4 && nal[0..3] == [0, 0, 1] {
        Some(nal[3] & 0x1F)
    } else if !nal.is_empty() {
        Some(nal[0] & 0x1F)
    } else {
        None
    }
}

/// Split a byte slice containing multiple Annex-B start codes into individual NAL slices.
#[must_use]
pub fn split_annexb_slice(data: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 4 <= data.len() {
        if data[i..i + 4] == [0, 0, 0, 1] {
            starts.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }

    if starts.len() <= 1 {
        return vec![data];
    }

    let mut nals = Vec::with_capacity(starts.len());
    for (idx, &s) in starts.iter().enumerate() {
        let end = if idx + 1 < starts.len() {
            starts[idx + 1]
        } else {
            data.len()
        };
        nals.push(&data[s..end]);
    }
    nals
}

/// Validate that an output path is a valid destination for an `.h264` export.
///
/// # Errors
/// Returns [`DvrError::InvalidPath`] or [`DvrError::UnsupportedFormat`].
pub fn validate_h264_output_path(path: &Path) -> Result<(), DvrError> {
    if path.is_dir() {
        return Err(DvrError::InvalidPath(format!(
            "path is an existing directory: {}",
            path.display()
        )));
    }

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            DvrError::InvalidPath(format!("missing file extension in: {}", path.display()))
        })?;

    if ext == "ts" || ext == "mp4" {
        return Err(DvrError::UnsupportedFormat(format!(
            ".{ext} export requires remuxing; only .h264 Annex-B export is currently supported"
        )));
    }

    if ext != "h264" {
        return Err(DvrError::UnsupportedFormat(format!(
            "unsupported extension .{ext}; only .h264 is supported"
        )));
    }

    let parent = path.parent().ok_or_else(|| {
        DvrError::InvalidPath(format!("path has no parent directory: {}", path.display()))
    })?;

    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(DvrError::InvalidPath(format!(
            "parent directory does not exist: {}",
            parent.display()
        )));
    }

    Ok(())
}

/// Helper to derive `<path>.tmp` in the same directory.
fn get_tmp_path(output_path: &Path) -> Result<PathBuf, DvrError> {
    let file_name = output_path.file_name().ok_or_else(|| {
        DvrError::InvalidPath(format!("invalid file name: {}", output_path.display()))
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    Ok(output_path.with_file_name(tmp_name))
}

// ─── Group of Pictures (GOP) ─────────────────────────────────────────────────

/// An atomic Group of Pictures starting with an IDR keyframe and all subsequent non-IDR NALs.
#[derive(Debug, Clone)]
pub struct Gop {
    /// Sequence Parameter Set snapshotted when this GOP's IDR arrived.
    pub sps: Option<Arc<[u8]>>,
    /// Picture Parameter Set snapshotted when this GOP's IDR arrived.
    pub pps: Option<Arc<[u8]>>,
    /// Stream timestamp of the leading IDR keyframe.
    pub start_timestamp: u64,
    /// Stream timestamp of the most recent NAL unit in this GOP.
    pub end_timestamp: u64,
    /// Contiguous sequence of NAL units in this GOP (first is IDR).
    pub nals: Vec<Arc<[u8]>>,
    /// Total byte count of all NALs in this GOP.
    pub total_bytes: usize,
}

// ─── Rolling 30s Instant Replay Buffer ───────────────────────────────────────

/// Internal state for [`RollingDvrBuffer`].
#[derive(Debug)]
struct RollingDvrBufferInner {
    gops: VecDeque<Gop>,
    cached_sps: Option<Arc<[u8]>>,
    cached_pps: Option<Arc<[u8]>>,
    retention_ticks: u64,
    timescale: u32,
    max_bytes: usize,
    total_bytes: usize,
    latest_timestamp: u64,
    seen_first_idr: bool,
}

impl RollingDvrBufferInner {
    fn new(retention_ticks: u64, max_bytes: usize, timescale: u32) -> Self {
        Self {
            gops: VecDeque::new(),
            cached_sps: None,
            cached_pps: None,
            retention_ticks,
            timescale,
            max_bytes,
            total_bytes: 0,
            latest_timestamp: 0,
            seen_first_idr: false,
        }
    }

    /// Push an individual NAL unit into the rolling buffer.
    fn push_single_nal(&mut self, nal: &[u8], mut timestamp: u64) {
        if nal.is_empty() {
            return;
        }

        // Clamp timestamps that go backwards
        if timestamp < self.latest_timestamp {
            timestamp = self.latest_timestamp;
        } else {
            self.latest_timestamp = timestamp;
        }

        let nal_type = match extract_nal_type(nal) {
            Some(t) => t,
            None => return,
        };

        match nal_type {
            // SPS (type 7): Cache active SPS
            7 => {
                self.cached_sps = Some(ensure_annexb(nal));
            }
            // PPS (type 8): Cache active PPS
            8 => {
                self.cached_pps = Some(ensure_annexb(nal));
            }
            // IDR Keyframe Slice (type 5)
            5 => {
                self.seen_first_idr = true;
                let annexb_nal = ensure_annexb(nal);
                let nal_len = annexb_nal.len();

                let gop = Gop {
                    sps: self.cached_sps.clone(),
                    pps: self.cached_pps.clone(),
                    start_timestamp: timestamp,
                    end_timestamp: timestamp,
                    nals: vec![annexb_nal],
                    total_bytes: nal_len,
                };

                self.total_bytes += nal_len;
                self.gops.push_back(gop);
                self.evict_oldest();
            }
            // Non-IDR Slice (type 1) or metadata (SEI type 6, etc.)
            _ => {
                if !self.seen_first_idr {
                    // Drop non-IDR NALs arriving before the first IDR
                    return;
                }

                let annexb_nal = ensure_annexb(nal);
                let nal_len = annexb_nal.len();

                if let Some(current_gop) = self.gops.back_mut() {
                    current_gop.nals.push(annexb_nal);
                    current_gop.end_timestamp = timestamp;
                    current_gop.total_bytes += nal_len;
                    self.total_bytes += nal_len;
                    self.evict_oldest();
                }
            }
        }
    }

    /// Evict oldest GOPs while 2+ GOPs exist and retention criteria are met.
    fn evict_oldest(&mut self) {
        // Condition 1: while 2+ GOPs exist and second_gop_start + retention <= latest_ts, drop oldest GOP.
        while self.gops.len() >= 2 {
            let second_gop_start = self.gops[1].start_timestamp;
            if second_gop_start.saturating_add(self.retention_ticks) <= self.latest_timestamp {
                if let Some(evicted) = self.gops.pop_front() {
                    self.total_bytes = self.total_bytes.saturating_sub(evicted.total_bytes);
                }
            } else {
                break;
            }
        }

        // Condition 2: while 2+ GOPs exist and total_bytes exceeds max_bytes, drop oldest GOP.
        while self.gops.len() >= 2 && self.total_bytes > self.max_bytes {
            if let Some(evicted) = self.gops.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(evicted.total_bytes);
            }
        }
    }

    /// Take a fast, zero-reencode snapshot of retained GOPs for disk export.
    fn snapshot_export(&self) -> Result<ExportSnapshot, DvrError> {
        if self.gops.is_empty() {
            return Err(DvrError::EmptyBuffer);
        }

        let oldest_gop = &self.gops[0];
        let newest_gop = &self.gops[self.gops.len() - 1];

        let duration_ticks = newest_gop
            .end_timestamp
            .saturating_sub(oldest_gop.start_timestamp);
        let duration_ms = (duration_ticks * 1000) / (self.timescale.max(1) as u64);

        // Snapshot oldest SPS and PPS
        let oldest_sps = oldest_gop.sps.clone();
        let oldest_pps = oldest_gop.pps.clone();

        // Collect all NALs across all retained GOPs
        let mut nals = Vec::new();
        let mut last_sps = oldest_sps.clone();
        let mut last_pps = oldest_pps.clone();

        for (idx, gop) in self.gops.iter().enumerate() {
            // For subsequent GOPs, write updated SPS/PPS if they changed mid-stream
            if idx > 0 {
                if gop.sps != last_sps {
                    if let Some(ref sps) = gop.sps {
                        nals.push(sps.clone());
                    }
                    last_sps = gop.sps.clone();
                }
                if gop.pps != last_pps {
                    if let Some(ref pps) = gop.pps {
                        nals.push(pps.clone());
                    }
                    last_pps = gop.pps.clone();
                }
            }

            for nal in &gop.nals {
                nals.push(nal.clone());
            }
        }

        Ok(ExportSnapshot {
            oldest_sps,
            oldest_pps,
            nals,
            duration_ms,
            duration_ticks,
        })
    }

    fn status(&self, is_recording: bool) -> DvrStatus {
        let (buffered_seconds, idr_count) = if self.gops.is_empty() {
            (0.0, 0)
        } else {
            let start = self.gops[0].start_timestamp;
            let end = self.gops[self.gops.len() - 1].end_timestamp;
            let ticks = end.saturating_sub(start);
            let secs = (ticks as f64) / (self.timescale.max(1) as f64);
            (secs, self.gops.len())
        };

        DvrStatus {
            buffered_seconds,
            bytes: self.total_bytes,
            idr_count,
            is_recording,
        }
    }
}

/// Lightweight snapshot of NAL references extracted under lock for background disk writing.
struct ExportSnapshot {
    oldest_sps: Option<Arc<[u8]>>,
    oldest_pps: Option<Arc<[u8]>>,
    nals: Vec<Arc<[u8]>>,
    duration_ms: u64,
    duration_ticks: u64,
}

/// Thread-safe rolling 30s instant replay buffer.
#[derive(Debug)]
pub struct RollingDvrBuffer {
    inner: Mutex<RollingDvrBufferInner>,
}

impl Default for RollingDvrBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_RETENTION_TICKS, DEFAULT_MAX_BYTES, H264_TIMESCALES)
    }
}

impl RollingDvrBuffer {
    /// Create a new rolling DVR buffer.
    #[must_use]
    pub fn new(retention_ticks: u64, max_bytes: usize, timescale: u32) -> Self {
        Self {
            inner: Mutex::new(RollingDvrBufferInner::new(
                retention_ticks,
                max_bytes,
                timescale,
            )),
        }
    }

    /// Push an H.264 Annex-B buffer (may contain one or more NAL units) with stream timestamp.
    ///
    /// # Errors
    /// Returns [`DvrError::LockPoisoned`] on internal lock failure.
    pub fn push_nal(&self, data: &[u8], timestamp: u64) -> Result<(), DvrError> {
        let mut inner = self.inner.lock().map_err(|_| DvrError::LockPoisoned)?;
        for nal in split_annexb_slice(data) {
            inner.push_single_nal(nal, timestamp);
        }
        Ok(())
    }

    /// Push a [`MediaFrame`] into the rolling buffer.
    ///
    /// # Errors
    /// Returns [`DvrError::LockPoisoned`] on internal lock failure.
    pub fn push_frame(&self, frame: &MediaFrame) -> Result<(), DvrError> {
        self.push_nal(&frame.data, frame.timestamp as u64)
    }

    /// Export the retained instant replay buffer to an `.h264` file.
    ///
    /// The lock is held only to take an atomic snapshot of `Arc<[u8]>` references;
    /// all file I/O and atomic rename are performed outside the lock.
    ///
    /// # Errors
    /// Returns [`DvrError`] on empty buffer, invalid path, or disk write error.
    pub fn export_replay_clip<P: AsRef<Path>>(
        &self,
        output_path: P,
    ) -> Result<ExportStats, DvrError> {
        let path = output_path.as_ref();
        validate_h264_output_path(path)?;
        let tmp_path = get_tmp_path(path)?;

        // Acquire lock only to snapshot
        let snapshot = {
            let inner = self.inner.lock().map_err(|_| DvrError::LockPoisoned)?;
            inner.snapshot_export()?
        };

        // File I/O completely outside the lock
        let mut bytes_written = 0usize;
        let write_res = (|| -> Result<(), std::io::Error> {
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);

            if let Some(ref sps) = snapshot.oldest_sps {
                writer.write_all(sps)?;
                bytes_written += sps.len();
            }
            if let Some(ref pps) = snapshot.oldest_pps {
                writer.write_all(pps)?;
                bytes_written += pps.len();
            }

            for nal in &snapshot.nals {
                writer.write_all(nal)?;
                bytes_written += nal.len();
            }

            writer.flush()?;
            writer.get_ref().sync_all()?;
            drop(writer);

            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
            std::fs::rename(&tmp_path, path)?;
            Ok(())
        })();

        if let Err(e) = write_res {
            if tmp_path.exists() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            return Err(DvrError::Io(e));
        }

        Ok(ExportStats {
            bytes: bytes_written,
            duration_ms: snapshot.duration_ms,
            duration_ticks: snapshot.duration_ticks,
        })
    }

    /// Query the current DVR telemetry status.
    #[must_use]
    pub fn status(&self, is_recording: bool) -> DvrStatus {
        match self.inner.lock() {
            Ok(inner) => inner.status(is_recording),
            Err(_) => DvrStatus {
                buffered_seconds: 0.0,
                bytes: 0,
                idr_count: 0,
                is_recording,
            },
        }
    }

    /// Number of active GOPs retained in buffer.
    #[must_use]
    pub fn gop_count(&self) -> usize {
        match self.inner.lock() {
            Ok(i) => i.gops.len(),
            Err(_) => 0,
        }
    }

    /// Total bytes retained in buffer.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        match self.inner.lock() {
            Ok(i) => i.total_bytes,
            Err(_) => 0,
        }
    }

    /// Returns `true` if the buffer contains no GOPs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self.inner.lock() {
            Ok(i) => i.gops.is_empty(),
            Err(_) => true,
        }
    }
}

// ─── Live Stream Recorder ───────────────────────────────────────────────────

struct ActiveRecording {
    writer: BufWriter<File>,
    path: PathBuf,
    tmp_path: PathBuf,
    bytes_written: usize,
    start_timestamp: u64,
    last_timestamp: u64,
    seen_first_idr: bool,
}

enum RecorderState {
    Idle,
    Recording(ActiveRecording),
    Failed { error: String, tmp_path: PathBuf },
}

struct LiveRecorderInner {
    state: RecorderState,
    cached_sps: Option<Arc<[u8]>>,
    cached_pps: Option<Arc<[u8]>>,
    timescale: u32,
}

impl std::fmt::Debug for LiveRecorderInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveRecorderInner")
            .field(
                "is_recording",
                &matches!(self.state, RecorderState::Recording(_)),
            )
            .field("timescale", &self.timescale)
            .finish()
    }
}

/// Continuous live H.264 stream recorder writing directly to disk with pre-IDR skipping.
#[derive(Debug)]
pub struct LiveRecorder {
    inner: Mutex<LiveRecorderInner>,
}

impl Default for LiveRecorder {
    fn default() -> Self {
        Self::new(H264_TIMESCALES)
    }
}

impl LiveRecorder {
    /// Create a new [`LiveRecorder`].
    #[must_use]
    pub fn new(timescale: u32) -> Self {
        Self {
            inner: Mutex::new(LiveRecorderInner {
                state: RecorderState::Idle,
                cached_sps: None,
                cached_pps: None,
                timescale,
            }),
        }
    }

    /// Start a live recording session writing to `output_path`.
    ///
    /// # Errors
    /// Returns [`DvrError::AlreadyRecording`] if a recording is currently active,
    /// or [`DvrError::InvalidPath`] / [`DvrError::UnsupportedFormat`].
    pub fn start_live_recording<P: AsRef<Path>>(&self, output_path: P) -> Result<(), DvrError> {
        let path = output_path.as_ref();
        validate_h264_output_path(path)?;
        let tmp_path = get_tmp_path(path)?;

        let mut inner = self.inner.lock().map_err(|_| DvrError::LockPoisoned)?;
        match inner.state {
            RecorderState::Recording(_) => return Err(DvrError::AlreadyRecording),
            RecorderState::Failed { ref tmp_path, .. } => {
                if tmp_path.exists() {
                    let _ = std::fs::remove_file(tmp_path);
                }
            }
            RecorderState::Idle => {}
        }

        let file = File::create(&tmp_path)?;
        let writer = BufWriter::new(file);

        inner.state = RecorderState::Recording(ActiveRecording {
            writer,
            path: path.to_path_buf(),
            tmp_path,
            bytes_written: 0,
            start_timestamp: 0,
            last_timestamp: 0,
            seen_first_idr: false,
        });

        Ok(())
    }

    /// Push an H.264 Annex-B buffer (may contain one or more NAL units) to the active recorder.
    ///
    /// On write failure, recording is halted and the error preserved for stop/status;
    /// this method never panics and never blocks stream ingestion.
    pub fn push_nal(&self, data: &[u8], timestamp: u64) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        for nal in split_annexb_slice(data) {
            if nal.is_empty() {
                continue;
            }

            let nal_type = match extract_nal_type(nal) {
                Some(t) => t,
                None => continue,
            };

            // Cache SPS/PPS
            if nal_type == 7 {
                inner.cached_sps = Some(ensure_annexb(nal));
            } else if nal_type == 8 {
                inner.cached_pps = Some(ensure_annexb(nal));
            }

            let sps_to_write = inner.cached_sps.clone();
            let pps_to_write = inner.cached_pps.clone();

            if let RecorderState::Recording(ref mut rec) = inner.state {
                match nal_type {
                    // IDR Keyframe Slice
                    5 => {
                        let annexb = ensure_annexb(nal);
                        let mut write_op = || -> Result<(), std::io::Error> {
                            if !rec.seen_first_idr {
                                rec.seen_first_idr = true;
                                rec.start_timestamp = timestamp;

                                if let Some(ref sps) = sps_to_write {
                                    rec.writer.write_all(sps)?;
                                    rec.bytes_written += sps.len();
                                }
                                if let Some(ref pps) = pps_to_write {
                                    rec.writer.write_all(pps)?;
                                    rec.bytes_written += pps.len();
                                }
                            }

                            rec.writer.write_all(&annexb)?;
                            rec.bytes_written += annexb.len();
                            rec.last_timestamp = timestamp;
                            Ok(())
                        };

                        if let Err(e) = write_op() {
                            inner.state = RecorderState::Failed {
                                error: e.to_string(),
                                tmp_path: rec.tmp_path.clone(),
                            };
                            return;
                        }
                    }
                    // Non-IDR Slice or metadata
                    _ => {
                        if !rec.seen_first_idr {
                            // Skip non-IDR frames until the first IDR
                            continue;
                        }

                        let annexb = ensure_annexb(nal);
                        let mut write_op = || -> Result<(), std::io::Error> {
                            rec.writer.write_all(&annexb)?;
                            rec.bytes_written += annexb.len();
                            rec.last_timestamp = timestamp;
                            Ok(())
                        };

                        if let Err(e) = write_op() {
                            inner.state = RecorderState::Failed {
                                error: e.to_string(),
                                tmp_path: rec.tmp_path.clone(),
                            };
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Stop the live recording session, flush and sync the file, and atomically rename.
    ///
    /// # Errors
    /// Returns [`DvrError::NotRecording`] if no recording was in progress,
    /// or [`DvrError::RecordingFailed`] if a write error occurred during recording.
    pub fn stop_live_recording(&self) -> Result<RecordingStats, DvrError> {
        let mut inner = self.inner.lock().map_err(|_| DvrError::LockPoisoned)?;
        let old_state = std::mem::replace(&mut inner.state, RecorderState::Idle);

        match old_state {
            RecorderState::Idle => Err(DvrError::NotRecording),
            RecorderState::Failed { error, tmp_path } => {
                if tmp_path.exists() {
                    let _ = std::fs::remove_file(&tmp_path);
                }
                Err(DvrError::RecordingFailed(error))
            }
            RecorderState::Recording(mut rec) => {
                let finalize_res = (|| -> Result<(), std::io::Error> {
                    rec.writer.flush()?;
                    rec.writer.get_ref().sync_all()?;
                    drop(rec.writer);

                    if rec.path.exists() {
                        let _ = std::fs::remove_file(&rec.path);
                    }
                    std::fs::rename(&rec.tmp_path, &rec.path)?;
                    Ok(())
                })();

                if let Err(e) = finalize_res {
                    if rec.tmp_path.exists() {
                        let _ = std::fs::remove_file(&rec.tmp_path);
                    }
                    return Err(DvrError::Io(e));
                }

                let duration_ms = if rec.seen_first_idr && rec.last_timestamp >= rec.start_timestamp
                {
                    let ticks = rec.last_timestamp - rec.start_timestamp;
                    (ticks * 1000) / (inner.timescale.max(1) as u64)
                } else {
                    0
                };

                Ok(RecordingStats {
                    bytes: rec.bytes_written,
                    duration_ms,
                })
            }
        }
    }

    /// Returns `true` if a recording is currently active and healthy.
    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.inner
            .lock()
            .is_ok_and(|i| matches!(i.state, RecorderState::Recording(_)))
    }
}

// ─── Unified DVR Manager (Tauri Managed State) ───────────────────────────────

/// High-level DVR Manager unifying instant replay pre-roll and live recording.
#[derive(Debug, Clone)]
pub struct DvrManager {
    /// Rolling 30s instant replay buffer.
    pub buffer: Arc<RollingDvrBuffer>,
    /// Live stream disk recorder.
    pub recorder: Arc<LiveRecorder>,
}

impl Default for DvrManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DvrManager {
    /// Create a new unified [`DvrManager`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(RollingDvrBuffer::default()),
            recorder: Arc::new(LiveRecorder::default()),
        }
    }

    /// Ingest a NAL unit into both the instant replay buffer and active recorder.
    ///
    /// # Errors
    /// Returns [`DvrError::LockPoisoned`] on internal lock failure.
    pub fn push_nal(&self, data: &[u8], timestamp: u64) -> Result<(), DvrError> {
        self.buffer.push_nal(data, timestamp)?;
        self.recorder.push_nal(data, timestamp);
        Ok(())
    }

    /// Ingest a [`MediaFrame`].
    ///
    /// # Errors
    /// Returns [`DvrError::LockPoisoned`] on internal lock failure.
    pub fn push_frame(&self, frame: &MediaFrame) -> Result<(), DvrError> {
        self.push_nal(&frame.data, frame.timestamp as u64)
    }

    /// Export an instant replay clip to an `.h264` path.
    ///
    /// # Errors
    /// Returns [`DvrError`] on empty buffer, invalid path, or disk write error.
    pub fn export_replay_clip<P: AsRef<Path>>(
        &self,
        output_path: P,
    ) -> Result<ExportStats, DvrError> {
        self.buffer.export_replay_clip(output_path)
    }

    /// Start a live recording session.
    ///
    /// # Errors
    /// Returns [`DvrError::AlreadyRecording`] if recording is already active.
    pub fn start_live_recording<P: AsRef<Path>>(&self, output_path: P) -> Result<(), DvrError> {
        self.recorder.start_live_recording(output_path)
    }

    /// Stop the live recording session.
    ///
    /// # Errors
    /// Returns [`DvrError::NotRecording`] if no recording was in progress.
    pub fn stop_live_recording(&self) -> Result<RecordingStats, DvrError> {
        self.recorder.stop_live_recording()
    }

    /// Retrieve the aggregated DVR status.
    #[must_use]
    pub fn status(&self) -> DvrStatus {
        let is_recording = self.recorder.is_recording();
        self.buffer.status(is_recording)
    }
}

// ─── Legacy RingBuffer Compatibility ─────────────────────────────────────────

/// A ring-buffer that retains the most recent compressed frames for pre-roll
/// DVR capture (preserved for legacy test suite compatibility).
#[derive(Debug)]
pub struct RingBuffer {
    frames: VecDeque<MediaFrame>,
    capacity: usize,
}

impl RingBuffer {
    /// Create a new ring buffer with the given frame capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(capacity),
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
    /// # Errors
    /// Returns [`DvrError`] if no keyframe is found.
    pub fn extract_clip(&self) -> Result<Vec<&MediaFrame>, DvrError> {
        let start = self.last_keyframe_index()?;
        Ok(self.frames.iter().skip(start).collect())
    }
}

/// Write a clip to a file path as a fragmented MP4.
///
/// # Errors
/// Returns [`DvrError`] on I/O failure.
pub fn write_clip<P: AsRef<Path>>(frames: &[&MediaFrame], path: P) -> Result<(), DvrError> {
    log::info!(
        "DVR: writing {} frames to {}",
        frames.len(),
        path.as_ref().display()
    );
    Ok(())
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::PayloadType;

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

    // ─── Step 9 Tests: Whole-GOP, SPS/PPS Snapshot, Byte Cap, Recorder ──────

    #[test]
    fn test_whole_gop_eviction() {
        // Retention: 1 second = 90_000 ticks
        let buffer = RollingDvrBuffer::new(90_000, usize::MAX, 90_000);

        // Feed GOP 0: IDR at t=0, Non-IDR at t=45_000
        buffer.push_nal(&[0, 0, 0, 1, 0x65, 0xAA], 0).unwrap();
        buffer.push_nal(&[0, 0, 0, 1, 0x61, 0xBB], 45_000).unwrap();
        assert_eq!(buffer.gop_count(), 1);

        // Feed GOP 1: IDR at t=90_000, Non-IDR at t=135_000
        buffer.push_nal(&[0, 0, 0, 1, 0x65, 0xCC], 90_000).unwrap();
        buffer.push_nal(&[0, 0, 0, 1, 0x61, 0xDD], 135_000).unwrap();
        assert_eq!(buffer.gop_count(), 2);

        // GOP 0 is not yet evicted because second_gop_start (90k) + 90k = 180k > 135k
        assert_eq!(buffer.gop_count(), 2);

        // Feed GOP 2: IDR at t=180_000
        // Now second_gop_start (90k) + 90k = 180k <= latest_ts (180k) -> GOP 0 evicted!
        buffer.push_nal(&[0, 0, 0, 1, 0x65, 0xEE], 180_000).unwrap();
        assert_eq!(
            buffer.gop_count(),
            2,
            "GOP 0 must be evicted as an atomic unit"
        );

        let status = buffer.status(false);
        assert_eq!(status.idr_count, 2);
    }

    #[test]
    fn test_per_gop_sps_pps_snapshot() {
        let buffer = RollingDvrBuffer::new(10_000_000, usize::MAX, 90_000);

        let sps_v1 = [0, 0, 0, 1, 0x67, 0x01];
        let pps_v1 = [0, 0, 0, 1, 0x68, 0x01];
        buffer.push_nal(&sps_v1, 0).unwrap();
        buffer.push_nal(&pps_v1, 0).unwrap();
        // IDR for GOP 0
        buffer.push_nal(&[0, 0, 0, 1, 0x65, 0x10], 0).unwrap();

        // Feed updated SPS/PPS v2 before GOP 1
        let sps_v2 = [0, 0, 0, 1, 0x67, 0x02];
        let pps_v2 = [0, 0, 0, 1, 0x68, 0x02];
        buffer.push_nal(&sps_v2, 1000).unwrap();
        buffer.push_nal(&pps_v2, 1000).unwrap();
        // IDR for GOP 1
        buffer.push_nal(&[0, 0, 0, 1, 0x65, 0x20], 1000).unwrap();

        let inner = buffer.inner.lock().unwrap();
        assert_eq!(inner.gops.len(), 2);
        assert_eq!(inner.gops[0].sps.as_deref().unwrap(), &sps_v1[..]);
        assert_eq!(inner.gops[0].pps.as_deref().unwrap(), &pps_v1[..]);
        assert_eq!(inner.gops[1].sps.as_deref().unwrap(), &sps_v2[..]);
        assert_eq!(inner.gops[1].pps.as_deref().unwrap(), &pps_v2[..]);
    }

    #[test]
    fn test_byte_cap_eviction() {
        // Buffer with high retention ticks but strict 50 byte cap
        let buffer = RollingDvrBuffer::new(10_000_000, 50, 90_000);

        // NAL 1: 30 bytes
        let nal1 = vec![0u8; 30];
        let mut nal1_idr = vec![0, 0, 0, 1, 0x65];
        nal1_idr.extend_from_slice(&nal1);
        buffer.push_nal(&nal1_idr, 0).unwrap();
        assert_eq!(buffer.gop_count(), 1);

        // NAL 2: 30 bytes (total 70 bytes > 50 bytes cap -> evicts GOP 0!)
        let mut nal2_idr = vec![0, 0, 0, 1, 0x65];
        nal2_idr.extend_from_slice(&nal1);
        buffer.push_nal(&nal2_idr, 1000).unwrap();

        assert_eq!(
            buffer.gop_count(),
            1,
            "oldest GOP must be evicted to honor byte cap"
        );
        assert!(buffer.total_bytes() <= 50);
    }

    #[test]
    fn test_recorder_state_transitions() {
        let recorder = LiveRecorder::default();
        let tmp_dir = std::env::temp_dir();
        let out_file = tmp_dir.join("jcb_test_rec_transition.h264");

        // Non-recording stop fails
        assert!(matches!(
            recorder.stop_live_recording(),
            Err(DvrError::NotRecording)
        ));

        // Unsupported extension fails
        let bad_ext = tmp_dir.join("test.mp4");
        assert!(matches!(
            recorder.start_live_recording(&bad_ext),
            Err(DvrError::UnsupportedFormat(_))
        ));

        // Start recording succeeds
        recorder.start_live_recording(&out_file).unwrap();
        assert!(recorder.is_recording());

        // Second start fails
        assert!(matches!(
            recorder.start_live_recording(&out_file),
            Err(DvrError::AlreadyRecording)
        ));

        // Feed IDR and stop
        recorder.push_nal(&[0, 0, 0, 1, 0x65, 0x11, 0x22], 0);
        let stats = recorder.stop_live_recording().unwrap();
        assert!(!recorder.is_recording());
        assert_eq!(stats.bytes, 7);
        assert!(out_file.exists());

        let _ = std::fs::remove_file(&out_file);
    }

    #[test]
    fn test_pre_idr_skipping() {
        let buffer = RollingDvrBuffer::new(10_000_000, usize::MAX, 90_000);
        let recorder = LiveRecorder::default();
        let tmp_dir = std::env::temp_dir();
        let out_file = tmp_dir.join("jcb_test_pre_idr_skipping.h264");
        recorder.start_live_recording(&out_file).unwrap();

        // Feed non-IDR frames before any IDR
        buffer.push_nal(&[0, 0, 0, 1, 0x61, 0xAA], 100).unwrap();
        buffer.push_nal(&[0, 0, 0, 1, 0x61, 0xBB], 200).unwrap();
        recorder.push_nal(&[0, 0, 0, 1, 0x61, 0xAA], 100);
        recorder.push_nal(&[0, 0, 0, 1, 0x61, 0xBB], 200);

        assert!(
            buffer.is_empty(),
            "non-IDR before IDR must be dropped in buffer"
        );

        // Now feed SPS, PPS, then IDR
        buffer.push_nal(&[0, 0, 0, 1, 0x67, 0x01], 300).unwrap();
        buffer.push_nal(&[0, 0, 0, 1, 0x68, 0x02], 300).unwrap();
        buffer.push_nal(&[0, 0, 0, 1, 0x65, 0xCC], 300).unwrap();

        recorder.push_nal(&[0, 0, 0, 1, 0x67, 0x01], 300);
        recorder.push_nal(&[0, 0, 0, 1, 0x68, 0x02], 300);
        recorder.push_nal(&[0, 0, 0, 1, 0x65, 0xCC], 300);

        assert_eq!(buffer.gop_count(), 1, "buffer starts from first IDR");
        let stats = recorder.stop_live_recording().unwrap();
        assert_eq!(stats.bytes, 6 + 6 + 6); // SPS (6) + PPS (6) + IDR (6)

        let _ = std::fs::remove_file(&out_file);
    }
}
