// JCB AirPlay — media.rs
// H.264 / AAC frame pipeline, lock-free SPSC ring buffer, and AirPlay stream parser.
//
// Responsibilities:
//   • Zero-copy parsing and serialization for the 128-byte AirPlay mirroring stream header.
//   • Pre-allocated, lock-free Single-Producer Single-Consumer (SPSC) ring buffer
//     for moving media packets across network reader and decoder threads with zero heap
//     reallocations and atomic telemetry.
//   • Asynchronous mirroring stream TCP reader (port 7100).
//   • Demux incoming RTP payloads into H.264 NAL units and AAC ADTS frames.

use std::cell::UnsafeCell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// The exact length of an AirPlay mirroring stream packet header in bytes.
pub const AIRPLAY_STREAM_HEADER_LEN: usize = 128;

/// Maximum payload size permitted for an AirPlay stream frame (8 MB).
/// Prevents out-of-memory denial-of-service from malformed header sizes.
pub const MAX_PAYLOAD_SIZE: u32 = 8 * 1024 * 1024;

/// Default TCP port for the AirPlay mirroring stream.
pub const DEFAULT_MIRRORING_PORT: u16 = 7100;

/// Errors that can occur in the media pipeline or stream parser.
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

    /// The AirPlay stream header is malformed (expected 128 bytes).
    #[error("malformed AirPlay stream header: expected 128 bytes, got {0}")]
    MalformedStreamHeader(usize),

    /// The payload size exceeds the maximum permitted bound.
    #[error("stream payload size {0} exceeds max bound {1}")]
    PayloadTooLarge(u32, u32),

    /// I/O error occurred during stream reading.
    #[error("stream I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// RTP payload types used by AirPlay audio/video baseline.
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

/// Typed enumeration of AirPlay mirroring stream payload types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPayloadType {
    /// H.264 video bitstream frame.
    VideoBitstream,
    /// Codec configuration (H.264 SPS / PPS parameter sets).
    CodecConfig,
    /// Heartbeat keepalive frame.
    Heartbeat,
    /// Streaming telemetry and sync report.
    StreamingReport,
    /// Unknown or vendor-specific payload type code.
    Unknown(u16),
}

impl StreamPayloadType {
    /// Map a 16-bit little-endian value to [`StreamPayloadType`].
    #[must_use]
    pub const fn from_u16(val: u16) -> Self {
        match val {
            0x00 => Self::VideoBitstream,
            0x01 => Self::CodecConfig,
            0x02 => Self::Heartbeat,
            0x05 => Self::StreamingReport,
            other => Self::Unknown(other),
        }
    }

    /// Convert [`StreamPayloadType`] to its 16-bit little-endian value.
    #[must_use]
    pub const fn as_u16(&self) -> u16 {
        match *self {
            Self::VideoBitstream => 0x00,
            Self::CodecConfig => 0x01,
            Self::Heartbeat => 0x02,
            Self::StreamingReport => 0x05,
            Self::Unknown(val) => val,
        }
    }
}

/// Exact 128-byte little-endian AirPlay mirroring stream header.
///
/// Layout:
/// - `0..4`:   `payload_size` (`u32` LE, bounded by [`MAX_PAYLOAD_SIZE`])
/// - `4..6`:   `payload_type` (`u16` LE, mapped to [`StreamPayloadType`])
/// - `6..8`:   `payload_option` (`u16` LE)
/// - `8..16`:  `timestamp_ntp` (`u64` LE)
/// - `16..20`: `source_width` (`f32` LE)
/// - `20..24`: `source_height` (`f32` LE)
/// - `24..40`: Reserved padding (16 bytes)
/// - `40..44`: `display_width` (`f32` LE)
/// - `44..48`: `display_height` (`f32` LE)
/// - `48..128`: Reserved padding (80 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct AirPlayStreamHeader {
    /// Length of the following media payload in bytes.
    pub payload_size: u32,
    /// Type of media payload (video, codec config, heartbeat, etc.).
    pub payload_type: StreamPayloadType,
    /// Payload options bitmask or flags.
    pub payload_option: u16,
    /// 64-bit NTP timestamp for audio/video synchronization.
    pub timestamp_ntp: u64,
    /// Native source video width in pixels.
    pub source_width: f32,
    /// Native source video height in pixels.
    pub source_height: f32,
    /// Target display rendering width in pixels.
    pub display_width: f32,
    /// Target display rendering height in pixels.
    pub display_height: f32,
    /// Reserved header bytes 24..40.
    pub reserved1: [u8; 16],
    /// Reserved header bytes 48..128.
    pub reserved2: [u8; 80],
}

impl AirPlayStreamHeader {
    /// Zero-copy parse a 128-byte little-endian AirPlay stream header.
    ///
    /// # Errors
    /// Returns [`MediaError::MalformedStreamHeader`] if slice is shorter than 128 bytes,
    /// or [`MediaError::PayloadTooLarge`] if `payload_size > MAX_PAYLOAD_SIZE`.
    pub fn parse(bytes: &[u8]) -> Result<Self, MediaError> {
        if bytes.len() < AIRPLAY_STREAM_HEADER_LEN {
            return Err(MediaError::MalformedStreamHeader(bytes.len()));
        }

        let payload_size = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        if payload_size > MAX_PAYLOAD_SIZE {
            return Err(MediaError::PayloadTooLarge(payload_size, MAX_PAYLOAD_SIZE));
        }

        let payload_type_raw = u16::from_le_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let payload_option = u16::from_le_bytes(
            bytes[6..8]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let timestamp_ntp = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let source_width = f32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let source_height = f32::from_le_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );

        let mut reserved1 = [0u8; 16];
        reserved1.copy_from_slice(&bytes[24..40]);

        let display_width = f32::from_le_bytes(
            bytes[40..44]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let display_height = f32::from_le_bytes(
            bytes[44..48]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );

        let mut reserved2 = [0u8; 80];
        reserved2.copy_from_slice(&bytes[48..128]);

        Ok(Self {
            payload_size,
            payload_type: StreamPayloadType::from_u16(payload_type_raw),
            payload_option,
            timestamp_ntp,
            source_width,
            source_height,
            display_width,
            display_height,
            reserved1,
            reserved2,
        })
    }

    /// Serialize the header into a 128-byte stack array with zero heap allocations.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; AIRPLAY_STREAM_HEADER_LEN] {
        let mut buf = [0u8; AIRPLAY_STREAM_HEADER_LEN];
        self.write_into(&mut buf);
        buf
    }

    /// Write serialized header bytes directly into an existing 128-byte buffer.
    pub fn write_into(&self, buf: &mut [u8; AIRPLAY_STREAM_HEADER_LEN]) {
        buf[0..4].copy_from_slice(&self.payload_size.to_le_bytes());
        buf[4..6].copy_from_slice(&self.payload_type.as_u16().to_le_bytes());
        buf[6..8].copy_from_slice(&self.payload_option.to_le_bytes());
        buf[8..16].copy_from_slice(&self.timestamp_ntp.to_le_bytes());
        buf[16..20].copy_from_slice(&self.source_width.to_le_bytes());
        buf[20..24].copy_from_slice(&self.source_height.to_le_bytes());
        buf[24..40].copy_from_slice(&self.reserved1);
        buf[40..44].copy_from_slice(&self.display_width.to_le_bytes());
        buf[44..48].copy_from_slice(&self.display_height.to_le_bytes());
        buf[48..128].copy_from_slice(&self.reserved2);
    }
}

/// A parsed AirPlay mirroring packet consisting of the 128-byte header and payload.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamPacket {
    /// Exact 128-byte header metadata.
    pub header: AirPlayStreamHeader,
    /// Raw payload bytes (e.g., Annex-B H.264 slice NAL units).
    pub payload: Vec<u8>,
}

/// Cache-line padding container (64-byte alignment) to avoid false sharing.
#[repr(align(64))]
#[derive(Debug)]
pub struct CachePadded<T>(pub T);

impl<T> std::ops::Deref for CachePadded<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Telemetry metrics for the lock-free SPSC ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingBufferTelemetry {
    /// Cumulative count of packets successfully pushed by producer.
    pub packets_pushed: u64,
    /// Cumulative count of packets successfully popped by consumer.
    pub packets_popped: u64,
    /// Count of packets rejected/dropped due to full ring buffer overflow.
    pub packets_dropped_overflow: u64,
    /// Maximum concurrent depth reached by the queue over its lifetime.
    pub high_water_mark: usize,
    /// Current depth of the queue at time of observation.
    pub current_depth: usize,
    /// Total bounded slot capacity of the ring buffer.
    pub capacity: usize,
}

/// Internal atomic stats for the ring buffer.
struct BufferStats {
    packets_pushed: AtomicU64,
    packets_popped: AtomicU64,
    packets_dropped_overflow: AtomicU64,
    high_water_mark: AtomicUsize,
}

/// Internal shared state for the lock-free SPSC ring buffer.
struct SpscInner<T> {
    buffer: Box<[UnsafeCell<Option<T>>]>,
    capacity: usize,
    mask: usize,
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
    stats: BufferStats,
}

// SAFETY: SpscInner manages lock-free synchronization between exactly one producer
// (which only updates `head` and writes to slot `head & mask`) and one consumer
// (which only updates `tail` and takes from slot `tail & mask`).
// Release-Acquire fences guarantee memory consistency with no concurrent slot mutation.
unsafe impl<T: Send> Send for SpscInner<T> {}
unsafe impl<T: Send> Sync for SpscInner<T> {}

/// Single-producer handle for the lock-free SPSC ring buffer.
pub struct SpscProducer<T> {
    inner: Arc<SpscInner<T>>,
    buffer_pool: Vec<Vec<u8>>,
}

// SAFETY: SpscProducer has exclusive producer access to `inner`.
unsafe impl<T: Send> Send for SpscProducer<T> {}

/// Single-consumer handle for the lock-free SPSC ring buffer.
pub struct SpscConsumer<T> {
    inner: Arc<SpscInner<T>>,
}

// SAFETY: SpscConsumer has exclusive consumer access to `inner`.
unsafe impl<T: Send> Send for SpscConsumer<T> {}

impl<T> SpscProducer<T> {
    /// Push an item into the ring buffer.
    ///
    /// # Errors
    /// Returns [`MediaError::QueueOverflow`] if the queue is full.
    pub fn push(&mut self, item: T) -> Result<(), MediaError> {
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Acquire);

        if head.wrapping_sub(tail) >= self.inner.capacity {
            self.inner
                .stats
                .packets_dropped_overflow
                .fetch_add(1, Ordering::Relaxed);
            return Err(MediaError::QueueOverflow);
        }

        let slot = head & self.inner.mask;
        // SAFETY: head - tail < capacity, so consumer has already read and cleared
        // this slot. Single producer owns this slot exclusively.
        unsafe {
            *self.inner.buffer[slot].get() = Some(item);
        }

        self.inner
            .head
            .store(head.wrapping_add(1), Ordering::Release);
        self.inner
            .stats
            .packets_pushed
            .fetch_add(1, Ordering::Relaxed);

        let depth = head.wrapping_sub(tail) + 1;
        self.inner
            .stats
            .high_water_mark
            .fetch_max(depth, Ordering::Relaxed);

        Ok(())
    }

    /// Acquire a reusable byte buffer from the local pool or allocate with capacity.
    /// Eliminates steady-state heap reallocations on the TCP read hot path.
    #[must_use]
    pub fn acquire_buffer(&mut self, min_capacity: usize) -> Vec<u8> {
        if let Some(mut buf) = self.buffer_pool.pop() {
            if buf.capacity() >= min_capacity {
                buf.clear();
                return buf;
            }
        }
        Vec::with_capacity(min_capacity)
    }

    /// Return an unused or drained payload buffer to the pool for reuse.
    pub fn recycle_buffer(&mut self, mut buf: Vec<u8>) {
        if self.buffer_pool.len() < 128 {
            buf.clear();
            self.buffer_pool.push(buf);
        }
    }

    /// Returns the current number of items waiting in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the buffer is completely full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len() >= self.inner.capacity
    }

    /// Returns the total bounded slot capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Snapshot current buffer telemetry metrics.
    #[must_use]
    pub fn telemetry(&self) -> RingBufferTelemetry {
        RingBufferTelemetry {
            packets_pushed: self.inner.stats.packets_pushed.load(Ordering::Relaxed),
            packets_popped: self.inner.stats.packets_popped.load(Ordering::Relaxed),
            packets_dropped_overflow: self
                .inner
                .stats
                .packets_dropped_overflow
                .load(Ordering::Relaxed),
            high_water_mark: self.inner.stats.high_water_mark.load(Ordering::Relaxed),
            current_depth: self.len(),
            capacity: self.inner.capacity,
        }
    }
}

impl<T> SpscConsumer<T> {
    /// Pop an item from the ring buffer, if available.
    pub fn pop(&mut self) -> Option<T> {
        let tail = self.inner.tail.load(Ordering::Relaxed);
        let head = self.inner.head.load(Ordering::Acquire);

        if tail == head {
            return None;
        }

        let slot = tail & self.inner.mask;
        // SAFETY: tail != head, so producer has published this slot with Release.
        // Consumer loaded head with Acquire. Single consumer owns this slot exclusively.
        let item = unsafe { (*self.inner.buffer[slot].get()).take() };

        self.inner
            .tail
            .store(tail.wrapping_add(1), Ordering::Release);
        self.inner
            .stats
            .packets_popped
            .fetch_add(1, Ordering::Relaxed);

        item
    }

    /// Returns the current number of items waiting in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the buffer is completely full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len() >= self.inner.capacity
    }

    /// Returns the total bounded slot capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Snapshot current buffer telemetry metrics.
    #[must_use]
    pub fn telemetry(&self) -> RingBufferTelemetry {
        RingBufferTelemetry {
            packets_pushed: self.inner.stats.packets_pushed.load(Ordering::Relaxed),
            packets_popped: self.inner.stats.packets_popped.load(Ordering::Relaxed),
            packets_dropped_overflow: self
                .inner
                .stats
                .packets_dropped_overflow
                .load(Ordering::Relaxed),
            high_water_mark: self.inner.stats.high_water_mark.load(Ordering::Relaxed),
            current_depth: self.len(),
            capacity: self.inner.capacity,
        }
    }
}

/// Create a pre-allocated lock-free bounded SPSC ring buffer split into Producer and Consumer.
///
/// Capacity is automatically rounded up to the nearest power of two (minimum 2).
#[must_use]
pub fn split_ring_buffer<T>(capacity: usize) -> (SpscProducer<T>, SpscConsumer<T>) {
    let cap = capacity.next_power_of_two().max(2);
    let mask = cap - 1;

    let mut slots = Vec::with_capacity(cap);
    for _ in 0..cap {
        slots.push(UnsafeCell::new(None));
    }

    let inner = Arc::new(SpscInner {
        buffer: slots.into_boxed_slice(),
        capacity: cap,
        mask,
        head: CachePadded(AtomicUsize::new(0)),
        tail: CachePadded(AtomicUsize::new(0)),
        stats: BufferStats {
            packets_pushed: AtomicU64::new(0),
            packets_popped: AtomicU64::new(0),
            packets_dropped_overflow: AtomicU64::new(0),
            high_water_mark: AtomicUsize::new(0),
        },
    });

    (
        SpscProducer {
            inner: Arc::clone(&inner),
            buffer_pool: Vec::with_capacity(64),
        },
        SpscConsumer { inner },
    )
}

/// Pre-allocated bounded SPSC ring buffer container.
pub struct SpscRingBuffer<T> {
    producer: SpscProducer<T>,
    consumer: SpscConsumer<T>,
}

impl<T> SpscRingBuffer<T> {
    /// Construct a new pre-allocated SPSC ring buffer.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (producer, consumer) = split_ring_buffer(capacity);
        Self { producer, consumer }
    }

    /// Split this ring buffer into paired [`SpscProducer`] and [`SpscConsumer`] handles.
    #[must_use]
    pub fn split(self) -> (SpscProducer<T>, SpscConsumer<T>) {
        (self.producer, self.consumer)
    }

    /// Push an item into the buffer.
    ///
    /// # Errors
    /// Returns [`MediaError::QueueOverflow`] if the queue is full.
    pub fn push(&mut self, item: T) -> Result<(), MediaError> {
        self.producer.push(item)
    }

    /// Pop an item from the buffer if available.
    pub fn pop(&mut self) -> Option<T> {
        self.consumer.pop()
    }

    /// Snapshot current buffer telemetry metrics.
    #[must_use]
    pub fn telemetry(&self) -> RingBufferTelemetry {
        self.producer.telemetry()
    }

    /// Current item count in buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.producer.len()
    }

    /// Returns `true` if buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.producer.is_empty()
    }

    /// Returns `true` if buffer is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.producer.is_full()
    }

    /// Buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.producer.capacity()
    }
}

/// Asynchronous AirPlay mirroring stream TCP listener.
pub struct MirroringStreamServer {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl MirroringStreamServer {
    /// Bind the mirroring TCP stream server to the specified socket address.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if socket binding fails.
    pub async fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Bind to the default AirPlay mirroring stream port (`0.0.0.0:7100`).
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if socket binding fails.
    pub async fn bind_default() -> Result<Self, std::io::Error> {
        let addr = SocketAddr::from(([0, 0, 0, 0], DEFAULT_MIRRORING_PORT));
        Self::bind(addr).await
    }

    /// Returns the bound local socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Read a single 128-byte header and media payload from an asynchronous reader into a pre-allocated buffer.
    ///
    /// # Errors
    /// Returns [`MediaError`] if header is malformed, payload exceeds bound, or I/O fails.
    pub async fn read_packet<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        producer: &mut SpscProducer<StreamPacket>,
    ) -> Result<Option<StreamPacket>, MediaError> {
        let mut header_buf = [0u8; AIRPLAY_STREAM_HEADER_LEN];
        match reader.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(MediaError::Io(e)),
        }

        let header = AirPlayStreamHeader::parse(&header_buf)?;
        let size = header.payload_size as usize;
        let mut payload = producer.acquire_buffer(size);
        payload.resize(size, 0);

        if size > 0 {
            if let Err(e) = reader.read_exact(&mut payload).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(MediaError::MalformedFrame);
                }
                return Err(MediaError::Io(e));
            }
        }

        Ok(Some(StreamPacket { header, payload }))
    }

    /// Accept a single incoming mirroring connection and stream packets into the producer until EOF.
    ///
    /// # Errors
    /// Returns [`MediaError`] if accepting connection or reading packet stream fails.
    pub async fn serve_one(
        &self,
        mut producer: SpscProducer<StreamPacket>,
    ) -> Result<u64, MediaError> {
        let (mut socket, _) = self.listener.accept().await.map_err(MediaError::Io)?;
        let mut count = 0u64;

        while let Some(packet) = Self::read_packet(&mut socket, &mut producer).await? {
            let _ = producer.push(packet);
            count += 1;
        }

        Ok(count)
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
        let payload = vec![0x01u8; 16];
        let frame = parse_rtp_frame(96, 90000, &payload).unwrap();
        assert_eq!(frame.payload_type, PayloadType::H264);
        assert!(!frame.is_keyframe);
        assert_eq!(frame.timestamp, 90000);
    }

    #[test]
    fn parse_rtp_frame_h264_idr_is_keyframe() {
        let payload = vec![0x05u8, 0x00, 0x00];
        let frame = parse_rtp_frame(96, 180000, &payload).unwrap();
        assert!(frame.is_keyframe);
    }

    #[test]
    fn stream_payload_type_mapping() {
        assert_eq!(StreamPayloadType::from_u16(0x00), StreamPayloadType::VideoBitstream);
        assert_eq!(StreamPayloadType::from_u16(0x01), StreamPayloadType::CodecConfig);
        assert_eq!(StreamPayloadType::from_u16(0x02), StreamPayloadType::Heartbeat);
        assert_eq!(StreamPayloadType::from_u16(0x05), StreamPayloadType::StreamingReport);
        assert_eq!(StreamPayloadType::from_u16(0x99), StreamPayloadType::Unknown(0x99));

        assert_eq!(StreamPayloadType::VideoBitstream.as_u16(), 0x00);
        assert_eq!(StreamPayloadType::CodecConfig.as_u16(), 0x01);
        assert_eq!(StreamPayloadType::Heartbeat.as_u16(), 0x02);
        assert_eq!(StreamPayloadType::StreamingReport.as_u16(), 0x05);
        assert_eq!(StreamPayloadType::Unknown(0x99).as_u16(), 0x99);
    }

    #[test]
    fn header_roundtrip_and_serialization() {
        let original = AirPlayStreamHeader {
            payload_size: 4096,
            payload_type: StreamPayloadType::VideoBitstream,
            payload_option: 2,
            timestamp_ntp: 0x0102_0304_0506_0708,
            source_width: 1920.0,
            source_height: 1080.0,
            display_width: 1920.0,
            display_height: 1080.0,
            reserved1: [0xAA; 16],
            reserved2: [0xBB; 80],
        };

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 128);

        let parsed = AirPlayStreamHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn header_oversized_rejection() {
        let mut header = AirPlayStreamHeader {
            payload_size: MAX_PAYLOAD_SIZE + 1,
            payload_type: StreamPayloadType::VideoBitstream,
            payload_option: 0,
            timestamp_ntp: 0,
            source_width: 1280.0,
            source_height: 720.0,
            display_width: 1280.0,
            display_height: 720.0,
            reserved1: [0; 16],
            reserved2: [0; 80],
        };

        let bytes = header.to_bytes();
        let result = AirPlayStreamHeader::parse(&bytes);
        assert!(matches!(result, Err(MediaError::PayloadTooLarge(..))));

        header.payload_size = MAX_PAYLOAD_SIZE;
        let valid_bytes = header.to_bytes();
        assert!(AirPlayStreamHeader::parse(&valid_bytes).is_ok());
    }

    #[test]
    fn spsc_ring_buffer_basic_push_pop_telemetry() {
        let mut ring = SpscRingBuffer::<u32>::new(4);
        assert_eq!(ring.capacity(), 4);
        assert!(ring.is_empty());

        assert!(ring.push(10).is_ok());
        assert!(ring.push(20).is_ok());
        assert_eq!(ring.len(), 2);

        let telem = ring.telemetry();
        assert_eq!(telem.packets_pushed, 2);
        assert_eq!(telem.packets_popped, 0);
        assert_eq!(telem.high_water_mark, 2);

        assert_eq!(ring.pop(), Some(10));
        assert_eq!(ring.pop(), Some(20));
        assert_eq!(ring.pop(), None);
        assert!(ring.is_empty());

        let telem = ring.telemetry();
        assert_eq!(telem.packets_popped, 2);
    }
}
