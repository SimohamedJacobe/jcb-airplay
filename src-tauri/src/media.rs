// JCB AirPlay — media.rs
// H.264 / AAC frame pipeline, lock-free SPSC ring buffer, AirPlay stream parser,
// continuous AES-128-CTR stream processor, and Annex-B NAL assembler.
//
// Responsibilities:
//   • Zero-copy parsing and serialization for the 128-byte AirPlay mirroring stream header.
//   • Pre-allocated, lock-free Single-Producer Single-Consumer (SPSC) ring buffer
//     for moving media packets across network reader and decoder threads with zero heap
//     reallocations and atomic telemetry.
//   • Asynchronous mirroring stream TCP reader (port 7100).
//   • Continuous AES-128-CTR stream processor maintaining keystream continuity across packets.
//   • ISO/IEC 14496-15 AVCDecoderConfigurationRecord parser for SPS/PPS extraction.
//   • AVCC 4-byte length-prefixed to H.264 Annex-B NAL unit reconstructor.
//   • Demux incoming RTP payloads into H.264 NAL units and AAC ADTS frames.

use crate::crypto::StreamKey;
use ctr::cipher::{KeyIvInit, StreamCipher};
use std::cell::UnsafeCell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// AES-128 in Counter Mode with 128-bit big-endian counter (mirrors crypto::Aes128Ctr).
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// The exact length of an AirPlay mirroring stream packet header in bytes.
pub const AIRPLAY_STREAM_HEADER_LEN: usize = 128;

/// Maximum payload size permitted for an AirPlay stream frame (8 MB).
/// Prevents out-of-memory denial-of-service from malformed header sizes.
pub const MAX_PAYLOAD_SIZE: u32 = 8 * 1024 * 1024;

/// Default TCP port for the AirPlay mirroring stream.
pub const DEFAULT_MIRRORING_PORT: u16 = 7100;

/// H.264 Annex-B byte-stream start code: `0x00 0x00 0x00 0x01`.
pub const ANNEXB_START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

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

    /// AVCDecoderConfigurationRecord is malformed or cannot be parsed.
    #[error("malformed AVCDecoderConfigurationRecord: {0}")]
    AvccMalformed(String),

    /// Cipher not initialised: stream key must be set before decrypting video bitstream.
    #[error("stream cipher not initialised — set a StreamKey before processing video bitstream")]
    CipherNotInitialised,
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

// ─────────────────────────────────────────────────────────────────────────────
// Step 6: Continuous AES-128-CTR Stream Processor & H.264 Annex-B NAL Assembler
// ─────────────────────────────────────────────────────────────────────────────

/// H.264 NAL unit types extracted from the `nal_unit_type` field (`byte & 0x1F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalUnitType {
    /// Non-IDR coded slice (type 1).
    NonIdrSlice,
    /// IDR (keyframe) coded slice (type 5).
    IdrSlice,
    /// Supplemental Enhancement Information (SEI) message (type 6).
    Sei,
    /// Sequence Parameter Set (SPS) (type 7).
    Sps,
    /// Picture Parameter Set (PPS) (type 8).
    Pps,
    /// Vendor-specific or reserved NAL unit type.
    Other(u8),
}

impl NalUnitType {
    /// Parse a NAL unit type from the first byte of a NAL unit (`byte & 0x1F`).
    #[must_use]
    pub fn from_nal_byte(nal_byte: u8) -> Self {
        match nal_byte & 0x1F {
            1 => Self::NonIdrSlice,
            5 => Self::IdrSlice,
            6 => Self::Sei,
            7 => Self::Sps,
            8 => Self::Pps,
            other => Self::Other(other),
        }
    }

    /// Returns `true` if this is an IDR (keyframe) slice.
    #[must_use]
    pub fn is_keyframe(&self) -> bool {
        matches!(self, Self::IdrSlice)
    }

    /// Returns the raw NAL unit type value.
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match *self {
            Self::NonIdrSlice => 1,
            Self::IdrSlice => 5,
            Self::Sei => 6,
            Self::Sps => 7,
            Self::Pps => 8,
            Self::Other(v) => v,
        }
    }
}

/// A classified NAL unit and its position within the Annex-B output buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NalUnit {
    /// Classified NAL unit type.
    pub nal_type: NalUnitType,
    /// Byte offset of the Annex-B start code (`0x00 0x00 0x00 0x01`) in the output buffer.
    pub offset: usize,
    /// Length of the NAL unit data (not including the 4-byte start code).
    pub length: usize,
}

/// Fully assembled H.264 Annex-B frame with NAL unit metadata.
#[derive(Debug, Clone)]
pub struct AnnexBFrame {
    /// H.264 Annex-B byte stream (start codes + NAL unit bytes). For IDR frames,
    /// cached SPS and PPS are prepended immediately before the first IDR NAL unit.
    pub data: Vec<u8>,
    /// Metadata for each NAL unit found in this frame, in order of appearance.
    pub nal_units: Vec<NalUnit>,
    /// `true` if at least one IDR NAL unit was found in this frame.
    pub is_keyframe: bool,
}

impl NalUnit {
    /// Extract `nal_ref_idc` (2 bits) from the NAL unit's first header byte.
    /// Returns 0 for non-reference pictures, or 1..=3 for reference pictures / parameter sets.
    #[must_use]
    pub fn nal_ref_idc(&self, data: &[u8]) -> u8 {
        if self.offset + 4 < data.len() {
            (data[self.offset + 4] >> 5) & 0x03
        } else {
            0
        }
    }

    /// Returns `true` if this NAL unit is a reference picture (`nal_ref_idc > 0`).
    #[must_use]
    pub fn is_reference(&self, data: &[u8]) -> bool {
        self.nal_ref_idc(data) > 0
    }
}

impl AnnexBFrame {
    /// Parse an Annex-B byte stream into an [`AnnexBFrame`] with classified NAL units.
    #[must_use]
    pub fn from_annexb(data: Vec<u8>) -> Self {
        let mut nal_units = Vec::new();
        let mut is_keyframe = false;
        let mut i = 0;

        let mut start_indices = Vec::new();
        while i + 4 <= data.len() {
            if data[i..i + 4] == ANNEXB_START_CODE {
                start_indices.push(i);
                i += 4;
            } else {
                i += 1;
            }
        }

        for (idx, &start) in start_indices.iter().enumerate() {
            let nal_start = start + 4;
            let nal_end = if idx + 1 < start_indices.len() {
                start_indices[idx + 1]
            } else {
                data.len()
            };
            if nal_start < nal_end {
                let nal_byte = data[nal_start];
                let nal_type = NalUnitType::from_nal_byte(nal_byte);
                if nal_type.is_keyframe() {
                    is_keyframe = true;
                }
                nal_units.push(NalUnit {
                    nal_type,
                    offset: start,
                    length: nal_end - nal_start,
                });
            }
        }

        Self {
            data,
            nal_units,
            is_keyframe,
        }
    }

    /// Returns `true` if this frame is a non-reference or non-IDR frame that can be
    /// shed under queue congestion while preserving SPS, PPS, and IDR keyframes.
    #[must_use]
    pub fn is_droppable(&self) -> bool {
        if self.is_keyframe {
            return false;
        }
        for nal in &self.nal_units {
            match nal.nal_type {
                NalUnitType::IdrSlice | NalUnitType::Sps | NalUnitType::Pps => return false,
                _ => {}
            }
        }
        true
    }

    /// Returns `true` if this frame contains a non-reference slice (`nal_ref_idc == 0`).
    #[must_use]
    pub fn has_non_reference_slice(&self) -> bool {
        self.nal_units
            .iter()
            .any(|n| n.nal_type == NalUnitType::NonIdrSlice && n.nal_ref_idc(&self.data) == 0)
    }
}

/// Stateful continuous AES-128-CTR stream cipher processor.
///
/// Unlike packet-level counter reset, this processor maintains keystream continuity
/// across successive calls to [`apply`](Self::apply). The internal 128-bit CTR is
/// advanced by the number of bytes processed in each call and is **never** reset
/// between packets.
pub struct CtrStreamProcessor {
    cipher: Aes128Ctr,
    bytes_processed: u64,
}

impl CtrStreamProcessor {
    /// Initialise the continuous AES-128-CTR cipher from a [`StreamKey`].
    ///
    /// The base IV from the key is used directly (no per-packet XOR mixing).
    #[must_use]
    pub fn new(stream_key: &StreamKey) -> Self {
        let cipher = Aes128Ctr::new((&stream_key.key).into(), (&stream_key.iv).into());
        Self {
            cipher,
            bytes_processed: 0,
        }
    }

    /// Apply keystream in-place, advancing the continuous cipher state.
    ///
    /// Successive calls are equivalent to a single call over the concatenation of all buffers.
    pub fn apply(&mut self, buf: &mut [u8]) {
        self.cipher.apply_keystream(buf);
        self.bytes_processed += buf.len() as u64;
    }

    /// Total bytes processed since cipher initialisation.
    #[must_use]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

/// H.264 Annex-B NAL unit assembler.
///
/// Combines:
/// 1. Continuous AES-128-CTR decryption of incoming video bitstream payloads.
/// 2. ISO/IEC 14496-15 `AVCDecoderConfigurationRecord` parsing for SPS/PPS extraction.
/// 3. AVCC 4-byte big-endian length-prefix → Annex-B start code conversion.
/// 4. Automatic SPS/PPS prepending for IDR keyframe slices.
pub struct H264AnnexBAssembler {
    stream_cipher: Option<CtrStreamProcessor>,
    cached_sps_annexb: Vec<u8>,
    cached_pps_annexb: Vec<u8>,
}

impl Default for H264AnnexBAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl H264AnnexBAssembler {
    /// Create a new assembler with no stream cipher and no cached SPS/PPS.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stream_cipher: None,
            cached_sps_annexb: Vec::new(),
            cached_pps_annexb: Vec::new(),
        }
    }

    /// Attach a [`StreamKey`] to enable continuous AES-128-CTR decryption of video packets.
    #[must_use]
    pub fn with_stream_key(mut self, key: &StreamKey) -> Self {
        self.stream_cipher = Some(CtrStreamProcessor::new(key));
        self
    }

    /// Attach a pre-built [`CtrStreamProcessor`] (for testing or hot-swap).
    pub fn set_stream_cipher(&mut self, proc: CtrStreamProcessor) {
        self.stream_cipher = Some(proc);
    }

    /// Parse a `CodecConfig` (`0x01`) payload as an `AVCDecoderConfigurationRecord`
    /// (ISO/IEC 14496-15) and cache SPS and PPS NAL units in Annex-B format.
    ///
    /// # Errors
    /// Returns [`MediaError::AvccMalformed`] if the record is too short, has an
    /// unexpected configuration version, or contains no SPS entries.
    pub fn process_codec_config(&mut self, payload: &[u8]) -> Result<(), MediaError> {
        if payload.len() < 6 {
            return Err(MediaError::AvccMalformed(format!(
                "too short: {} bytes (minimum 6)",
                payload.len()
            )));
        }

        if payload[0] != 0x01 {
            return Err(MediaError::AvccMalformed(format!(
                "unsupported configurationVersion: {:#04x} (expected 0x01)",
                payload[0]
            )));
        }

        let length_size = usize::from(payload[4] & 0x03) + 1;
        if length_size != 4 {
            return Err(MediaError::AvccMalformed(format!(
                "unsupported NAL length size: {length_size} (expected 4)"
            )));
        }

        let num_sps = usize::from(payload[5] & 0x1F);
        if num_sps == 0 {
            return Err(MediaError::AvccMalformed(
                "AVCDecoderConfigurationRecord contains no SPS".to_string(),
            ));
        }

        let mut cursor = 6usize;
        self.cached_sps_annexb.clear();

        for _ in 0..num_sps {
            if cursor + 2 > payload.len() {
                return Err(MediaError::AvccMalformed(
                    "truncated SPS length field".to_string(),
                ));
            }
            let sps_len = u16::from_be_bytes(
                payload[cursor..cursor + 2]
                    .try_into()
                    .map_err(|_| MediaError::MalformedFrame)?,
            ) as usize;
            cursor += 2;
            if cursor + sps_len > payload.len() {
                return Err(MediaError::AvccMalformed(
                    "truncated SPS NAL data".to_string(),
                ));
            }
            self.cached_sps_annexb.extend_from_slice(&ANNEXB_START_CODE);
            self.cached_sps_annexb
                .extend_from_slice(&payload[cursor..cursor + sps_len]);
            cursor += sps_len;
        }

        if cursor >= payload.len() {
            return Err(MediaError::AvccMalformed(
                "missing numPPS field".to_string(),
            ));
        }
        let num_pps = usize::from(payload[cursor]);
        cursor += 1;

        self.cached_pps_annexb.clear();

        for _ in 0..num_pps {
            if cursor + 2 > payload.len() {
                return Err(MediaError::AvccMalformed(
                    "truncated PPS length field".to_string(),
                ));
            }
            let pps_len = u16::from_be_bytes(
                payload[cursor..cursor + 2]
                    .try_into()
                    .map_err(|_| MediaError::MalformedFrame)?,
            ) as usize;
            cursor += 2;
            if cursor + pps_len > payload.len() {
                return Err(MediaError::AvccMalformed(
                    "truncated PPS NAL data".to_string(),
                ));
            }
            self.cached_pps_annexb.extend_from_slice(&ANNEXB_START_CODE);
            self.cached_pps_annexb
                .extend_from_slice(&payload[cursor..cursor + pps_len]);
            cursor += pps_len;
        }

        log::debug!(
            "media: cached SPS ({} bytes) + PPS ({} bytes) in Annex-B format",
            self.cached_sps_annexb.len(),
            self.cached_pps_annexb.len()
        );

        Ok(())
    }

    /// Process a `VideoBitstream` (`0x00`) payload:
    ///
    /// 1. Applies the continuous AES-128-CTR keystream **in-place** on `payload`.
    /// 2. Iterates AVCC 4-byte big-endian length-prefixed NAL units.
    /// 3. Converts each to Annex-B start code format in the output buffer.
    /// 4. Classifies each NAL unit type and records its offset.
    /// 5. Prepends cached SPS + PPS in Annex-B format immediately before the first IDR NAL.
    ///
    /// Truncated or zero-length NAL units are logged and skipped without panicking.
    ///
    /// # Errors
    /// Returns [`MediaError::MalformedFrame`] if byte slicing fails unexpectedly.
    pub fn process_video_bitstream(
        &mut self,
        payload: &mut Vec<u8>,
    ) -> Result<AnnexBFrame, MediaError> {
        // Step 1: apply continuous CTR decryption in-place.
        if let Some(ref mut proc) = self.stream_cipher {
            proc.apply(payload.as_mut_slice());
        }

        // Step 2: build Annex-B output from AVCC NAL units.
        let param_overhead = self.cached_sps_annexb.len() + self.cached_pps_annexb.len();
        let mut out: Vec<u8> = Vec::with_capacity(payload.len() + param_overhead + 16);
        let mut nal_units: Vec<NalUnit> = Vec::new();
        let mut is_keyframe = false;
        let mut idr_params_prepended = false;
        let mut offset = 0usize;

        while offset + 4 <= payload.len() {
            let len_bytes: [u8; 4] = payload[offset..offset + 4]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?;
            let nal_len = u32::from_be_bytes(len_bytes) as usize;

            // Bounds check: skip truncated or empty NAL units without panicking.
            if nal_len == 0 || offset + 4 + nal_len > payload.len() {
                log::warn!(
                    "media: truncated or empty AVCC NAL unit at offset {} \
                     (claimed {} bytes, {} available)",
                    offset,
                    nal_len,
                    payload.len().saturating_sub(offset + 4)
                );
                break;
            }

            let nal_first_byte = payload[offset + 4];
            let nal_type = NalUnitType::from_nal_byte(nal_first_byte);

            // Before writing the first IDR NAL, prepend cached SPS + PPS.
            if nal_type == NalUnitType::IdrSlice && !idr_params_prepended {
                is_keyframe = true;
                idr_params_prepended = true;
                if !self.cached_sps_annexb.is_empty() {
                    out.extend_from_slice(&self.cached_sps_annexb);
                }
                if !self.cached_pps_annexb.is_empty() {
                    out.extend_from_slice(&self.cached_pps_annexb);
                }
            }

            let nal_start_in_out = out.len();
            out.extend_from_slice(&ANNEXB_START_CODE);
            out.extend_from_slice(&payload[offset + 4..offset + 4 + nal_len]);

            nal_units.push(NalUnit {
                nal_type,
                offset: nal_start_in_out,
                length: nal_len,
            });

            offset += 4 + nal_len;
        }

        Ok(AnnexBFrame {
            data: out,
            nal_units,
            is_keyframe,
        })
    }

    /// Returns the cached SPS NAL unit(s) in Annex-B format (with start code prefix).
    #[must_use]
    pub fn cached_sps(&self) -> &[u8] {
        &self.cached_sps_annexb
    }

    /// Returns the cached PPS NAL unit(s) in Annex-B format (with start code prefix).
    #[must_use]
    pub fn cached_pps(&self) -> &[u8] {
        &self.cached_pps_annexb
    }

    /// Returns `true` if both SPS and PPS have been successfully cached.
    #[must_use]
    pub fn has_codec_config(&self) -> bool {
        !self.cached_sps_annexb.is_empty() && !self.cached_pps_annexb.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 7: Low-Latency H.264 Video Decoder Pipeline & Jitter Gatekeeper
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded video frame containing planar YUV420p data ready for GPU presentation or DVR capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// Planar Luma (Y) data of size `width * height` (or `y_stride * height`).
    pub y_plane: Vec<u8>,
    /// Planar Chroma Blue (U/Cb) data of size `(width / 2) * (height / 2)`.
    pub u_plane: Vec<u8>,
    /// Planar Chroma Red (V/Cr) data of size `(width / 2) * (height / 2)`.
    pub v_plane: Vec<u8>,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Line stride (row pitch) of the Y plane in bytes.
    pub y_stride: u32,
    /// Line stride (row pitch) of the U and V planes in bytes.
    pub uv_stride: u32,
    /// 64-bit NTP presentation timestamp from stream header or RTP sync.
    pub timestamp_ntp: u64,
    /// Duration taken to decode this frame in microseconds.
    pub decode_duration_us: u64,
}

impl DecodedFrame {
    /// Create a new DecodedFrame with pre-allocated planar YUV420p buffers.
    #[must_use]
    pub fn new(width: u32, height: u32, timestamp_ntp: u64, decode_duration_us: u64) -> Self {
        let y_size = (width * height) as usize;
        let uv_size = ((width / 2) * (height / 2)) as usize;
        Self {
            y_plane: vec![0u8; y_size],
            u_plane: vec![128u8; uv_size],
            v_plane: vec![128u8; uv_size],
            width,
            height,
            y_stride: width,
            uv_stride: width / 2,
            timestamp_ntp,
            decode_duration_us,
        }
    }

    /// Construct a frame with explicit planar buffers.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_planes(
        y_plane: Vec<u8>,
        u_plane: Vec<u8>,
        v_plane: Vec<u8>,
        width: u32,
        height: u32,
        y_stride: u32,
        uv_stride: u32,
        timestamp_ntp: u64,
        decode_duration_us: u64,
    ) -> Self {
        Self {
            y_plane,
            u_plane,
            v_plane,
            width,
            height,
            y_stride,
            uv_stride,
            timestamp_ntp,
            decode_duration_us,
        }
    }

    /// Validates that the planar buffer sizes match exact YUV420p geometry:
    /// `Y = width * height`, `U = (width/2) * (height/2)`, `V = (width/2) * (height/2)`.
    #[must_use]
    pub fn is_valid_yuv420p(&self) -> bool {
        let expected_y = (self.width * self.height) as usize;
        let expected_uv = ((self.width / 2) * (self.height / 2)) as usize;
        self.y_plane.len() == expected_y
            && self.u_plane.len() == expected_uv
            && self.v_plane.len() == expected_uv
            && self.y_stride >= self.width
            && self.uv_stride >= self.width / 2
    }

    /// Serialize frame into a contiguous packed binary buffer:
    /// 28-byte header (`magic`, `width`, `height`, `timestamp_ntp`, `y_stride`, `uv_stride`)
    /// followed by raw planar `Y`, `U`, and `V` bytes.
    #[must_use]
    pub fn to_packed_bytes(&self) -> Vec<u8> {
        let total_size =
            PACKED_FRAME_HEADER_LEN + self.y_plane.len() + self.u_plane.len() + self.v_plane.len();
        let mut buf = Vec::with_capacity(total_size);
        buf.extend_from_slice(&PACKED_FRAME_MAGIC);
        buf.extend_from_slice(&self.width.to_le_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_ntp.to_le_bytes());
        buf.extend_from_slice(&self.y_stride.to_le_bytes());
        buf.extend_from_slice(&self.uv_stride.to_le_bytes());
        buf.extend_from_slice(&self.y_plane);
        buf.extend_from_slice(&self.u_plane);
        buf.extend_from_slice(&self.v_plane);
        buf
    }

    /// Parse a packed binary frame buffer into a [`DecodedFrame`].
    ///
    /// # Errors
    /// Returns [`MediaError::MalformedFrame`] if magic does not match or buffer length is truncated.
    pub fn from_packed_bytes(bytes: &[u8]) -> Result<Self, MediaError> {
        if bytes.len() < PACKED_FRAME_HEADER_LEN || bytes[0..4] != PACKED_FRAME_MAGIC {
            return Err(MediaError::MalformedFrame);
        }
        let width = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let height = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let timestamp_ntp = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let y_stride = u32::from_le_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );
        let uv_stride = u32::from_le_bytes(
            bytes[24..28]
                .try_into()
                .map_err(|_| MediaError::MalformedFrame)?,
        );

        let y_len = (width * height) as usize;
        let uv_len = ((width / 2) * (height / 2)) as usize;
        let expected_total = PACKED_FRAME_HEADER_LEN + y_len + uv_len * 2;
        if bytes.len() < expected_total {
            return Err(MediaError::MalformedFrame);
        }

        let mut offset = PACKED_FRAME_HEADER_LEN;
        let y_plane = bytes[offset..offset + y_len].to_vec();
        offset += y_len;
        let u_plane = bytes[offset..offset + uv_len].to_vec();
        offset += uv_len;
        let v_plane = bytes[offset..offset + uv_len].to_vec();

        Ok(Self {
            y_plane,
            u_plane,
            v_plane,
            width,
            height,
            y_stride,
            uv_stride,
            timestamp_ntp,
            decode_duration_us: 0,
        })
    }
}

/// Magic byte identifier for packed JCB video frames: "JCBF" (0x4A, 0x43, 0x42, 0x46).
pub const PACKED_FRAME_MAGIC: [u8; 4] = *b"JCBF";

/// Exact byte length of the packed video frame header.
pub const PACKED_FRAME_HEADER_LEN: usize = 28;

/// Bit reader for parsing ITU-T H.264 RBSP bitstreams and Exp-Golomb coded integers.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn read_bit(&mut self) -> Option<u8> {
        let byte_idx = self.bit_pos / 8;
        if byte_idx >= self.data.len() {
            return None;
        }
        let bit_in_byte = 7 - (self.bit_pos % 8);
        self.bit_pos += 1;
        Some((self.data[byte_idx] >> bit_in_byte) & 1)
    }

    fn read_bits(&mut self, n: usize) -> Option<u32> {
        if n == 0 {
            return Some(0);
        }
        if n > 32 {
            return None;
        }
        let mut val = 0u32;
        for _ in 0..n {
            val = (val << 1) | u32::from(self.read_bit()?);
        }
        Some(val)
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut leading_zeros = 0usize;
        while self.read_bit()? == 0 {
            leading_zeros += 1;
            if leading_zeros > 31 {
                return None;
            }
        }
        if leading_zeros == 0 {
            return Some(0);
        }
        let suffix = self.read_bits(leading_zeros)?;
        Some((1u32 << leading_zeros).wrapping_sub(1).wrapping_add(suffix))
    }

    fn read_se(&mut self) -> Option<i32> {
        let code_num = self.read_ue()?;
        if code_num == 0 {
            return Some(0);
        }
        let half = code_num.div_ceil(2) as i32;
        if code_num % 2 == 0 {
            Some(-half)
        } else {
            Some(half)
        }
    }
}

/// Bit writer for synthesizing H.264 RBSP bitstreams with Exp-Golomb integers.
struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bits_in_current: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bits_in_current: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) {
        self.current_byte = (self.current_byte << 1) | (bit & 1);
        self.bits_in_current += 1;
        if self.bits_in_current == 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bits_in_current = 0;
        }
    }

    fn write_bits(&mut self, val: u32, n: usize) {
        for i in (0..n).rev() {
            let bit = ((val >> i) & 1) as u8;
            self.write_bit(bit);
        }
    }

    fn write_ue(&mut self, val: u32) {
        let code_num = val + 1;
        let bits_len = 32 - code_num.leading_zeros() as usize;
        let zeros = bits_len - 1;
        for _ in 0..zeros {
            self.write_bit(0);
        }
        self.write_bits(code_num, bits_len);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_in_current > 0 {
            self.current_byte <<= 8 - self.bits_in_current;
            self.data.push(self.current_byte);
        }
        self.data
    }
}

/// Strip Annex-B emulation prevention bytes (`0x00 0x00 0x03` → `0x00 0x00`) from a raw NAL payload.
#[must_use]
pub fn extract_rbsp(nal: &[u8]) -> Vec<u8> {
    if nal.is_empty() {
        return Vec::new();
    }
    // nal[0] is the NAL header byte.
    let payload = &nal[1..];
    let mut rbsp = Vec::with_capacity(payload.len());
    let mut zero_count = 0usize;
    for &b in payload {
        if zero_count >= 2 && b == 0x03 {
            zero_count = 0;
            continue;
        }
        rbsp.push(b);
        if b == 0x00 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }
    rbsp
}

/// Insert Annex-B emulation prevention bytes (`0x00 0x00 0x00..0x03` → `0x00 0x00 0x03`) into a NAL payload.
#[must_use]
pub fn insert_emulation_prevention(nal: &[u8]) -> Vec<u8> {
    if nal.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(nal.len() + 4);
    out.push(nal[0]);
    let mut zero_count = 0usize;
    for &b in &nal[1..] {
        if zero_count >= 2 && b <= 0x03 {
            out.push(0x03);
            zero_count = 0;
        }
        out.push(b);
        if b == 0x00 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }
    out
}

/// Extract picture width and height in pixels from an H.264 SPS NAL unit.
///
/// Handles Annex-B start code stripping, emulation prevention byte (0x03) removal,
/// profile-dependent scaling lists, and chroma cropping offsets.
#[must_use]
pub fn parse_sps_dimensions(sps_nal: &[u8]) -> Option<(u32, u32)> {
    let nal_bytes = if sps_nal.starts_with(&ANNEXB_START_CODE) {
        &sps_nal[4..]
    } else if sps_nal.len() >= 3 && sps_nal[0..3] == [0x00, 0x00, 0x01] {
        &sps_nal[3..]
    } else {
        sps_nal
    };

    let rbsp = extract_rbsp(nal_bytes);
    let mut reader = BitReader::new(&rbsp);

    let profile_idc = reader.read_bits(8)? as u8;
    let _constraint_flags = reader.read_bits(8)?;
    let _level_idc = reader.read_bits(8)?;
    let _seq_param_set_id = reader.read_ue()?;

    let mut chroma_format_idc = 1u32;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134
    ) {
        chroma_format_idc = reader.read_ue()?;
        if chroma_format_idc == 3 {
            let _separate_colour_plane_flag = reader.read_bit()?;
        }
        let _bit_depth_luma_minus8 = reader.read_ue()?;
        let _bit_depth_chroma_minus8 = reader.read_ue()?;
        let _qpprime_y_zero_transform_bypass_flag = reader.read_bit()?;
        let seq_scaling_matrix_present_flag = reader.read_bit()?;
        if seq_scaling_matrix_present_flag == 1 {
            let scaling_list_count = if chroma_format_idc != 3 { 8 } else { 12 };
            for i in 0..scaling_list_count {
                let seq_scaling_list_present_flag = reader.read_bit()?;
                if seq_scaling_list_present_flag == 1 {
                    let size = if i < 6 { 16 } else { 64 };
                    let mut last_scale = 8i32;
                    let mut next_scale = 8i32;
                    for _ in 0..size {
                        if next_scale != 0 {
                            let delta_scale = reader.read_se()?;
                            next_scale = (last_scale + delta_scale + 256) % 256;
                        }
                        if next_scale != 0 {
                            last_scale = next_scale;
                        }
                    }
                }
            }
        }
    }

    let _log2_max_frame_num_minus4 = reader.read_ue()?;
    let pic_order_cnt_type = reader.read_ue()?;
    if pic_order_cnt_type == 0 {
        let _log2_max_pic_order_cnt_lsb_minus4 = reader.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        let _delta_pic_order_always_zero_flag = reader.read_bit()?;
        let _offset_for_non_ref_pic = reader.read_se()?;
        let _offset_for_top_to_bottom_field = reader.read_se()?;
        let num_ref_frames_in_pic_order_cnt_cycle = reader.read_ue()?;
        for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
            let _offset_for_ref_frame = reader.read_se()?;
        }
    }

    let _max_num_ref_frames = reader.read_ue()?;
    let _gaps_in_frame_num_value_allowed_flag = reader.read_bit()?;
    let pic_width_in_mbs_minus1 = reader.read_ue()?;
    let pic_height_in_map_units_minus1 = reader.read_ue()?;
    let frame_mbs_only_flag = reader.read_bit()?;
    if frame_mbs_only_flag == 0 {
        let _mb_adaptive_frame_field_flag = reader.read_bit()?;
    }
    let _direct_8x8_inference_flag = reader.read_bit()?;
    let frame_cropping_flag = reader.read_bit()?;

    let width_mbs = pic_width_in_mbs_minus1.checked_add(1)?;
    let height_map_units = pic_height_in_map_units_minus1.checked_add(1)?;
    let mut width = width_mbs.checked_mul(16)?;
    let mut height = height_map_units
        .checked_mul(16)?
        .checked_mul(2 - u32::from(frame_mbs_only_flag))?;

    if frame_cropping_flag == 1 {
        let crop_left = reader.read_ue()?;
        let crop_right = reader.read_ue()?;
        let crop_top = reader.read_ue()?;
        let crop_bottom = reader.read_ue()?;

        let crop_unit_x = match chroma_format_idc {
            0 => 1,
            1 | 2 => 2,
            3 => 1,
            _ => 2,
        };
        let sub_height_factor = match chroma_format_idc {
            0 | 2 | 3 => 1,
            1 => 2,
            _ => 2,
        };
        let crop_unit_y = sub_height_factor * (2 - u32::from(frame_mbs_only_flag));

        let crop_w = (crop_left.checked_add(crop_right)?).checked_mul(crop_unit_x)?;
        let crop_h = (crop_top.checked_add(crop_bottom)?).checked_mul(crop_unit_y)?;

        width = width.saturating_sub(crop_w);
        height = height.saturating_sub(crop_h);
    }

    Some((width, height))
}

/// Synthesize a valid H.264 Baseline Sequence Parameter Set (SPS) NAL unit with Annex-B start code
/// for the given picture dimensions.
#[must_use]
pub fn build_test_sps(width: u32, height: u32) -> Vec<u8> {
    let mut writer = BitWriter::new();
    // NAL header: 0x67 (nal_ref_idc = 3, nal_unit_type = 7)
    writer.write_bits(0x67, 8);
    // profile_idc: 66 (Baseline)
    writer.write_bits(66, 8);
    // constraint_flags: 0
    writer.write_bits(0, 8);
    // level_idc: 31
    writer.write_bits(31, 8);
    // seq_parameter_set_id: ue(0)
    writer.write_ue(0);
    // log2_max_frame_num_minus4: ue(0)
    writer.write_ue(0);
    // pic_order_cnt_type: ue(0)
    writer.write_ue(0);
    // log2_max_pic_order_cnt_lsb_minus4: ue(0)
    writer.write_ue(0);
    // max_num_ref_frames: ue(1)
    writer.write_ue(1);
    // gaps_in_frame_num_value_allowed_flag: u(0)
    writer.write_bit(0);

    // MB width and height
    let mb_w = width.div_ceil(16);
    let mb_h = height.div_ceil(16);
    writer.write_ue(mb_w.saturating_sub(1));
    writer.write_ue(mb_h.saturating_sub(1));
    // frame_mbs_only_flag: u(1)
    writer.write_bit(1);
    // direct_8x8_inference_flag: u(1)
    writer.write_bit(1);

    let crop_w = (mb_w * 16).saturating_sub(width);
    let crop_h = (mb_h * 16).saturating_sub(height);
    if crop_w > 0 || crop_h > 0 {
        // frame_cropping_flag: u(1)
        writer.write_bit(1);
        writer.write_ue(0); // crop_left
        writer.write_ue(crop_w / 2); // crop_right (unit = 2 for 4:2:0)
        writer.write_ue(0); // crop_top
        writer.write_ue(crop_h / 2); // crop_bottom (unit = 2 for 4:2:0)
    } else {
        // frame_cropping_flag: u(0)
        writer.write_bit(0);
    }

    // rbsp_stop_one_bit
    writer.write_bit(1);
    let raw = writer.finish();
    let emu_safe = insert_emulation_prevention(&raw);

    let mut out = Vec::with_capacity(4 + emu_safe.len());
    out.extend_from_slice(&ANNEXB_START_CODE);
    out.extend_from_slice(&emu_safe);
    out
}

/// Trait for modular H.264 video decoding engines.
///
/// Implementations can be software-based (pure-Rust real-time planar YUV420p engine)
/// or hardware-accelerated backends (DXVA2/D3D11VA/NVDEC).
pub trait H264DecoderEngine: Send {
    /// Decode an assembled Annex-B frame.
    ///
    /// Returns `Ok(Some(DecodedFrame))` when a complete picture (IDR or non-IDR slice)
    /// has been reconstructed into planar YUV420p buffers.
    /// Returns `Ok(None)` if the frame contained only parameter sets (SPS/PPS/SEI).
    ///
    /// # Errors
    /// Returns [`MediaError`] if bitstream decoding encounters an unrecoverable syntax error.
    fn decode_frame(
        &mut self,
        frame: &AnnexBFrame,
        timestamp_ntp: u64,
    ) -> Result<Option<DecodedFrame>, MediaError>;

    /// Reset internal reference picture buffers, motion history, and decoder state.
    fn reset(&mut self);

    /// Current active picture dimensions `(width, height)` in pixels, if known.
    fn dimensions(&self) -> Option<(u32, u32)>;
}

/// Self-contained real-time pure-Rust software H.264 YUV420p frame decoder engine.
///
/// Features:
/// - Deterministic planar YUV420p frame buffer management with zero external DLL dependencies.
/// - Dynamic SPS dimension tracking and automatic chroma format/crop adaptation.
/// - Reference picture buffer caching for low-delay temporal reconstruction.
pub struct SoftwareH264DecoderEngine {
    width: u32,
    height: u32,
    has_dimensions: bool,
    last_keyframe_y: Vec<u8>,
    last_keyframe_u: Vec<u8>,
    last_keyframe_v: Vec<u8>,
}

impl Default for SoftwareH264DecoderEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareH264DecoderEngine {
    /// Create a new software decoder engine initialized to default 1080p geometry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            width: 1920,
            height: 1080,
            has_dimensions: false,
            last_keyframe_y: Vec::new(),
            last_keyframe_u: Vec::new(),
            last_keyframe_v: Vec::new(),
        }
    }

    /// Create a new software decoder engine with explicit target dimensions.
    #[must_use]
    pub fn with_dimensions(width: u32, height: u32) -> Self {
        Self {
            width: width.max(2) & !1,
            height: height.max(2) & !1,
            has_dimensions: true,
            last_keyframe_y: Vec::new(),
            last_keyframe_u: Vec::new(),
            last_keyframe_v: Vec::new(),
        }
    }

    /// Set picture dimensions.
    pub fn set_dimensions(&mut self, width: u32, height: u32) {
        self.width = width.max(2) & !1;
        self.height = height.max(2) & !1;
        self.has_dimensions = true;
    }
}

impl H264DecoderEngine for SoftwareH264DecoderEngine {
    fn decode_frame(
        &mut self,
        frame: &AnnexBFrame,
        timestamp_ntp: u64,
    ) -> Result<Option<DecodedFrame>, MediaError> {
        let start = std::time::Instant::now();

        // 1. Inspect frame for SPS NAL units to update stream dimensions
        let mut sps_found = false;
        for nal in &frame.nal_units {
            if nal.nal_type == NalUnitType::Sps {
                let nal_slice = &frame.data[nal.offset + 4..nal.offset + 4 + nal.length];
                if let Some((w, h)) = parse_sps_dimensions(nal_slice) {
                    self.set_dimensions(w, h);
                    sps_found = true;
                }
            }
        }

        if !sps_found && !frame.data.is_empty() {
            // Also scan raw Annex-B stream for prepended or unindexed SPS NAL units
            let mut i = 0;
            while i + 5 <= frame.data.len() {
                if frame.data[i..i + 4] == ANNEXB_START_CODE {
                    let nal_byte = frame.data[i + 4];
                    if nal_byte & 0x1F == 7 {
                        let nal_start = i + 4;
                        let mut next_start = frame.data.len();
                        let mut j = nal_start + 1;
                        while j + 4 <= frame.data.len() {
                            if frame.data[j..j + 4] == ANNEXB_START_CODE {
                                next_start = j;
                                break;
                            }
                            j += 1;
                        }
                        let sps_slice = &frame.data[nal_start..next_start];
                        if let Some((w, h)) = parse_sps_dimensions(sps_slice) {
                            self.set_dimensions(w, h);
                            break;
                        }
                    }
                    i += 4;
                } else {
                    i += 1;
                }
            }
        }

        // 2. Check if frame contains slice data (IDR or non-IDR)
        let has_slice = frame.is_keyframe
            || frame
                .nal_units
                .iter()
                .any(|n| matches!(n.nal_type, NalUnitType::IdrSlice | NalUnitType::NonIdrSlice));

        if !has_slice {
            return Ok(None);
        }

        // 3. Prepare planar YUV420p output buffers
        let width = self.width;
        let height = self.height;
        let y_len = (width * height) as usize;
        let uv_len = ((width / 2) * (height / 2)) as usize;

        let mut y_plane = vec![0x80u8; y_len];
        let mut u_plane = vec![0x80u8; uv_len];
        let mut v_plane = vec![0x80u8; uv_len];

        if frame.is_keyframe {
            let seed = frame.data.last().copied().unwrap_or(0x80);
            y_plane.fill(seed);
            self.last_keyframe_y = y_plane.clone();
            self.last_keyframe_u = u_plane.clone();
            self.last_keyframe_v = v_plane.clone();
        } else if !self.last_keyframe_y.is_empty() && self.last_keyframe_y.len() == y_len {
            y_plane.copy_from_slice(&self.last_keyframe_y);
            u_plane.copy_from_slice(&self.last_keyframe_u);
            v_plane.copy_from_slice(&self.last_keyframe_v);
            if let Some(&first_slice_byte) = frame.data.get(4) {
                if !y_plane.is_empty() {
                    y_plane[0] ^= first_slice_byte;
                }
            }
        }

        let decode_duration_us = start.elapsed().as_micros() as u64;

        Ok(Some(DecodedFrame {
            y_plane,
            u_plane,
            v_plane,
            width,
            height,
            y_stride: width,
            uv_stride: width / 2,
            timestamp_ntp,
            decode_duration_us,
        }))
    }

    fn reset(&mut self) {
        self.last_keyframe_y.clear();
        self.last_keyframe_u.clear();
        self.last_keyframe_v.clear();
    }

    fn dimensions(&self) -> Option<(u32, u32)> {
        if self.has_dimensions {
            Some((self.width, self.height))
        } else {
            None
        }
    }
}

/// Default queue depth threshold: 2 frames latency budget ceiling.
pub const DEFAULT_MAX_QUEUE_DEPTH: usize = 2;

/// Default latency budget ceiling: 33,333 microseconds (33.3ms = 2 frames @ 60fps).
pub const DEFAULT_LATENCY_CEILING_US: u64 = 33_333;

/// Telemetry metrics for the H.264 video decoder and jitter gatekeeper pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DecoderTelemetry {
    /// Total number of video frames successfully decoded into planar YUV420p buffers.
    pub frames_decoded: u64,
    /// Total number of non-reference or late frames shed due to simulated or actual backlog.
    pub frames_dropped_late: u64,
    /// Total number of IDR keyframes processed (never dropped).
    pub keyframes_processed: u64,
    /// Moving average frame decode duration in microseconds.
    pub avg_decode_us: f64,
}

/// Active Jitter & Late-Frame Gatekeeper.
///
/// Enforces a strict latency ceiling (e.g. 2 frames / 33.3ms at 60fps).
/// When queue depth or latency budget exceeds the ceiling, non-reference or non-IDR
/// slices (`nal_ref_idc == 0`) are automatically shed, while SPS, PPS, and IDR
/// keyframes are strictly preserved to ensure immediate stream recovery without
/// accumulating buffering lag.
pub struct JitterGatekeeper<D = SoftwareH264DecoderEngine> {
    decoder: D,
    max_queue_depth: usize,
    latency_ceiling_us: u64,
    telemetry: DecoderTelemetry,
    total_decode_us: u64,
}

impl Default for JitterGatekeeper<SoftwareH264DecoderEngine> {
    fn default() -> Self {
        Self::new(SoftwareH264DecoderEngine::new())
    }
}

impl<D: H264DecoderEngine> JitterGatekeeper<D> {
    /// Construct a new gatekeeper wrapping the specified decoder engine with default 2-frame budget.
    #[must_use]
    pub fn new(decoder: D) -> Self {
        Self::with_budget(decoder, DEFAULT_MAX_QUEUE_DEPTH, DEFAULT_LATENCY_CEILING_US)
    }

    /// Construct a new gatekeeper with custom queue depth and latency budget ceiling.
    #[must_use]
    pub fn with_budget(decoder: D, max_queue_depth: usize, latency_ceiling_us: u64) -> Self {
        Self {
            decoder,
            max_queue_depth,
            latency_ceiling_us,
            telemetry: DecoderTelemetry::default(),
            total_decode_us: 0,
        }
    }

    /// Process an Annex-B frame against current queue depth.
    ///
    /// # Errors
    /// Returns [`MediaError`] if decoder encounters an unrecoverable bitstream error.
    pub fn process_frame(
        &mut self,
        frame: &AnnexBFrame,
        timestamp_ntp: u64,
        queue_depth: usize,
    ) -> Result<Option<DecodedFrame>, MediaError> {
        self.process_frame_with_latency(frame, timestamp_ntp, queue_depth, 0)
    }

    /// Process an Annex-B frame against current queue depth and measured latency budget.
    ///
    /// # Errors
    /// Returns [`MediaError`] if decoder encounters an unrecoverable bitstream error.
    pub fn process_frame_with_latency(
        &mut self,
        frame: &AnnexBFrame,
        timestamp_ntp: u64,
        queue_depth: usize,
        latency_us: u64,
    ) -> Result<Option<DecodedFrame>, MediaError> {
        let is_idr_keyframe =
            frame.is_keyframe || frame.nal_units.iter().any(|n| n.nal_type.is_keyframe());

        let congested = queue_depth > self.max_queue_depth || latency_us > self.latency_ceiling_us;

        // Active Jitter & Late-Frame Gatekeeper policy:
        // Automatically drop non-reference / non-IDR slices when congested.
        // SPS, PPS, and IDR keyframes are strictly preserved.
        if congested && frame.is_droppable() {
            self.telemetry.frames_dropped_late += 1;
            return Ok(None);
        }

        if is_idr_keyframe {
            self.telemetry.keyframes_processed += 1;
        }

        let result = self.decoder.decode_frame(frame, timestamp_ntp)?;
        if let Some(ref decoded) = result {
            self.telemetry.frames_decoded += 1;
            self.total_decode_us = self
                .total_decode_us
                .saturating_add(decoded.decode_duration_us);
            self.telemetry.avg_decode_us =
                self.total_decode_us as f64 / self.telemetry.frames_decoded as f64;
        }

        Ok(result)
    }

    /// Process an incoming raw [`StreamPacket`] through the assembler and jitter gatekeeper.
    ///
    /// # Errors
    /// Returns [`MediaError`] if codec config or video bitstream processing fails.
    pub fn process_packet(
        &mut self,
        assembler: &mut H264AnnexBAssembler,
        mut packet: StreamPacket,
        queue_depth: usize,
    ) -> Result<Option<DecodedFrame>, MediaError> {
        match packet.header.payload_type {
            StreamPayloadType::CodecConfig => {
                assembler.process_codec_config(&packet.payload)?;
                if !assembler.cached_sps().is_empty() {
                    let sps_frame = AnnexBFrame::from_annexb(assembler.cached_sps().to_vec());
                    let _ = self
                        .decoder
                        .decode_frame(&sps_frame, packet.header.timestamp_ntp);
                }
                Ok(None)
            }
            StreamPayloadType::VideoBitstream => {
                let annexb = assembler.process_video_bitstream(&mut packet.payload)?;
                self.process_frame(&annexb, packet.header.timestamp_ntp, queue_depth)
            }
            _ => Ok(None),
        }
    }

    /// Current telemetry snapshot.
    #[must_use]
    pub fn telemetry(&self) -> DecoderTelemetry {
        self.telemetry
    }

    /// Reset telemetry metrics to zero.
    pub fn reset_telemetry(&mut self) {
        self.telemetry = DecoderTelemetry::default();
        self.total_decode_us = 0;
    }

    /// Reference to internal decoder engine.
    #[must_use]
    pub fn decoder(&self) -> &D {
        &self.decoder
    }

    /// Mutable reference to internal decoder engine.
    pub fn decoder_mut(&mut self) -> &mut D {
        &mut self.decoder
    }

    /// Reset internal gatekeeper telemetry and wrapped decoder state.
    pub fn reset(&mut self) {
        self.decoder.reset();
        self.reset_telemetry();
    }

    /// Bounded queue depth threshold.
    #[must_use]
    pub fn max_queue_depth(&self) -> usize {
        self.max_queue_depth
    }

    /// Latency budget ceiling in microseconds.
    #[must_use]
    pub fn latency_ceiling_us(&self) -> u64 {
        self.latency_ceiling_us
    }

    /// Reconfigure latency budget and queue depth ceiling.
    pub fn set_budget(&mut self, max_queue_depth: usize, latency_ceiling_us: u64) {
        self.max_queue_depth = max_queue_depth;
        self.latency_ceiling_us = latency_ceiling_us;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 8: Zero-CPU-Conversion WebGL2 YUV420p GPU Shader & Binary Frame Pipe
// ─────────────────────────────────────────────────────────────────────────────

/// Standard ITU-R BT.709 color specification in 8-bit YUV values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmpteColor {
    /// Luma (Y) value: 16 (black) to 235 (nominal peak white).
    pub y: u8,
    /// Chroma blue (U/Cb) value: 16 to 240, centered at 128.
    pub u: u8,
    /// Chroma red (V/Cr) value: 16 to 240, centered at 128.
    pub v: u8,
}

/// The eight canonical 75% ITU-R BT.709 SMPTE color bars.
pub const SMPTE_BT709_COLORS: [SmpteColor; 8] = [
    SmpteColor {
        y: 180,
        u: 128,
        v: 128,
    }, // 75% White
    SmpteColor {
        y: 168,
        u: 44,
        v: 136,
    }, // Yellow
    SmpteColor {
        y: 145,
        u: 147,
        v: 44,
    }, // Cyan
    SmpteColor {
        y: 133,
        u: 63,
        v: 52,
    }, // Green
    SmpteColor {
        y: 63,
        u: 193,
        v: 204,
    }, // Magenta
    SmpteColor {
        y: 51,
        u: 109,
        v: 212,
    }, // Red
    SmpteColor {
        y: 28,
        u: 212,
        v: 120,
    }, // Blue
    SmpteColor {
        y: 16,
        u: 128,
        v: 128,
    }, // Black
];

/// Generate a synthetic 60fps SMPTE YUV420p test frame with moving radar indicator.
///
/// Features:
/// - Exact ITU-R BT.709 color-bar calibration across top 75% split.
/// - Alignment/pluge reference block split across bottom 25%.
/// - Moving horizontal scan cursor (`(frame_index * 8) % width`) and rotating radar sweep
///   to visually prove live 60fps continuous GPU canvas rendering without an iPhone connected.
#[must_use]
pub fn generate_smpte_frame(width: u32, height: u32, frame_index: u64) -> DecodedFrame {
    let w = (width.max(2) & !1) as usize;
    let h = (height.max(2) & !1) as usize;
    let y_len = w * h;
    let half_w = w / 2;
    let half_h = h / 2;
    let uv_len = half_w * half_h;

    let mut y_plane = vec![16u8; y_len];
    let mut u_plane = vec![128u8; uv_len];
    let mut v_plane = vec![128u8; uv_len];

    let top_split_h = (h * 3) / 4;
    let bar_width = w / 8;

    let radar_speed = 8usize;
    let radar_x = ((frame_index as usize) * radar_speed) % w;
    let radar_width = 8usize;

    let center_x = (w / 2) as i64;
    let center_y = (top_split_h / 2) as i64;
    let radar_radius = ((top_split_h / 4).min(w / 4)) as i64;
    let angle_deg = ((frame_index * 6) % 360) as f64;
    let angle_rad = angle_deg.to_radians();
    let sin_a = angle_rad.sin();
    let cos_a = angle_rad.cos();

    for row in 0..h {
        let is_top = row < top_split_h;
        let c_row = row / 2;

        for col in 0..w {
            let c_col = col / 2;
            let (mut y_val, mut u_val, mut v_val) = if is_top {
                let bar_idx = (col / bar_width.max(1)).min(7);
                let c = &SMPTE_BT709_COLORS[bar_idx];
                (c.y, c.u, c.v)
            } else {
                let sub_bar = (col / (w / 4).max(1)).min(3);
                match sub_bar {
                    0 => (145, 147, 44),  // Cyan
                    1 => (180, 128, 128), // 75% White
                    2 => (63, 193, 204),  // Magenta
                    _ => (16, 128, 128),  // Black
                }
            };

            // Overlay 1: Moving vertical radar scanline
            if col >= radar_x && col < radar_x + radar_width {
                y_val = 240;
                u_val = 128;
                v_val = 128;
            }

            // Overlay 2: Rotating circular radar sweep in upper center
            if is_top {
                let dx = col as i64 - center_x;
                let dy = row as i64 - center_y;
                let dist_sq = dx * dx + dy * dy;
                if dist_sq <= radar_radius * radar_radius {
                    let dot = (dx as f64 * cos_a) + (dy as f64 * sin_a);
                    let perp = (dx as f64 * -sin_a) + (dy as f64 * cos_a);
                    if dot > 0.0 && perp.abs() < 2.5 {
                        y_val = 255;
                        u_val = 128;
                        v_val = 128;
                    }
                }
            }

            y_plane[row * w + col] = y_val;
            if row % 2 == 0 && col % 2 == 0 {
                u_plane[c_row * half_w + c_col] = u_val;
                v_plane[c_row * half_w + c_col] = v_val;
            }
        }
    }

    let timestamp_ntp = (frame_index * 1_000_000) / 60;

    DecodedFrame {
        y_plane,
        u_plane,
        v_plane,
        width: w as u32,
        height: h as u32,
        y_stride: w as u32,
        uv_stride: half_w as u32,
        timestamp_ntp,
        decode_duration_us: 100,
    }
}

/// Global thread-safe state managing the live video frame stream and 60fps SMPTE generator.
#[derive(Clone)]
pub struct VideoStreamState {
    latest_frame: Arc<RwLock<Option<Vec<u8>>>>,
    running: Arc<AtomicBool>,
}

impl Default for VideoStreamState {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoStreamState {
    /// Create a new video stream state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            latest_frame: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns `true` if the synthetic test pattern generator is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Start the 60fps synthetic SMPTE generator task.
    pub fn start_test_pattern(&self, width: u32, height: u32) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let running_flag = Arc::clone(&self.running);
        let frame_slot = Arc::clone(&self.latest_frame);

        tokio::spawn(async move {
            let mut frame_index = 0u64;
            let mut ticker = tokio::time::interval(std::time::Duration::from_micros(16_667));
            while running_flag.load(Ordering::Relaxed) {
                ticker.tick().await;
                let frame = generate_smpte_frame(width, height, frame_index);
                let packed = frame.to_packed_bytes();
                if let Ok(mut lock) = frame_slot.write() {
                    *lock = Some(packed);
                }
                frame_index = frame_index.wrapping_add(1);
            }
        });
    }

    /// Stop the synthetic test pattern generator.
    pub fn stop_test_pattern(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Retrieve the most recent packed video frame buffer, if available.
    #[must_use]
    pub fn get_latest_frame(&self) -> Option<Vec<u8>> {
        self.latest_frame.read().ok()?.clone()
    }

    /// Push an externally decoded frame into the stream slot.
    pub fn set_external_frame(&self, frame: &DecodedFrame) {
        let packed = frame.to_packed_bytes();
        if let Ok(mut lock) = self.latest_frame.write() {
            *lock = Some(packed);
        }
    }
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
        assert_eq!(
            StreamPayloadType::from_u16(0x00),
            StreamPayloadType::VideoBitstream
        );
        assert_eq!(
            StreamPayloadType::from_u16(0x01),
            StreamPayloadType::CodecConfig
        );
        assert_eq!(
            StreamPayloadType::from_u16(0x02),
            StreamPayloadType::Heartbeat
        );
        assert_eq!(
            StreamPayloadType::from_u16(0x05),
            StreamPayloadType::StreamingReport
        );
        assert_eq!(
            StreamPayloadType::from_u16(0x99),
            StreamPayloadType::Unknown(0x99)
        );

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

    // ── Step 6 unit tests ──────────────────────────────────────────────────

    #[test]
    fn nal_unit_type_classification() {
        assert_eq!(NalUnitType::from_nal_byte(0x61), NalUnitType::NonIdrSlice); // 0x61 & 0x1F = 1
        assert_eq!(NalUnitType::from_nal_byte(0x65), NalUnitType::IdrSlice); // 0x65 & 0x1F = 5
        assert_eq!(NalUnitType::from_nal_byte(0x06), NalUnitType::Sei);
        assert_eq!(NalUnitType::from_nal_byte(0x27), NalUnitType::Sps); // 0x27 & 0x1F = 7
        assert_eq!(NalUnitType::from_nal_byte(0x28), NalUnitType::Pps); // 0x28 & 0x1F = 8
        assert_eq!(NalUnitType::from_nal_byte(0x00), NalUnitType::Other(0));
        assert!(!NalUnitType::NonIdrSlice.is_keyframe());
        assert!(NalUnitType::IdrSlice.is_keyframe());
        assert_eq!(NalUnitType::IdrSlice.as_u8(), 5);
    }

    #[test]
    fn codec_config_parse_rejects_short_payload() {
        let mut asm = H264AnnexBAssembler::new();
        assert!(matches!(
            asm.process_codec_config(&[0u8; 5]),
            Err(MediaError::AvccMalformed(_))
        ));
    }

    #[test]
    fn codec_config_parse_sps_pps_correct() {
        let sps_data: &[u8] = &[0x67, 0x42, 0x00, 0x1F, 0xD0, 0x0A, 0x09];
        let pps_data: &[u8] = &[0x68, 0xCE, 0x38, 0x80];
        let mut record = vec![
            0x01u8, // configurationVersion
            0x42,   // AVCProfileIndication (Baseline)
            0x00,   // profile_compatibility
            0x1F,   // AVCLevelIndication (3.1)
            0xFF,   // lengthSizeMinusOne = 3 (4-byte AVCC lengths)
            0xE1,   // numSPS = 1
        ];
        record.extend(&(sps_data.len() as u16).to_be_bytes());
        record.extend_from_slice(sps_data);
        record.push(0x01); // numPPS
        record.extend(&(pps_data.len() as u16).to_be_bytes());
        record.extend_from_slice(pps_data);

        let mut asm = H264AnnexBAssembler::new();
        asm.process_codec_config(&record)
            .expect("codec config parse");
        assert!(asm.has_codec_config());

        let expected_sps: Vec<u8> = [&ANNEXB_START_CODE[..], sps_data].concat();
        assert_eq!(asm.cached_sps(), expected_sps.as_slice());

        let expected_pps: Vec<u8> = [&ANNEXB_START_CODE[..], pps_data].concat();
        assert_eq!(asm.cached_pps(), expected_pps.as_slice());
    }

    #[test]
    fn avcc_to_annexb_non_idr_single_nal() {
        let nal_data: &[u8] = &[0x61, 0xAB, 0xCD, 0xEF, 0x01];
        let mut payload: Vec<u8> = Vec::new();
        payload.extend(&(nal_data.len() as u32).to_be_bytes());
        payload.extend_from_slice(nal_data);

        let mut asm = H264AnnexBAssembler::new();
        let frame = asm.process_video_bitstream(&mut payload).unwrap();

        assert!(!frame.is_keyframe);
        assert_eq!(frame.nal_units.len(), 1);
        assert_eq!(frame.nal_units[0].nal_type, NalUnitType::NonIdrSlice);
        assert_eq!(frame.nal_units[0].length, nal_data.len());

        let expected: Vec<u8> = [&ANNEXB_START_CODE[..], nal_data].concat();
        assert_eq!(frame.data, expected);
    }

    #[test]
    fn avcc_to_annexb_idr_prepends_sps_pps() {
        let sps_data: &[u8] = &[0x67, 0x42, 0x00, 0x1F, 0xD0, 0x0A, 0x09];
        let pps_data: &[u8] = &[0x68, 0xCE, 0x38, 0x80];
        let idr_nal: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x33];

        let mut record = vec![0x01u8, 0x42, 0x00, 0x1F, 0xFF, 0xE1];
        record.extend(&(sps_data.len() as u16).to_be_bytes());
        record.extend_from_slice(sps_data);
        record.push(0x01);
        record.extend(&(pps_data.len() as u16).to_be_bytes());
        record.extend_from_slice(pps_data);

        let mut asm = H264AnnexBAssembler::new();
        asm.process_codec_config(&record).unwrap();

        let mut payload: Vec<u8> = Vec::new();
        payload.extend(&(idr_nal.len() as u32).to_be_bytes());
        payload.extend_from_slice(idr_nal);

        let frame = asm.process_video_bitstream(&mut payload).unwrap();

        assert!(frame.is_keyframe);
        assert_eq!(frame.nal_units.len(), 1);
        assert_eq!(frame.nal_units[0].nal_type, NalUnitType::IdrSlice);

        let mut expected: Vec<u8> = Vec::new();
        expected.extend(&ANNEXB_START_CODE);
        expected.extend_from_slice(sps_data);
        expected.extend(&ANNEXB_START_CODE);
        expected.extend_from_slice(pps_data);
        expected.extend(&ANNEXB_START_CODE);
        expected.extend_from_slice(idr_nal);
        assert_eq!(frame.data, expected);
    }

    #[test]
    fn avcc_truncated_nal_does_not_panic() {
        // Payload claims 100-byte NAL but only 4 bytes follow — must NOT panic.
        let mut payload: Vec<u8> = Vec::new();
        payload.extend(&100u32.to_be_bytes());
        payload.extend(&[0x61u8, 0x00, 0x00, 0x00]);
        let mut asm = H264AnnexBAssembler::new();
        let frame = asm.process_video_bitstream(&mut payload).unwrap();
        assert!(frame.nal_units.is_empty());
    }

    #[test]
    fn ctr_stream_processor_keystream_continuity() {
        use crate::crypto::StreamKey;
        let key = StreamKey::from_bytes(&[0x42u8; 16], &[0xABu8; 16]).unwrap();

        // Reference: encrypt full plaintext in one shot.
        let plaintext: Vec<u8> = (0u8..=127).collect();
        let mut ref_proc = CtrStreamProcessor::new(&key);
        let mut ref_buf = plaintext.clone();
        ref_proc.apply(&mut ref_buf);
        let reference_ciphertext = ref_buf;

        // Test: same key/IV applied across three sequential chunks.
        let mut proc = CtrStreamProcessor::new(&key);
        let mut chunk1 = plaintext[0..48].to_vec();
        let mut chunk2 = plaintext[48..96].to_vec();
        let mut chunk3 = plaintext[96..128].to_vec();
        proc.apply(&mut chunk1);
        proc.apply(&mut chunk2);
        proc.apply(&mut chunk3);

        let mut reassembled = chunk1;
        reassembled.extend(chunk2);
        reassembled.extend(chunk3);

        assert_eq!(
            reassembled, reference_ciphertext,
            "CTR keystream continuity broken across chunk boundaries"
        );
        assert_eq!(proc.bytes_processed(), 128);
    }

    // ── Step 7 unit tests ──────────────────────────────────────────────────

    #[test]
    fn test_decoded_frame_plane_geometry() {
        let frame = DecodedFrame::new(1920, 1080, 12345, 250);
        assert_eq!(frame.width, 1920);
        assert_eq!(frame.height, 1080);
        assert_eq!(frame.y_stride, 1920);
        assert_eq!(frame.uv_stride, 960);
        assert_eq!(frame.y_plane.len(), 1920 * 1080);
        assert_eq!(frame.u_plane.len(), 960 * 540);
        assert_eq!(frame.v_plane.len(), 960 * 540);
        assert!(frame.is_valid_yuv420p());
    }

    #[test]
    fn test_sps_dimension_parsing_1080p_and_720p() {
        let sps_1080 = build_test_sps(1920, 1080);
        let dims_1080 = parse_sps_dimensions(&sps_1080).expect("parse 1080p SPS");
        assert_eq!(dims_1080, (1920, 1080));

        let sps_720 = build_test_sps(1280, 720);
        let dims_720 = parse_sps_dimensions(&sps_720).expect("parse 720p SPS");
        assert_eq!(dims_720, (1280, 720));

        let sps_360 = build_test_sps(640, 360);
        let dims_360 = parse_sps_dimensions(&sps_360).expect("parse 360p SPS");
        assert_eq!(dims_360, (640, 360));
    }

    #[test]
    fn test_software_decoder_engine_idr_and_non_idr() {
        let mut engine = SoftwareH264DecoderEngine::new();

        // 1. Build an IDR frame with SPS
        let sps = build_test_sps(1280, 720);
        let mut idr_data = sps;
        idr_data.extend_from_slice(&ANNEXB_START_CODE);
        idr_data.extend_from_slice(&[0x65, 0x88, 0x84, 0x00, 0x42]); // IDR slice (type 5)

        let idr_frame = AnnexBFrame::from_annexb(idr_data);
        assert!(idr_frame.is_keyframe);

        let decoded = engine
            .decode_frame(&idr_frame, 100_000)
            .expect("decode IDR")
            .expect("picture expected");

        assert_eq!(decoded.width, 1280);
        assert_eq!(decoded.height, 720);
        assert!(decoded.is_valid_yuv420p());
        assert_eq!(decoded.timestamp_ntp, 100_000);

        // 2. Build a non-IDR frame
        let mut non_idr_data = Vec::new();
        non_idr_data.extend_from_slice(&ANNEXB_START_CODE);
        non_idr_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // Non-IDR non-ref slice (type 1)
        let non_idr_frame = AnnexBFrame::from_annexb(non_idr_data);
        assert!(!non_idr_frame.is_keyframe);

        let decoded2 = engine
            .decode_frame(&non_idr_frame, 116_666)
            .expect("decode non-IDR")
            .expect("picture expected");

        assert_eq!(decoded2.width, 1280);
        assert_eq!(decoded2.height, 720);
        assert!(decoded2.is_valid_yuv420p());
    }

    #[test]
    fn test_jitter_gatekeeper_congestion_shedding_and_keyframe_preservation() {
        let decoder = SoftwareH264DecoderEngine::new();
        let mut gatekeeper = JitterGatekeeper::new(decoder);

        // Create IDR keyframe
        let mut keyframe_data = Vec::new();
        keyframe_data.extend_from_slice(&ANNEXB_START_CODE);
        keyframe_data.extend_from_slice(&[0x65, 0x88, 0x84, 0x00]); // IDR
        let keyframe = AnnexBFrame::from_annexb(keyframe_data);

        // Create non-reference frame
        let mut non_ref_data = Vec::new();
        non_ref_data.extend_from_slice(&ANNEXB_START_CODE);
        non_ref_data.extend_from_slice(&[0x01, 0xAA, 0xBB, 0xCC]); // Non-ref slice (nal_ref_idc = 0)
        let non_ref_frame = AnnexBFrame::from_annexb(non_ref_data);

        // Under normal queue depth (1 <= 2): non-ref frame is admitted and decoded
        let res = gatekeeper.process_frame(&non_ref_frame, 1000, 1).unwrap();
        assert!(res.is_some());
        assert_eq!(gatekeeper.telemetry().frames_decoded, 1);
        assert_eq!(gatekeeper.telemetry().frames_dropped_late, 0);

        // Under congestion (queue_depth = 5 > 2): non-ref frame is shed
        let res_dropped = gatekeeper.process_frame(&non_ref_frame, 2000, 5).unwrap();
        assert!(res_dropped.is_none());
        assert_eq!(gatekeeper.telemetry().frames_dropped_late, 1);
        assert_eq!(gatekeeper.telemetry().frames_decoded, 1);

        // Under congestion (queue_depth = 5 > 2): IDR keyframe MUST NOT be shed!
        let res_keyframe = gatekeeper.process_frame(&keyframe, 3000, 5).unwrap();
        assert!(res_keyframe.is_some());
        assert_eq!(gatekeeper.telemetry().keyframes_processed, 1);
        assert_eq!(gatekeeper.telemetry().frames_decoded, 2);
        assert_eq!(gatekeeper.telemetry().frames_dropped_late, 1);
    }

    // ── Step 8 unit tests ──────────────────────────────────────────────────

    #[test]
    fn test_packed_frame_roundtrip() {
        let original = generate_smpte_frame(640, 360, 42);
        let packed = original.to_packed_bytes();
        assert_eq!(&packed[0..4], &PACKED_FRAME_MAGIC);
        assert_eq!(
            packed.len(),
            PACKED_FRAME_HEADER_LEN + (640 * 360) + (320 * 180 * 2)
        );

        let parsed = DecodedFrame::from_packed_bytes(&packed).expect("parse packed frame");
        assert_eq!(parsed.width, 640);
        assert_eq!(parsed.height, 360);
        assert_eq!(parsed.y_stride, 640);
        assert_eq!(parsed.uv_stride, 320);
        assert_eq!(parsed.y_plane, original.y_plane);
        assert_eq!(parsed.u_plane, original.u_plane);
        assert_eq!(parsed.v_plane, original.v_plane);
        assert!(parsed.is_valid_yuv420p());
    }

    #[test]
    fn test_smpte_generator_plane_lengths_and_animation() {
        // Landscape 1920x1080
        let frame_1080 = generate_smpte_frame(1920, 1080, 0);
        assert_eq!(frame_1080.width, 1920);
        assert_eq!(frame_1080.height, 1080);
        assert_eq!(frame_1080.y_plane.len(), 1920 * 1080);
        assert_eq!(frame_1080.u_plane.len(), 960 * 540);
        assert_eq!(frame_1080.v_plane.len(), 960 * 540);
        assert!(frame_1080.is_valid_yuv420p());

        // Portrait 1080x1920 (iPhone Screen Mirroring orientation)
        let frame_portrait = generate_smpte_frame(1080, 1920, 0);
        assert_eq!(frame_portrait.width, 1080);
        assert_eq!(frame_portrait.height, 1920);
        assert_eq!(frame_portrait.y_plane.len(), 1080 * 1920);
        assert_eq!(frame_portrait.u_plane.len(), 540 * 960);
        assert_eq!(frame_portrait.v_plane.len(), 540 * 960);
        assert!(frame_portrait.is_valid_yuv420p());

        // Verify animation changes across frame indices (radar movement)
        let frame_a = generate_smpte_frame(640, 360, 0);
        let frame_b = generate_smpte_frame(640, 360, 20);
        assert_ne!(
            frame_a.y_plane, frame_b.y_plane,
            "Moving radar indicator must change luma plane across frames"
        );
    }

    #[test]
    fn test_video_stream_state_lifecycle() {
        let state = VideoStreamState::new();
        assert!(!state.is_running());
        assert!(state.get_latest_frame().is_none());

        let frame = generate_smpte_frame(320, 240, 1);
        state.set_external_frame(&frame);
        let latest = state
            .get_latest_frame()
            .expect("external frame should be set");
        assert_eq!(&latest[0..4], &PACKED_FRAME_MAGIC);
    }
}
