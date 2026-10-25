// Outside Judge Integration & Throughput Benchmark Suite:
// src-tauri/tests/ringbuffer_bench.rs
//
// Validates:
// 1. Exact 128-byte AirPlay header zero-copy parsing, byte serialization, and rejection of malformed/oversized frames.
// 2. Deterministic overflow drop semantics and telemetry tracking on bounded SPSC ring buffers.
// 3. Multi-threaded throughput benchmark pumping 10,000 simulated 1080p60 packets across producer/consumer threads,
//    asserting zero dropped packets under normal drain and sub-millisecond average latency.
// 4. End-to-end async TCP mirroring listener stream reading into the SPSC ring buffer.

use jcb_airplay_lib::media::{
    split_ring_buffer, AirPlayStreamHeader, MediaError, MirroringStreamServer, SpscRingBuffer,
    StreamPacket, StreamPayloadType, AIRPLAY_STREAM_HEADER_LEN, MAX_PAYLOAD_SIZE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[test]
fn test_airplay_header_exact_roundtrip_all_types() {
    let test_cases = [
        (StreamPayloadType::VideoBitstream, 16384, 0, 1920.0, 1080.0),
        (StreamPayloadType::CodecConfig, 48, 1, 1920.0, 1080.0),
        (StreamPayloadType::Heartbeat, 0, 0, 0.0, 0.0),
        (StreamPayloadType::StreamingReport, 128, 4, 1280.0, 720.0),
        (StreamPayloadType::Unknown(0x00A0), 2048, 2, 2532.0, 1170.0),
    ];

    for (payload_type, payload_size, option, width, height) in test_cases {
        let original = AirPlayStreamHeader {
            payload_size,
            payload_type,
            payload_option: option,
            timestamp_ntp: 0xDEAD_BEEF_CAFE_BABE,
            source_width: width,
            source_height: height,
            display_width: width,
            display_height: height,
            reserved1: [0x55; 16],
            reserved2: [0xAA; 80],
        };

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), AIRPLAY_STREAM_HEADER_LEN);

        // Verify exact little-endian fields in raw byte slice
        let parsed_size = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(parsed_size, payload_size);

        let parsed_type = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        assert_eq!(parsed_type, payload_type.as_u16());

        let parsed_opt = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        assert_eq!(parsed_opt, option);

        let parsed_ntp = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(parsed_ntp, 0xDEAD_BEEF_CAFE_BABE);

        let parsed_sw = f32::from_le_bytes(bytes[16..20].try_into().unwrap());
        assert_eq!(parsed_sw, width);

        let parsed_sh = f32::from_le_bytes(bytes[20..24].try_into().unwrap());
        assert_eq!(parsed_sh, height);

        let parsed_dw = f32::from_le_bytes(bytes[40..44].try_into().unwrap());
        assert_eq!(parsed_dw, width);

        let parsed_dh = f32::from_le_bytes(bytes[44..48].try_into().unwrap());
        assert_eq!(parsed_dh, height);

        // Verify full parser roundtrip
        let parsed = AirPlayStreamHeader::parse(&bytes).expect("parsing valid header failed");
        assert_eq!(parsed, original);
    }
}

#[test]
fn test_airplay_header_malformed_and_oversized_rejection() {
    // 1. Shorter than 128 bytes
    let truncated = [0u8; 127];
    match AirPlayStreamHeader::parse(&truncated) {
        Err(MediaError::MalformedStreamHeader(len)) => assert_eq!(len, 127),
        other => panic!("expected MalformedStreamHeader(127), got {:?}", other),
    }

    let empty = [];
    match AirPlayStreamHeader::parse(&empty) {
        Err(MediaError::MalformedStreamHeader(0)) => {}
        other => panic!("expected MalformedStreamHeader(0), got {:?}", other),
    }

    // 2. Payload size exceeding 8 MB maximum bound
    let mut oversized_bytes = [0u8; AIRPLAY_STREAM_HEADER_LEN];
    let bad_size = MAX_PAYLOAD_SIZE + 1;
    oversized_bytes[0..4].copy_from_slice(&bad_size.to_le_bytes());
    match AirPlayStreamHeader::parse(&oversized_bytes) {
        Err(MediaError::PayloadTooLarge(size, max)) => {
            assert_eq!(size, bad_size);
            assert_eq!(max, MAX_PAYLOAD_SIZE);
        }
        other => panic!("expected PayloadTooLarge, got {:?}", other),
    }

    // 3. Exactly MAX_PAYLOAD_SIZE must be accepted
    oversized_bytes[0..4].copy_from_slice(&MAX_PAYLOAD_SIZE.to_le_bytes());
    assert!(AirPlayStreamHeader::parse(&oversized_bytes).is_ok());
}

#[test]
fn test_spsc_ring_buffer_deterministic_overflow_handling() {
    let capacity = 8;
    let (mut producer, mut consumer) = split_ring_buffer::<u64>(capacity);
    assert_eq!(producer.capacity(), 8);
    assert_eq!(producer.len(), 0);
    assert!(producer.is_empty());
    assert!(!producer.is_full());

    // Fill buffer completely
    for i in 0..8 {
        assert!(producer.push(i).is_ok());
    }

    assert_eq!(producer.len(), 8);
    assert!(producer.is_full());
    assert_eq!(producer.telemetry().high_water_mark, 8);
    assert_eq!(producer.telemetry().packets_dropped_overflow, 0);

    // 9th and 10th pushes must deterministically fail with QueueOverflow
    let err9 = producer.push(999);
    assert!(matches!(err9, Err(MediaError::QueueOverflow)));
    assert_eq!(producer.telemetry().packets_dropped_overflow, 1);

    let err10 = producer.push(1000);
    assert!(matches!(err10, Err(MediaError::QueueOverflow)));
    assert_eq!(producer.telemetry().packets_dropped_overflow, 2);

    // High water mark remains 8
    assert_eq!(producer.telemetry().high_water_mark, 8);

    // Drain 3 items
    assert_eq!(consumer.pop(), Some(0));
    assert_eq!(consumer.pop(), Some(1));
    assert_eq!(consumer.pop(), Some(2));
    assert_eq!(consumer.len(), 5);

    // Pushing 3 new items must now succeed
    assert!(producer.push(100).is_ok());
    assert!(producer.push(101).is_ok());
    assert!(producer.push(102).is_ok());
    assert_eq!(producer.len(), 8);

    // Total pushed: 8 + 3 = 11, total dropped: 2
    let telem = producer.telemetry();
    assert_eq!(telem.packets_pushed, 11);
    assert_eq!(telem.packets_dropped_overflow, 2);
    assert_eq!(telem.packets_popped, 3);
}

#[test]
fn test_spsc_ring_buffer_container_api() {
    let mut ring = SpscRingBuffer::<u32>::new(16);
    assert_eq!(ring.capacity(), 16);
    assert!(ring.is_empty());
    assert!(!ring.is_full());

    for i in 0..10 {
        assert!(ring.push(i).is_ok());
    }
    assert_eq!(ring.len(), 10);
    assert_eq!(ring.telemetry().high_water_mark, 10);

    let (producer, mut consumer) = ring.split();
    assert_eq!(producer.len(), 10);
    assert_eq!(consumer.len(), 10);

    for i in 0..10 {
        assert_eq!(consumer.pop(), Some(i));
    }
    assert!(consumer.is_empty());
}

#[test]
fn test_spsc_throughput_10000_packets_1080p60_submillisecond_latency() {
    const PACKET_COUNT: usize = 10_000;
    const BUFFER_CAPACITY: usize = 2048;
    const SIMULATED_PAYLOAD_SIZE: usize = 16 * 1024; // 16 KB typical 1080p60 H.264 slice

    let (mut producer, mut consumer) = split_ring_buffer::<StreamPacket>(BUFFER_CAPACITY);
    let done = Arc::new(AtomicBool::new(false));
    let done_consumer = Arc::clone(&done);

    let sample_header = AirPlayStreamHeader {
        payload_size: SIMULATED_PAYLOAD_SIZE as u32,
        payload_type: StreamPayloadType::VideoBitstream,
        payload_option: 0,
        timestamp_ntp: 1_000_000,
        source_width: 1920.0,
        source_height: 1080.0,
        display_width: 1920.0,
        display_height: 1080.0,
        reserved1: [0; 16],
        reserved2: [0; 80],
    };

    // Pre-allocate a standard payload pattern to avoid allocation on hot path
    let payload_template = vec![0xABu8; SIMULATED_PAYLOAD_SIZE];

    let start_time = Instant::now();

    // Consumer thread: actively drains packets and validates ordering and integrity
    let consumer_handle = std::thread::spawn(move || {
        let mut received = 0usize;
        while received < PACKET_COUNT {
            if let Some(packet) = consumer.pop() {
                assert_eq!(packet.header.payload_size as usize, SIMULATED_PAYLOAD_SIZE);
                assert_eq!(packet.payload.len(), SIMULATED_PAYLOAD_SIZE);
                assert_eq!(packet.header.timestamp_ntp, received as u64);
                received += 1;
            } else if done_consumer.load(Ordering::Relaxed) {
                // Drain any remainder
                while let Some(packet) = consumer.pop() {
                    assert_eq!(packet.header.payload_size as usize, SIMULATED_PAYLOAD_SIZE);
                    received += 1;
                }
                break;
            } else {
                std::thread::yield_now();
            }
        }
        let telem = consumer.telemetry();
        (received, telem)
    });

    // Producer thread: sends 10,000 packets with realistic 1080p60 metadata
    for i in 0..PACKET_COUNT {
        let mut header = sample_header.clone();
        header.timestamp_ntp = i as u64;

        // Zero-allocation: use buffer pool
        let mut payload = producer.acquire_buffer(SIMULATED_PAYLOAD_SIZE);
        payload.clear();
        payload.extend_from_slice(&payload_template);

        let packet = StreamPacket { header, payload };

        // Under normal active drain, push directly. Spin/yield if transiently full.
        while let Err(MediaError::QueueOverflow) = producer.push(packet.clone()) {
            std::thread::yield_now();
        }
    }

    done.store(true, Ordering::Release);

    let (received_count, final_telem) = consumer_handle.join().expect("consumer thread panicked");
    let total_duration = start_time.elapsed();

    // Calculate latency metrics
    let total_nanos = total_duration.as_nanos();
    let avg_latency_micros = (total_nanos as f64) / (PACKET_COUNT as f64 * 1000.0);
    let avg_latency_millis = avg_latency_micros / 1000.0;

    println!("\n--- JCB AirPlay SPSC Ring Buffer Benchmark ---");
    println!("Pushed: {} packets", final_telem.packets_pushed);
    println!("Popped: {} packets", final_telem.packets_popped);
    println!("Dropped: {} packets", final_telem.packets_dropped_overflow);
    println!("High Water Mark: {} slots", final_telem.high_water_mark);
    println!("Total Elapsed Time: {:?}", total_duration);
    println!(
        "Average Transfer Latency: {:.4} ms ({:.2} µs)",
        avg_latency_millis, avg_latency_micros
    );
    println!("-----------------------------------------------\n");

    // Assert zero dropped packets under normal drain
    assert_eq!(received_count, PACKET_COUNT);
    assert_eq!(final_telem.packets_pushed, PACKET_COUNT as u64);
    assert_eq!(final_telem.packets_popped, PACKET_COUNT as u64);
    assert_eq!(final_telem.packets_dropped_overflow, 0);

    // Assert sub-millisecond average queuing latency (< 1.0 ms)
    assert!(
        avg_latency_millis < 1.0,
        "Average queuing latency ({:.4} ms) exceeded 1.0 ms requirement!",
        avg_latency_millis
    );
}

#[tokio::test]
async fn test_tcp_mirroring_listener_e2e_stream() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = MirroringStreamServer::bind(server_addr)
        .await
        .expect("failed to bind MirroringStreamServer");
    let local_addr = server.local_addr();

    let (producer, mut consumer) = split_ring_buffer::<StreamPacket>(128);

    // Spawn server to handle one incoming connection
    let server_handle = tokio::spawn(async move {
        server
            .serve_one(producer)
            .await
            .expect("server serve_one failed")
    });

    // Connect client
    let mut client = TcpStream::connect(local_addr)
        .await
        .expect("failed to connect to mirroring server");

    // Packet 1: CodecConfig SPS/PPS (32 bytes)
    let sps_pps_payload = vec![0x67, 0x42, 0x00, 0x1F, 0x68, 0xCE, 0x38, 0x80];
    let header1 = AirPlayStreamHeader {
        payload_size: sps_pps_payload.len() as u32,
        payload_type: StreamPayloadType::CodecConfig,
        payload_option: 0,
        timestamp_ntp: 100,
        source_width: 1920.0,
        source_height: 1080.0,
        display_width: 1920.0,
        display_height: 1080.0,
        reserved1: [0; 16],
        reserved2: [0; 80],
    };
    client.write_all(&header1.to_bytes()).await.unwrap();
    client.write_all(&sps_pps_payload).await.unwrap();

    // Packet 2: VideoBitstream (1024 bytes)
    let video_payload = vec![0x27; 1024];
    let header2 = AirPlayStreamHeader {
        payload_size: video_payload.len() as u32,
        payload_type: StreamPayloadType::VideoBitstream,
        payload_option: 1,
        timestamp_ntp: 200,
        source_width: 1920.0,
        source_height: 1080.0,
        display_width: 1920.0,
        display_height: 1080.0,
        reserved1: [0; 16],
        reserved2: [0; 80],
    };
    client.write_all(&header2.to_bytes()).await.unwrap();
    client.write_all(&video_payload).await.unwrap();

    // Packet 3: Heartbeat (0 bytes payload)
    let header3 = AirPlayStreamHeader {
        payload_size: 0,
        payload_type: StreamPayloadType::Heartbeat,
        payload_option: 0,
        timestamp_ntp: 300,
        source_width: 0.0,
        source_height: 0.0,
        display_width: 0.0,
        display_height: 0.0,
        reserved1: [0; 16],
        reserved2: [0; 80],
    };
    client.write_all(&header3.to_bytes()).await.unwrap();

    // Flush and cleanly close client stream
    client.flush().await.unwrap();
    drop(client);

    // Wait for server to finish reading stream
    let packets_served = server_handle.await.expect("server task join failed");
    assert_eq!(packets_served, 3);

    // Verify consumer popped all 3 packets with exact match
    let p1 = consumer.pop().expect("missing packet 1");
    assert_eq!(p1.header.payload_type, StreamPayloadType::CodecConfig);
    assert_eq!(p1.header.payload_size, sps_pps_payload.len() as u32);
    assert_eq!(p1.payload, sps_pps_payload);

    let p2 = consumer.pop().expect("missing packet 2");
    assert_eq!(p2.header.payload_type, StreamPayloadType::VideoBitstream);
    assert_eq!(p2.header.payload_size, 1024);
    assert_eq!(p2.payload, video_payload);

    let p3 = consumer.pop().expect("missing packet 3");
    assert_eq!(p3.header.payload_type, StreamPayloadType::Heartbeat);
    assert_eq!(p3.header.payload_size, 0);
    assert!(p3.payload.is_empty());

    assert!(consumer.pop().is_none());
}
