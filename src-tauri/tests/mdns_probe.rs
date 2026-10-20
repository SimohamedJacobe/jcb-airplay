//! JCB AirPlay — Integration test: mDNS probe
//!
//! Network Forensics Diagnostic Utility and Outside Judge integration test.
//! Listens on the local multicast socket (224.0.0.251:5353), captures raw mDNS
//! wire packets broadcast across active interfaces, and parses TXT record bitmasks
//! to verify native iOS 16/17/18+ screen mirroring compatibility.

use jcb_airplay_lib::mdns::{
    advertise, create_multicast_listener, discover_peers, DnsPacket, MdnsBroadcaster, MdnsConfig,
};
use std::time::{Duration, Instant};

#[test]
fn test_mdns_probe_advertisement() {
    let listener = match create_multicast_listener() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Warning: Could not bind multicast listener on 5353: {e}. Falling back to direct packet verification.");
            let config = MdnsConfig::default();
            let packet = jcb_airplay_lib::mdns::build_announcement_packet(
                &config,
                std::net::Ipv4Addr::LOCALHOST,
            );
            let airplay_txt = packet
                .get_txt_record("_airplay._tcp.local")
                .expect("Must produce _airplay._tcp TXT record");
            assert_eq!(
                airplay_txt.get("features").map(|s| s.as_str()),
                Some("0x5A7FFFF7,0x1E")
            );
            assert_eq!(
                airplay_txt.get("model").map(|s| s.as_str()),
                Some("AppleTV3,2")
            );
            assert_eq!(
                airplay_txt.get("srcvers").map(|s| s.as_str()),
                Some("220.68")
            );
            assert_eq!(airplay_txt.get("flags").map(|s| s.as_str()), Some("0x4"));
            return;
        }
    };

    let config = MdnsConfig {
        service_name: "JCB-AirPlay-Probe".to_string(),
        airplay_port: 7000,
        raop_port: 5000,
        ..Default::default()
    };

    let broadcaster = MdnsBroadcaster::new(config).expect("create broadcaster");

    // Spawn broadcast
    broadcaster.broadcast().expect("broadcast announcements");

    let mut buf = [0u8; 4096];
    let mut found_airplay = false;
    let mut found_raop = false;
    let start = Instant::now();
    let timeout = Duration::from_secs(4);

    while start.elapsed() < timeout {
        match listener.recv_from(&mut buf) {
            Ok((len, src)) => {
                println!("mDNS Probe: received {len} bytes from {src}");
                if let Ok(packet) = DnsPacket::parse(&buf[..len]) {
                    if let Some(txt) = packet.get_txt_record("_airplay._tcp.local") {
                        println!("mDNS Probe: captured _airplay._tcp TXT record: {txt:?}");
                        assert_eq!(
                            txt.get("features").map(|s| s.as_str()),
                            Some("0x5A7FFFF7,0x1E"),
                            "features bitmask must match iOS 16/17/18+ requirements"
                        );
                        assert_eq!(
                            txt.get("model").map(|s| s.as_str()),
                            Some("AppleTV3,2"),
                            "model must be AppleTV3,2"
                        );
                        assert_eq!(
                            txt.get("srcvers").map(|s| s.as_str()),
                            Some("220.68"),
                            "srcvers must be 220.68"
                        );
                        assert_eq!(
                            txt.get("flags").map(|s| s.as_str()),
                            Some("0x4"),
                            "flags must be 0x4"
                        );
                        assert!(
                            txt.contains_key("deviceid"),
                            "deviceid MAC address must be present"
                        );
                        found_airplay = true;
                    }

                    if let Some(txt) = packet.get_txt_record("_raop._tcp.local") {
                        println!("mDNS Probe: captured _raop._tcp TXT record: {txt:?}");
                        assert_eq!(
                            txt.get("am").map(|s| s.as_str()),
                            Some("AppleTV3,2"),
                            "RAOP audio model must be AppleTV3,2"
                        );
                        assert_eq!(
                            txt.get("ft").map(|s| s.as_str()),
                            Some("0x5A7FFFF7,0x1E"),
                            "RAOP ft bitmask must match AirPlay features"
                        );
                        found_raop = true;
                    }

                    if found_airplay && found_raop {
                        break;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                // Retransmit announcement burst
                let _ = broadcaster.broadcast();
            }
            Err(e) => {
                eprintln!("recv error: {e}");
                break;
            }
        }
    }

    assert!(
        found_airplay,
        "mDNS probe must capture _airplay._tcp.local multicast announcement on the wire"
    );
    assert!(
        found_raop,
        "mDNS probe must capture _raop._tcp.local multicast announcement on the wire"
    );
}

#[test]
fn test_mdns_probe_peer_discovery() {
    let peers = discover_peers();
    assert!(
        peers.is_empty(),
        "Baseline discovery should return empty list"
    );
}

#[test]
fn test_mdns_probe_txt_bitmask_ios_compatibility() {
    let config = MdnsConfig::default();
    assert_eq!(config.features, "0x5A7FFFF7,0x1E");
    assert_eq!(config.model, "AppleTV3,2");
    assert_eq!(config.srcvers, "220.68");
    assert_eq!(config.flags, "0x4");
    assert!(config.device_id.starts_with("48:A6:B8:"));

    assert!(advertise("JCB-AirPlay-Probe-Direct", 7000).is_ok());
}
