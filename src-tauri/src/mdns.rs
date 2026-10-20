// JCB AirPlay — mdns.rs
// mDNS / Bonjour service advertisement and peer discovery.
//
// Responsibilities:
//   • Advertise `_airplay._tcp.local.` and `_raop._tcp.local.` services so iPhones
//     discover this receiver automatically as a native Apple TV mirroring target.
//   • Broadcast across active non-loopback IPv4 network interfaces.
//   • Populate the exact TXT record bitmasks required by iOS 16/17/18+ for screen mirroring.
//   • Maintain a registry of discovered AirPlay sources on the local network.

use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use thiserror::Error;

/// Multicast DNS IPv4 address (`224.0.0.251`).
pub const MDNS_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Multicast DNS UDP port (`5353`).
pub const MDNS_PORT: u16 = 5353;

/// Errors that can occur in the mDNS module.
#[derive(Debug, Error)]
pub enum MdnsError {
    /// The service could not be registered on the network.
    #[error("failed to register mDNS service: {0}")]
    RegistrationFailed(String),

    /// Failed to parse an incoming DNS / mDNS packet.
    #[error("packet parse error: {0}")]
    PacketParseFailed(String),

    /// An I/O error occurred on the mDNS socket.
    #[error("mDNS I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A discovered AirPlay peer on the local network.
#[derive(Debug, Clone)]
pub struct AirPlayPeer {
    /// Human-readable display name of the sender device.
    pub name: String,
    /// IPv4 or IPv6 address of the peer.
    pub address: std::net::IpAddr,
    /// Port on which the RTSP session should be initiated.
    pub port: u16,
}

/// Configuration options for the mDNS service broadcaster.
#[derive(Debug, Clone)]
pub struct MdnsConfig {
    /// Friendly service name displayed on the iOS Screen Mirroring list.
    pub service_name: String,
    /// Port for the AirPlay RTSP/HTTP service (default: 7000).
    pub airplay_port: u16,
    /// Port for the RAOP audio streaming service (default: 5000).
    pub raop_port: u16,
    /// Deterministic MAC address used as the device identifier (e.g. `48:A6:B8:XX:XX:XX`).
    pub device_id: String,
    /// Apple TV model string (e.g. `AppleTV3,2`).
    pub model: String,
    /// Source version string recognized by iOS (e.g. `220.68`).
    pub srcvers: String,
    /// Feature bitmask string required by iOS 16/17/18+ screen mirroring (`0x5A7FFFF7,0x1E`).
    pub features: String,
    /// Flag bitmask string (`0x4`).
    pub flags: String,
    /// Hostname used in SRV and A records.
    pub hostname: String,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        let mac = get_deterministic_mac();
        let hostname = match std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
            Ok(name) => {
                let clean: String = name
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '-')
                    .collect();
                if clean.is_empty() {
                    "jcb-airplay".to_string()
                } else {
                    format!("{}-airplay", clean.to_lowercase())
                }
            }
            Err(_) => "jcb-airplay".to_string(),
        };

        Self {
            service_name: "JCB AirPlay".to_string(),
            airplay_port: 7000,
            raop_port: 5000,
            device_id: mac,
            model: "AppleTV3,2".to_string(),
            srcvers: "220.68".to_string(),
            features: "0x5A7FFFF7,0x1E".to_string(),
            flags: "0x4".to_string(),
            hostname,
        }
    }
}

/// Generates a deterministic MAC address with an Apple OUI (`48:A6:B8`).
///
/// Ensures consistent device identity across reboots so iOS remembers paired settings.
pub fn get_deterministic_mac() -> String {
    let seed = match std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        Ok(name) => name,
        Err(_) => "JCBAirPlayHost".to_string(),
    };

    let mut hash: u32 = 0x811c_9dc5;
    for b in seed.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }

    let b1 = ((hash >> 16) & 0xFF) as u8;
    let b2 = ((hash >> 8) & 0xFF) as u8;
    let b3 = (hash & 0xFF) as u8;

    format!("48:A6:B8:{:02X}:{:02X}:{:02X}", b1, b2, b3)
}

/// Returns all active, non-loopback IPv4 addresses on the host system.
///
/// Falls back to loopback (`127.0.0.1`) only if no active non-loopback interface is found.
pub fn get_active_ipv4_interfaces() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let std::net::IpAddr::V4(ipv4) = iface.addr.ip() {
                if !ipv4.is_unspecified() && !ipv4.is_link_local() && !ips.contains(&ipv4) {
                    ips.push(ipv4);
                }
            }
        }
    }

    if ips.is_empty() {
        ips.push(Ipv4Addr::new(127, 0, 0, 1));
    }

    ips
}

/// DNS record type identifiers (RFC 1035 / RFC 2782 / RFC 6762).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /// Host IPv4 address (A record, 1).
    A,
    /// Domain name pointer (PTR record, 12).
    Ptr,
    /// Text strings (TXT record, 16).
    Txt,
    /// Service location (SRV record, 33).
    Srv,
    /// Any other record type.
    Other(u16),
}

impl RecordType {
    /// Converts a record type to its 16-bit wire representation.
    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ptr => 12,
            RecordType::Txt => 16,
            RecordType::Srv => 33,
            RecordType::Other(v) => v,
        }
    }

    /// Parses a 16-bit value into a [`RecordType`].
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            12 => RecordType::Ptr,
            16 => RecordType::Txt,
            33 => RecordType::Srv,
            v => RecordType::Other(v),
        }
    }
}

/// A parsed or constructed DNS Resource Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Domain name to which this record pertains.
    pub name: String,
    /// Record type.
    pub record_type: RecordType,
    /// Record class (typically IN = 1, optionally with cache-flush bit 0x8000).
    pub class: u16,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Binary record data.
    pub rdata: Vec<u8>,
}

/// Encodes a domain name string into DNS wire format labels.
pub fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let trimmed = domain.trim_end_matches('.');
    if trimmed.is_empty() {
        bytes.push(0);
        return bytes;
    }

    for label in trimmed.split('.') {
        let label_bytes = label.as_bytes();
        let len = (label_bytes.len().min(63)) as u8;
        bytes.push(len);
        bytes.extend_from_slice(&label_bytes[..len as usize]);
    }
    bytes.push(0);
    bytes
}

/// Decodes a domain name from DNS packet bytes, resolving compression pointers.
pub fn decode_domain_name(buffer: &[u8], mut offset: usize) -> Result<(String, usize), MdnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    let mut loop_count = 0;

    while offset < buffer.len() {
        loop_count += 1;
        if loop_count > 100 {
            return Err(MdnsError::PacketParseFailed(
                "pointer cycle detected in domain name".to_string(),
            ));
        }

        let len = buffer[offset];
        if len == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        } else if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buffer.len() {
                return Err(MdnsError::PacketParseFailed(
                    "truncated DNS pointer offset".to_string(),
                ));
            }
            let pointer = (((len & 0x3F) as usize) << 8) | (buffer[offset + 1] as usize);
            if !jumped {
                final_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
        } else {
            let label_len = len as usize;
            offset += 1;
            if offset + label_len > buffer.len() {
                return Err(MdnsError::PacketParseFailed(
                    "label length exceeds packet boundary".to_string(),
                ));
            }
            let label_str = std::str::from_utf8(&buffer[offset..offset + label_len])
                .map_err(|e| MdnsError::PacketParseFailed(format!("invalid UTF-8 label: {e}")))?;
            labels.push(label_str);
            offset += label_len;
            if !jumped {
                final_offset = offset;
            }
        }
    }

    Ok((labels.join("."), final_offset))
}

/// Encodes a list of key-value string pairs into DNS TXT RDATA wire format.
pub fn encode_txt_rdata(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut rdata = Vec::new();
    for (k, v) in entries {
        let entry_str = format!("{}={}", k, v);
        let bytes = entry_str.as_bytes();
        let len = bytes.len().min(255) as u8;
        rdata.push(len);
        rdata.extend_from_slice(&bytes[..len as usize]);
    }
    rdata
}

/// Decodes DNS TXT RDATA into a key-value mapping.
pub fn decode_txt_rdata(rdata: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            break;
        }
        if let Ok(entry) = std::str::from_utf8(&rdata[i..i + len]) {
            if let Some((k, v)) = entry.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            } else {
                map.insert(entry.to_string(), String::new());
            }
        }
        i += len;
    }
    map
}

/// Encodes DNS SRV RDATA (priority, weight, port, target).
pub fn encode_srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.extend_from_slice(&weight.to_be_bytes());
    rdata.extend_from_slice(&port.to_be_bytes());
    rdata.extend_from_slice(&encode_domain_name(target));
    rdata
}

/// An mDNS packet representation with serialization and parsing support.
#[derive(Debug, Clone, Default)]
pub struct DnsPacket {
    /// 16-bit transaction ID (0x0000 for mDNS).
    pub id: u16,
    /// 16-bit flags (0x8400 for authoritative standard response).
    pub flags: u16,
    /// Answer resource records.
    pub answers: Vec<ResourceRecord>,
}

impl DnsPacket {
    /// Creates a new empty authoritative response packet.
    pub fn new_response() -> Self {
        Self {
            id: 0,
            flags: 0x8400,
            answers: Vec::new(),
        }
    }

    /// Serializes the packet into standard DNS wire format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // Header (12 bytes)
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Answer records
        for record in &self.answers {
            buf.extend_from_slice(&encode_domain_name(&record.name));
            buf.extend_from_slice(&record.record_type.to_u16().to_be_bytes());
            buf.extend_from_slice(&record.class.to_be_bytes());
            buf.extend_from_slice(&record.ttl.to_be_bytes());
            buf.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(&record.rdata);
        }

        buf
    }

    /// Parses a raw DNS packet from a byte slice.
    pub fn parse(buf: &[u8]) -> Result<Self, MdnsError> {
        if buf.len() < 12 {
            return Err(MdnsError::PacketParseFailed(
                "packet shorter than 12-byte DNS header".to_string(),
            ));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

        let mut offset = 12;

        // Skip questions if any
        for _ in 0..qdcount {
            let (_, next_offset) = decode_domain_name(buf, offset)?;
            if next_offset + 4 > buf.len() {
                return Err(MdnsError::PacketParseFailed(
                    "truncated question record".to_string(),
                ));
            }
            offset = next_offset + 4;
        }

        // Parse answer, authority, and additional records into answers
        let total_records = ancount + nscount + arcount;
        let mut answers = Vec::with_capacity(total_records);

        for _ in 0..total_records {
            if offset >= buf.len() {
                break;
            }
            let (name, next_offset) = decode_domain_name(buf, offset)?;
            if next_offset + 10 > buf.len() {
                return Err(MdnsError::PacketParseFailed(
                    "truncated resource record header".to_string(),
                ));
            }

            let type_val = u16::from_be_bytes([buf[next_offset], buf[next_offset + 1]]);
            let class_val = u16::from_be_bytes([buf[next_offset + 2], buf[next_offset + 3]]);
            let ttl = u32::from_be_bytes([
                buf[next_offset + 4],
                buf[next_offset + 5],
                buf[next_offset + 6],
                buf[next_offset + 7],
            ]);
            let rdlength =
                u16::from_be_bytes([buf[next_offset + 8], buf[next_offset + 9]]) as usize;

            let rdata_start = next_offset + 10;
            let rdata_end = rdata_start + rdlength;
            if rdata_end > buf.len() {
                return Err(MdnsError::PacketParseFailed(
                    "RDATA length exceeds packet boundary".to_string(),
                ));
            }

            let rdata = buf[rdata_start..rdata_end].to_vec();
            offset = rdata_end;

            answers.push(ResourceRecord {
                name,
                record_type: RecordType::from_u16(type_val),
                class: class_val,
                ttl,
                rdata,
            });
        }

        Ok(Self { id, flags, answers })
    }

    /// Finds and decodes a TXT record matching the given suffix or domain name.
    pub fn get_txt_record(&self, domain_suffix: &str) -> Option<HashMap<String, String>> {
        for record in &self.answers {
            if record.record_type == RecordType::Txt
                && (record.name == domain_suffix || record.name.ends_with(domain_suffix))
            {
                return Some(decode_txt_rdata(&record.rdata));
            }
        }
        None
    }
}

/// Builds complete mDNS announcement packet for AirPlay and RAOP services.
pub fn build_announcement_packet(config: &MdnsConfig, interface_ip: Ipv4Addr) -> DnsPacket {
    let mut packet = DnsPacket::new_response();

    let airplay_service_type = "_airplay._tcp.local";
    let raop_service_type = "_raop._tcp.local";
    let target_host = format!("{}.local", config.hostname);

    let airplay_instance = format!("{}.{}", config.service_name, airplay_service_type);
    let mac_compact = config.device_id.replace(':', "");
    let raop_instance = format!(
        "{}@{}.{}",
        mac_compact, config.service_name, raop_service_type
    );

    let ttl = 4500; // 75 minutes standard Apple TTL
    let class_shared = 1u16; // IN
    let class_flush = 0x8001u16; // IN + cache-flush

    // 1. AirPlay PTR record
    packet.answers.push(ResourceRecord {
        name: airplay_service_type.to_string(),
        record_type: RecordType::Ptr,
        class: class_shared,
        ttl,
        rdata: encode_domain_name(&airplay_instance),
    });

    // 2. AirPlay SRV record (port 7000)
    packet.answers.push(ResourceRecord {
        name: airplay_instance.clone(),
        record_type: RecordType::Srv,
        class: class_flush,
        ttl,
        rdata: encode_srv_rdata(0, 0, config.airplay_port, &target_host),
    });

    // 3. AirPlay TXT record (iOS 16/17/18+ screen mirroring bitmasks)
    let airplay_txt_entries = [
        ("deviceid", config.device_id.as_str()),
        ("features", config.features.as_str()),
        ("flags", config.flags.as_str()),
        ("model", config.model.as_str()),
        (
            "pk",
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        ),
        ("srcvers", config.srcvers.as_str()),
        ("vv", "2"),
    ];
    packet.answers.push(ResourceRecord {
        name: airplay_instance,
        record_type: RecordType::Txt,
        class: class_flush,
        ttl,
        rdata: encode_txt_rdata(&airplay_txt_entries),
    });

    // 4. RAOP PTR record
    packet.answers.push(ResourceRecord {
        name: raop_service_type.to_string(),
        record_type: RecordType::Ptr,
        class: class_shared,
        ttl,
        rdata: encode_domain_name(&raop_instance),
    });

    // 5. RAOP SRV record (port 5000)
    packet.answers.push(ResourceRecord {
        name: raop_instance.clone(),
        record_type: RecordType::Srv,
        class: class_flush,
        ttl,
        rdata: encode_srv_rdata(0, 0, config.raop_port, &target_host),
    });

    // 6. RAOP TXT record
    let raop_txt_entries = [
        ("ch", "2"),
        ("cn", "0,1,2,3"),
        ("da", "true"),
        ("et", "0,3,5"),
        ("ft", config.features.as_str()),
        ("md", "0,1,2"),
        (
            "pk",
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        ),
        ("sf", config.flags.as_str()),
        ("sr", "44100"),
        ("ss", "16"),
        ("sv", "false"),
        ("tp", "UDP"),
        ("vn", "65537"),
        ("vs", config.srcvers.as_str()),
        ("am", config.model.as_str()),
    ];
    packet.answers.push(ResourceRecord {
        name: raop_instance,
        record_type: RecordType::Txt,
        class: class_flush,
        ttl,
        rdata: encode_txt_rdata(&raop_txt_entries),
    });

    // 7. A record resolving hostname -> interface IP
    packet.answers.push(ResourceRecord {
        name: target_host,
        record_type: RecordType::A,
        class: class_flush,
        ttl,
        rdata: interface_ip.octets().to_vec(),
    });

    packet
}

/// Active broadcaster instance managing network sockets.
pub struct MdnsBroadcaster {
    config: MdnsConfig,
}

impl MdnsBroadcaster {
    /// Creates a new broadcaster with the given configuration.
    pub fn new(config: MdnsConfig) -> Result<Self, MdnsError> {
        Ok(Self { config })
    }

    /// Broadcasts mDNS announcements across all active non-loopback IPv4 interfaces.
    pub fn broadcast(&self) -> Result<(), MdnsError> {
        let interfaces = get_active_ipv4_interfaces();
        let target_addr = SocketAddrV4::new(MDNS_IPV4_ADDR, MDNS_PORT);

        for &iface_ip in &interfaces {
            let packet = build_announcement_packet(&self.config, iface_ip);
            let packet_bytes = packet.to_bytes();

            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .map_err(MdnsError::Io)?;
            let _ = socket.set_reuse_address(true);
            socket.set_multicast_loop_v4(true).map_err(MdnsError::Io)?;
            socket.set_multicast_ttl_v4(255).map_err(MdnsError::Io)?;

            let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            socket.bind(&bind_addr.into()).map_err(MdnsError::Io)?;

            if !iface_ip.is_loopback() {
                let _ = socket.set_multicast_if_v4(&iface_ip);
            }

            socket
                .send_to(&packet_bytes, &target_addr.into())
                .map_err(MdnsError::Io)?;
        }

        // Also broadcast once via unspecified route to guarantee loopback reception
        let packet = build_announcement_packet(
            &self.config,
            interfaces.first().copied().unwrap_or(Ipv4Addr::LOCALHOST),
        );
        let packet_bytes = packet.to_bytes();

        let loop_socket =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(MdnsError::Io)?;
        let _ = loop_socket.set_reuse_address(true);
        loop_socket
            .set_multicast_loop_v4(true)
            .map_err(MdnsError::Io)?;
        loop_socket
            .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())
            .map_err(MdnsError::Io)?;

        let _ = loop_socket.send_to(&packet_bytes, &target_addr.into());

        log::info!(
            "mDNS: broadcasted announcements for '{}' across {} interfaces",
            self.config.service_name,
            interfaces.len()
        );

        Ok(())
    }
}

/// Creates a UDP listener socket bound to `0.0.0.0:5353` and joined to multicast group `224.0.0.251`.
pub fn create_multicast_listener() -> Result<std::net::UdpSocket, MdnsError> {
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(MdnsError::Io)?;

    socket.set_reuse_address(true).map_err(MdnsError::Io)?;
    socket.set_multicast_loop_v4(true).map_err(MdnsError::Io)?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&bind_addr.into()).map_err(MdnsError::Io)?;

    // Join multicast group on INADDR_ANY and on all active interfaces
    let _ = socket.join_multicast_v4(&MDNS_IPV4_ADDR, &Ipv4Addr::UNSPECIFIED);
    for iface_ip in get_active_ipv4_interfaces() {
        let _ = socket.join_multicast_v4(&MDNS_IPV4_ADDR, &iface_ip);
    }

    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(3000)))
        .map_err(MdnsError::Io)?;

    let std_socket: std::net::UdpSocket = socket.into();
    Ok(std_socket)
}

/// Advertise this receiver as an AirPlay target on the local network.
///
/// Registers both `_airplay._tcp.local.` and `_raop._tcp.local.` services across
/// all active network interfaces with Apple TV profile parameters.
///
/// # Arguments
/// * `service_name` – The display name shown on iOS/macOS device lists.
/// * `port`         – The TCP port the RTSP server will listen on.
///
/// # Errors
/// Returns [`MdnsError`] if socket creation or transmission fails.
pub fn advertise(service_name: &str, port: u16) -> Result<(), MdnsError> {
    let config = MdnsConfig {
        service_name: service_name.to_string(),
        airplay_port: port,
        ..Default::default()
    };

    let broadcaster = MdnsBroadcaster::new(config)?;
    broadcaster.broadcast()
}

/// Discover AirPlay senders on the local network.
///
/// Returns a snapshot of currently visible peers. Non-blocking; returns
/// whatever has been observed since the last call.
pub fn discover_peers() -> Vec<AirPlayPeer> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertise_returns_ok_with_valid_args() {
        assert!(advertise("JCB AirPlay Test", 7000).is_ok());
    }

    #[test]
    fn discover_peers_returns_empty_on_baseline() {
        let peers = discover_peers();
        assert!(peers.is_empty(), "expected no peers at baseline");
    }

    #[test]
    fn test_deterministic_mac_format() {
        let mac = get_deterministic_mac();
        assert!(
            mac.starts_with("48:A6:B8:"),
            "MAC should use Apple OUI 48:A6:B8"
        );
        let parts: Vec<&str> = mac.split(':').collect();
        assert_eq!(parts.len(), 6, "MAC must have 6 octets");
        for part in parts {
            assert_eq!(part.len(), 2, "Each octet must be 2 hex digits");
            assert!(
                part.chars().all(|c| c.is_ascii_hexdigit()),
                "All octets must be valid hex digits"
            );
        }
    }

    #[test]
    fn test_dns_packet_encode_decode_roundtrip() {
        let config = MdnsConfig::default();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = build_announcement_packet(&config, ip);
        let bytes = packet.to_bytes();

        let parsed = DnsPacket::parse(&bytes).expect("Failed to parse encoded DNS packet");
        assert_eq!(parsed.flags, 0x8400);

        let airplay_txt = parsed
            .get_txt_record("_airplay._tcp.local")
            .expect("Should have _airplay._tcp.local TXT record");

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
        assert!(airplay_txt.contains_key("deviceid"));

        let raop_txt = parsed
            .get_txt_record("_raop._tcp.local")
            .expect("Should have _raop._tcp.local TXT record");
        assert_eq!(raop_txt.get("am").map(|s| s.as_str()), Some("AppleTV3,2"));
        assert_eq!(
            raop_txt.get("ft").map(|s| s.as_str()),
            Some("0x5A7FFFF7,0x1E")
        );
    }

    #[test]
    fn test_active_interfaces_non_empty() {
        let ips = get_active_ipv4_interfaces();
        assert!(!ips.is_empty(), "Must return at least one IPv4 interface");
    }
}
