use ip::{IpHeader, IpProto, FromBytes};
use udp::{UdpPcb, UdpHeader};

pub struct TunIf {
    udp: Vec<UdpPcb>,
}

impl TunIf {
    pub fn new() -> TunIf {
        TunIf {
            udp: Vec::new()
        }
    }

    pub fn input_packet(&self, packet: &[u8]) {
        let result = IpHeader::from_bytes(packet);
        if result.is_err() {
            return println!("Error: IP header parsing failed: {:?}", result.err().unwrap());
        }

        let header = result.unwrap();
        if header.len() > packet.len() {
            return println!("Error: IP header length is greater than total packet length, packet dropped");
        }
        if header.checksum_valid() == false {
            return println!("Error: IP header checksum is invalid, packet dropped");
        }

        let payload = &packet[header.len()..];

        match header.proto() {
            &IpProto::Udp => {
                match UdpHeader::from_bytes(payload) {
                    Ok(udp_hdr) => {
                        let data = &payload[udp_hdr.len()..];
                        if udp_hdr.dest != 53 {
                            return println!("UDP packet is not DNS, packet dropped");
                        }
                        if udp_hdr.checksum_valid(&data, &header) == false {
                            return println!("Error: UDP header checksum is invalid, packet dropped");
                        }

                        println!("PACKET VALID!!!!");
                    },
                    _ => ()
                };
            },
            &IpProto::Tcp => {
                println!("IP Proto is TCP!");
            },
            ref other => {
                return println!("IP protocol {:?} is not currently supported", other);
            }
        };
    }
}
