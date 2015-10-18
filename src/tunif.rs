use ip::{IpHeader, Ipv4Header, Ipv6Header, IpProto, FromBytes};
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
        match IpHeader::from_bytes(packet) {
            Ok(IpHeader::V4(ipv4_hdr)) => {
                if ipv4_hdr.hlen > packet.len() {
                    return println!("Error: IP header length is greater than total packet length, packet dropped");
                }
                if ipv4_hdr.checksum_valid() == false {
                    return println!("Error: IP header checksum is invalid, packet dropped");
                }

                let payload = &packet[ipv4_hdr.hlen..];
                
                match ipv4_hdr.proto {
                    IpProto::Udp => {
                        let ip_hdr = IpHeader::V4(ipv4_hdr);
                        match UdpHeader::from_bytes(payload) {
                            Ok(udp_hdr) => {
                                let data = &payload[8..];
                                if udp_hdr.dest != 53 {
                                    return println!("UDP packet is not DNS, packet dropped");
                                }
                                if udp_hdr.checksum_valid(&data, &ip_hdr) == false {
                                    return println!("Error: UDP header checksum is invalid, packet dropped");
                                }

                                println!("PACKET VALID!!!!");
                            },
                            _ => ()
                        };
                    },
                    IpProto::Tcp => {
                        println!("IP Proto is TCP!");
                    },
                    other => {
                        return println!("IP protocol {:?} is not currently supported", other);
                    }
                };
            },
            Ok(IpHeader::V6(ipv6_hdr)) => {
                println!("Error: TunIf cannot handle IPv6 headers yet {:?}", ipv6_hdr.src);
            },
            Err(error) => {
                println!("Error: {:?}, dropping packet", error);
            }
        };
    }
}
