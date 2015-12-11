//! A module exposing a virtual tunnel interface to tor.
#![deny(missing_docs)]
use std::thread;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::net::UdpSocket;

use result::{Result, Error};
use packet::{Header, Pair};
use ip::{IpHeader, IpProto};
use udp::UdpHeader;
use tcp::TcpHeader;

/// A virtual tunnel interface
pub struct TunIf {
    pkt_cb: Option<Box<Fn(&[u8], u8) + Send>>,
}

impl fmt::Debug for TunIf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TunIf {{ }}")
    }
}

impl TunIf {
    /// Initializes a new tunnel interface
    pub fn new() -> TunIf {
        TunIf { pkt_cb: None }
    }
}

/// An IP packet interface for TunIf
pub trait IpHandler {
    /// Takes an IP packet from the interface and forwards it over tor
    fn input_packet(&self, packet: &[u8]) -> Result<()>;

    /// Outputs a packet to the interface from tor
    fn output_packet(&self, packet: &[u8], proto: u8);

    /// Sets a callback to receive packets from tor
    fn set_packet_callback(&self, cb: Option<Box<Fn(&[u8], u8) + Send>>);
}

impl IpHandler for Arc<Mutex<TunIf>> {
    fn input_packet(&self, packet: &[u8]) -> Result<()> {
        let ip_hdr = try!(IpHeader::with_buf(packet));
        if !ip_hdr.checksum_valid() {
            return Err(Error::IPChecksumInvalid);
        }

        let payload = &packet[ip_hdr.len()..];
        match ip_hdr.proto() {
            IpProto::Udp => {
                let udp_hdr = UdpHeader::with_buf(payload);
                let data = &payload[udp_hdr.len()..][..udp_hdr.data_len()];
                if udp_hdr.dest() != 53 {
                    return Err(Error::IPProtoNotSupported(IpProto::Udp));
                }
                if !udp_hdr.checksum_valid(&ip_hdr, data.pair_iter()) {
                    return Err(Error::IPChecksumInvalid); // TODO: Make into UDP specific error
                }

                let tunif = self.clone();
                let bytes = data.to_vec().into_boxed_slice();
                let src_ip = ip_hdr.src();
                let dest_ip = ip_hdr.dest();
                let src_port = udp_hdr.src();
                let dest_port = udp_hdr.dest();

                thread::spawn(move || {
                    let socket = try_log!(UdpSocket::bind("127.0.0.1:0"));
                    try_log!(socket.send_to(&*bytes, "127.0.0.1:12345")); // TODO: Allow configuration of DNSPort
                    drop(bytes);

                    let mut buf = [0; 512 + 60 + 8]; // TODO: Use max_len() when converted to associated constants

                    let (ip_len, ip_ver) = {
                        let mut ip_hdr = IpHeader::with_buf_hint(&mut buf[..], &src_ip);
                        ip_hdr.initialize();
                        ip_hdr.set_src(&dest_ip);
                        ip_hdr.set_dest(&src_ip);
                        ip_hdr.set_proto(&IpProto::Udp);
                        (ip_hdr.len(), ip_hdr.version())
                    };

                    let udp_len = {
                        let mut udp_hdr = UdpHeader::with_buf(&mut buf[ip_len..]);
                        udp_hdr.set_dest(src_port);
                        udp_hdr.set_src(dest_port);
                        udp_hdr.len()
                    };
                    let (data_len, _addr) = try_log!(socket.recv_from(&mut buf[ip_len +
                                                                               udp_len..]));

                    let total_len = ip_len + udp_len + data_len;
                    {
                        let mut ip_hdr = IpHeader::with_buf(&mut buf[..]).unwrap();
                        ip_hdr.set_total_len(total_len);
                        ip_hdr.calculate_checksum();
                    }
                    {
                        let mut udp_hdr = UdpHeader::with_buf(&mut buf[ip_len..]);
                        udp_hdr.set_udp_len(udp_len + data_len);
                    }

                    let checksum = {
                        let ip_hdr = IpHeader::with_buf(&buf[..]).unwrap();
                        let udp_hdr = UdpHeader::with_buf(&buf[ip_len..]);
                        udp_hdr.calculate_checksum(&ip_hdr,
                                                   (&buf[ip_len + udp_len..total_len]).pair_iter())
                    };
                    UdpHeader::with_buf(&mut buf[ip_len..]).set_checksum(checksum);

                    tunif.output_packet(&buf[..total_len], ip_ver);
                });
            }
            IpProto::Tcp => {
                let tcp_hdr = TcpHeader::with_buf(payload);
                let data = &packet[ip_hdr.len() + tcp_hdr.len()..ip_hdr.total_len()];
                if !tcp_hdr.checksum_valid(&ip_hdr, data.pair_iter()) {
                    return Err(Error::IPChecksumInvalid); // TODO: Make into TCPP specific error
                }

                // TODO: Do something with the packet
            }
            p => return Err(Error::IPProtoNotSupported(p)),
        }
        Ok(())
    }

    fn output_packet(&self, packet: &[u8], proto: u8) {
        match (*self).lock().unwrap().pkt_cb {
            Some(ref cb) => cb(packet, proto),
            None => (),
        }
    }

    fn set_packet_callback(&self, cb: Option<Box<Fn(&[u8], u8) + Send>>) {
        self.lock().unwrap().pkt_cb = cb;
    }
}
