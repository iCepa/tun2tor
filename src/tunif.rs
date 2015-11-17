//! A module exposing a virtual tunnel interface to tor.
#![deny(missing_docs)]
use std::thread;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

use ip::{IpHeader, IpProto, FromBytes};
use udp::UdpHeader;

use mio::{EventLoop, Token, Handler, EventSet, PollOpt};
use mio::udp::UdpSocket;

const DNS_HANDLER: Token = Token(0);

/// A handle for a UDP connection
#[derive(Debug)]
pub struct UdpPcb {
    sock: UdpSocket,
    tunif: Arc<Mutex<TunIf>>,
}

impl Handler for UdpPcb {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, _: &mut EventLoop<UdpPcb>, _: Token, _: EventSet) {
        let mut buffer: [u8; 4096] = [0; 4096];
        let data = match self.sock.recv_from(&mut buffer) {
            Ok(Some((len, _addr))) => Some(&buffer[..len]),
            _ => None,
        };

        // TODO: Wrap the data into a proper IP packet

        match data {
            Some(d) => match &self.tunif.lock().unwrap().pkt_cb {
                &Some(ref cb) => cb(&d),
                &None => return,
            },
            None => return,
        }
    }
}

/// A virtual tunnel interface
pub struct TunIf {
    pkt_cb: Option<Box<Fn(&[u8]) + Send>>,
}

impl fmt::Debug for TunIf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TunIf")
    }
}

impl TunIf {
    /// Initializes a new tunnel interface
    pub fn new() -> TunIf {
        TunIf { pkt_cb: None }
    }
}

/// A packet-level interface for TunIf
pub trait PktHandler {
    /// Sends an IP packet over tor
    fn input_packet(&self, packet: &[u8]);

    /// Sets a callback to receive packets from tor
    fn set_packet_callback(&self, cb: Option<Box<Fn(&[u8]) + Send>>);
}

impl PktHandler for Arc<Mutex<TunIf>> {
    fn input_packet(&self, packet: &[u8]) {
        let result = IpHeader::from_bytes(packet);
        if result.is_err() {
            return println!("IP header parsing failed: {:?}", result.err().unwrap());
        }

        let header = result.unwrap();
        if header.len() > packet.len() {
            return println!("IP header length is greater than total packet length, packet dropped");
        }
        if header.checksum_valid() == false {
            return println!("IP header checksum is invalid, packet dropped");
        }

        let payload = &packet[header.len()..];

        match header.proto() {
            &IpProto::Udp => {
                match UdpHeader::from_bytes(payload) {
                    Ok(udp_hdr) => {
                        if udp_hdr.dest != 53 {
                            return println!("UDP packet is not DNS, packet dropped");
                        }
                        if udp_hdr.len() > payload.len() {
                            return println!("UDP header length is greater than payload length, \
                                             packet dropped");
                        }

                        let data = &payload[udp_hdr.len()..];

                        if udp_hdr.checksum_valid(&data, &header) == false {
                            // return println!("UDP header checksum is invalid, packet dropped");
                        }

                        let clone = self.clone();
                        let bytes = data.to_vec().into_boxed_slice();

                        thread::spawn(move || {
                            let mut event_loop = EventLoop::new().unwrap();

                            let localhost = Ipv4Addr::new(127, 0, 0, 1);
                            let src = SocketAddr::V4(SocketAddrV4::new(localhost, 0));
                            let sock = UdpSocket::bound(&src).unwrap();
                            event_loop.register(&sock,
                                                DNS_HANDLER,
                                                EventSet::readable(),
                                                PollOpt::level())
                                      .unwrap();

                            // TODO: Make DNSPort configuratble
                            let dest = SocketAddr::V4(SocketAddrV4::new(localhost, 12345));
                            sock.send_to(&*bytes, &dest);

                            let mut handler = UdpPcb {
                                sock: sock,
                                tunif: clone,
                            };
                            event_loop.run(&mut handler).unwrap();
                        });
                    }
                    Err(err) =>
                        println!("UDP header could not be parsed {:?}, packet dropped", err),
                }
            }
            &IpProto::Tcp => println!("IP Proto is TCP!"),
            ref other => println!("IP protocol {:?} is not currently supported", other),
        }
    }

    fn set_packet_callback(&self, cb: Option<Box<Fn(&[u8]) + Send>>) {
        self.lock().unwrap().pkt_cb = cb;
    }
}
