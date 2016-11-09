//! A module exposing a virtual tunnel interface to tor.
#![deny(missing_docs)]

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{Read, Write};
use std::net::{UdpSocket, TcpStream, IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use rand::random;
use socks::{Connect, Address, AuthMethod};

use packet::{IpPacket, IpPacketMut, Payload, Pair};
use packet::ip::{IpHeader, IpProto};
use packet::result::{Result, Error};
use packet::tcp::TcpHeader;

struct Tcb {
    tx: Sender<Box<[u8]>>,
}

impl Tcb {
    pub fn new<'a>(output_packet: Arc<Fn(Vec<u8>, IpAddr) + Send + Sync>,
                   ip: &IpHeader<'a>,
                   tcp: &TcpHeader<'a>)
                   -> Result<Tcb> {
        if !tcp.is_syn() {
            return Err(Error::IPChecksumInvalid); // TODO Handle error
        }
        let output_packet = Arc::downgrade(&output_packet);
        let src = SocketAddr::new(ip.src(), tcp.src());
        let dest = SocketAddr::new(ip.dest(), tcp.dest());
        let mut ack_num = tcp.seq_num();
        let (tx, rx) = mpsc::channel();
        let tcb = Tcb { tx: tx };
        thread::spawn(move || {
            let mut writer = match TcpStream::connect("127.0.0.1:9050") {
                Ok(s) => s,
                Err(e) => return, // TODO: Handle error
            };

            if let Err(e) = writer.socks5_connect(Address::from(dest), &[AuthMethod::None]) {
                return; // TODO: Handle error
            }

            ack_num += 1;
            let mut seq_num: u32 = random();

            let packet = IpPacketMut::new_tcp(dest, src, seq_num, ack_num, true, true, &[]);

            if let Some(output_packet) = output_packet.upgrade() {
                println!("WROTE SYN-ACK");
                output_packet(packet.into_buf(), src.ip());
            }

            let weak2 = output_packet.clone();

            let mut reader = writer.try_clone().unwrap();
            thread::spawn(move || {
                loop {
                    let mut buf = [0; 512];
                    match reader.read(&mut buf) {
                        Ok(len) => {
                            seq_num += 1;
                            let packet = IpPacketMut::new_tcp(dest,
                                                              src,
                                                              seq_num,
                                                              0,
                                                              false,
                                                              true,
                                                              &buf[..len]);
                            if let Some(output_packet) = output_packet.upgrade() {
                                println!("WROTE SYN RESPONSE DATA");
                                output_packet(packet.into_buf(), src.ip());
                            }
                        }
                        Err(e) => continue, // TODO: Handle error
                    }
                }
            });

            loop {
                match rx.recv() {
                    Ok(buf) => {
                        let packet = IpPacket::with_buf(&buf).unwrap();
                        if let Payload::Tcp(ref t) = packet.payload {
                            if t.is_syn() {
                                ack_num += 1;
                                writer.write_all(packet.data()).unwrap();
                                println!("WROTE DATA TO SOCKS");
                                let response =
                                    IpPacketMut::new_tcp(dest, src, 0, ack_num, true, false, &[]);
                                if let Some(output_packet) = weak2.upgrade() {
                                    output_packet(response.into_buf(), src.ip());
                                    println!("WROTE ACK FOR DATA");
                                }
                            }
                            if t.is_ack() {
                                println!("RECEIVED ACK");
                            }
                        }
                    }
                    Err(e) => continue, // TODO: Handle error
                }
            }

        });
        Ok(tcb)
    }

    pub fn input_packet(&self, packet: &[u8]) -> Result<()> {
        Ok(try!(self.tx.send(packet.to_vec().into_boxed_slice())))
    }
}

/// A virtual tunnel interface
pub struct TunIf {
    tcbs: RwLock<HashMap<((IpAddr, u16), (IpAddr, u16)), Tcb>>,
    output_packet: Arc<Fn(Vec<u8>, IpAddr) + Send + Sync>,
}

impl TunIf {
    /// Initializes a new tunnel interface
    pub fn new(output_packet: Arc<Fn(Vec<u8>, IpAddr) + Send + Sync>) -> TunIf {
        TunIf {
            tcbs: RwLock::new(HashMap::new()),
            output_packet: output_packet,
        }
    }

    /// Takes an IP packet from the interface and forwards it over tor
    pub fn input_packet(&self, buf: &[u8]) -> Result<()> {
        let packet = try!(IpPacket::with_buf(&buf));
        if !packet.checksum_valid() {
            return Err(Error::IPChecksumInvalid);
        }

        match &packet.payload {
            &Payload::Udp(ref u) => {
                if u.dest() != 53 {
                    return Err(Error::IPProtoNotSupported(IpProto::Udp));
                }

                let output_packet = Arc::downgrade(&self.output_packet);
                let src = SocketAddr::new(packet.fixed.src(), u.src());
                let dest = SocketAddr::new(packet.fixed.dest(), u.dest());
                let data = packet.data().to_vec().into_boxed_slice();
                thread::spawn(move || {
                    // TODO: Allow configuration of DNSPort
                    let socket = match UdpSocket::bind("127.0.0.1:0") {
                        Ok(s) => s,
                        Err(e) => return, // TODO: Handle error
                    };
                    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    match socket.send_to(&*data, "127.0.0.1:12345") {
                        Ok(_l) => (),
                        Err(e) => return, // TODO: Handle error
                    };
                    drop(data);

                    let mut data = [0; 512];
                    let data_len = match socket.recv_from(&mut data) {
                        Ok((len, _addr)) => len,
                        Err(e) => return, // TODO: Handle error
                    };

                    let packet = IpPacketMut::new_udp(dest, src, &data[..data_len]);

                    if let Some(output_packet) = output_packet.upgrade() {
                        output_packet(packet.into_buf(), src.ip());
                    }
                });
            }
            &Payload::Tcp(ref t) => {
                let quad = ((packet.fixed.src(), t.src()), (packet.fixed.dest(), t.dest()));
                let output_packet = self.output_packet.clone();
                let mut tcbs = self.tcbs.write().unwrap();
                match tcbs.entry(quad) {
                    Entry::Occupied(e) => {
                        if e.get().input_packet(buf).is_err() {
                            e.remove();
                        }
                    }
                    Entry::Vacant(e) => {
                        e.insert(Tcb::new(output_packet, &packet.fixed, t).unwrap());
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}
