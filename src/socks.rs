use std::io;
use std::net::{SocketAddr, IpAddr};

use byteorder::{NetworkEndian, WriteBytesExt};
use futures::{Future, IntoFuture};
use tokio_io::io::{read_exact, write_all};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;

use tcp::TcpBackend;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
const SOCKS_CMD_TCP_CONNECT: u8 = 0x01;
const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

type BoxedStream = Box<dyn Future<Item = TcpStream, Error = io::Error>>;

#[derive(Debug, Copy, Clone)]
pub struct SocksBackend {
    addr: SocketAddr,
}

impl SocksBackend {
    pub fn new(addr: &SocketAddr) -> SocksBackend {
        SocksBackend { addr: *addr }
    }
}

impl TcpBackend for SocksBackend {
    fn build(&self, addr: &SocketAddr, handle: &Handle) -> BoxedStream {
        let addr = *addr;
        let stream = TcpStream::connect(&self.addr, handle);
        let greeting = stream.and_then(move |stream| {
            write_all(stream, vec![SOCKS5_VERSION, 1, SOCKS5_AUTH_METHOD_NONE])
        });
        let handshake = greeting.and_then(move |(stream, _)| {
            read_exact(stream, vec![0; 2]).and_then(move |(stream, resp)| {
                if resp[0] != SOCKS5_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid response version",
                    ));
                }

                match resp[1] {
                    0 => Ok(stream),
                    0xFF => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "no acceptable auth methods",
                    )),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown auth method",
                    )),
                }
            })
        });

        let command = handshake.and_then(move |stream| {
            let len = match addr {
                SocketAddr::V4(..) => 4 + 6,
                SocketAddr::V6(..) => 16 + 6,
            };

            let mut buf = vec![0; len];
            buf[0] = SOCKS5_VERSION;
            buf[1] = SOCKS_CMD_TCP_CONNECT;

            match addr.ip() {
                IpAddr::V4(a) => {
                    buf[3] = SOCKS5_ADDR_TYPE_IPV4;
                    (&mut buf[4..8]).clone_from_slice(&a.octets());
                }
                IpAddr::V6(a) => {
                    let mut buf = vec![0; 19];
                    buf[3] = SOCKS5_ADDR_TYPE_IPV6;
                    (&mut buf[4..20]).clone_from_slice(&a.octets())
                }
            };

            (&mut buf[len - 2..])
                .write_u16::<NetworkEndian>(addr.port())
                .unwrap();

            write_all(stream, buf)
        });

        let response = command.and_then(move |(stream, _)| {
            read_exact(stream, vec![0; 3]).and_then(move |(stream, resp)| {
                if resp[0] != SOCKS5_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid response version",
                    ));
                }

                match resp[1] {
                    0 => (),
                    1 => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "general SOCKS server failure",
                        ))
                    }
                    2 => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "connection not allowed by ruleset",
                        ))
                    }
                    3 => return Err(io::Error::new(io::ErrorKind::Other, "network unreachable")),
                    4 => return Err(io::Error::new(io::ErrorKind::Other, "host unreachable")),
                    5 => return Err(io::Error::new(io::ErrorKind::Other, "connection refused")),
                    6 => return Err(io::Error::new(io::ErrorKind::Other, "TTL expired")),
                    7 => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "command not supported",
                        ))
                    }
                    8 => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "address kind not supported",
                        ))
                    }
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown error")),
                };

                if resp[2] != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid reserved byte",
                    ));
                }

                Ok(stream)
            })
        });

        Box::new(response.and_then(move |stream| {
            read_exact(stream, vec![0; 1]).and_then(move |(stream, buf)| {
                let len = match buf[0] {
                    SOCKS5_ADDR_TYPE_IPV4 => 6,
                    SOCKS5_ADDR_TYPE_IPV6 => 18,
                    _ => {
                        return Box::new(
                            Err(io::Error::new(
                                io::ErrorKind::Other,
                                "unsupported address type",
                            )).into_future(),
                        ) as BoxedStream
                    }
                };
                Box::new(read_exact(stream, vec![0; len]).map(
                    move |(stream, _buf)| stream,
                )) as BoxedStream
            })
        }))
    }
}
