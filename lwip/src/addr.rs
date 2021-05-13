use byteorder::{ByteOrder, NativeEndian, NetworkEndian};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPADDR_TYPE_V4: u8 = 0;
const IPADDR_TYPE_V6: u8 = 6;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ip_addr_t {
    addr: ip6_addr_t,
    version: u8,
}

impl ip_addr_t {
    pub fn into_addr(self) -> Option<IpAddr> {
        match self.version {
            IPADDR_TYPE_V6 => Some(IpAddr::V6(self.addr.into())),
            IPADDR_TYPE_V4 => Some(IpAddr::V4((ip4_addr_t { addr: self.addr.addr[0] }).into())),
            _ => None
        }
    }

    pub fn localhost() -> ip_addr_t {
        ip_addr_t {
            addr: ip6_addr_t { addr: [0, 0, 0, 1] },
            version: IPADDR_TYPE_V6
        }
    }
}

impl From<IpAddr> for ip_addr_t {
    fn from(addr: IpAddr) -> ip_addr_t {
        ip_addr_t::from(&addr)
    }
}

impl<'a> From<&'a IpAddr> for ip_addr_t {
    fn from(addr: &IpAddr) -> ip_addr_t {
        match addr {
            &IpAddr::V4(ref a) => {
                ip_addr_t {
                    addr: ip6_addr_t { addr: [ip4_addr_t::from(a).addr, 0, 0, 0] },
                    version: IPADDR_TYPE_V4
                }
            }
            &IpAddr::V6(ref a) => {
                ip_addr_t {
                    addr: ip6_addr_t::from(a),
                    version: IPADDR_TYPE_V6
                }
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ip4_addr_t {
    addr: u32,
}

impl From<Ipv4Addr> for ip4_addr_t {
    fn from(addr: Ipv4Addr) -> ip4_addr_t {
        ip4_addr_t::from(&addr)
    }
}

impl<'a> From<&'a Ipv4Addr> for ip4_addr_t {
    fn from(addr: &Ipv4Addr) -> ip4_addr_t {
        ip4_addr_t { addr: NativeEndian::read_u32(&addr.octets()) }
    }
}

impl Into<Ipv4Addr> for ip4_addr_t {
    fn into(self) -> Ipv4Addr {
        (&self).into()
    }
}

impl<'a> Into<Ipv4Addr> for &'a ip4_addr_t {
    fn into(self) -> Ipv4Addr {
        let mut buf = [0; 4];
        NativeEndian::write_u32(&mut buf, self.addr);
        Ipv4Addr::from(buf)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ip6_addr_t {
    addr: [u32; 4],
}

impl From<Ipv6Addr> for ip6_addr_t {
    fn from(addr: Ipv6Addr) -> ip6_addr_t {
        ip6_addr_t::from(&addr)
    }
}

impl<'a> From<&'a Ipv6Addr> for ip6_addr_t {
    fn from(addr: &Ipv6Addr) -> ip6_addr_t {
        let octets = addr.octets();
        ip6_addr_t { addr: [NetworkEndian::read_u32(&octets[0..4]),
                            NetworkEndian::read_u32(&octets[4..8]),
                            NetworkEndian::read_u32(&octets[8..12]),
                            NetworkEndian::read_u32(&octets[12..16])] }
    }
}

impl Into<Ipv6Addr> for ip6_addr_t {
    fn into(self) -> Ipv6Addr {
        (&self).into()
    }
}

impl<'a> Into<Ipv6Addr> for &'a ip6_addr_t {
    fn into(self) -> Ipv6Addr {
        let mut octets = [0; 16];
        NetworkEndian::write_u32(&mut octets[0..4], self.addr[0]);
        NetworkEndian::write_u32(&mut octets[4..8], self.addr[1]);
        NetworkEndian::write_u32(&mut octets[8..12], self.addr[2]);
        NetworkEndian::write_u32(&mut octets[12..16], self.addr[3]);
        Ipv6Addr::from(octets)
    }
}
