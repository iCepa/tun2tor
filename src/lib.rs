extern crate libc;
extern crate byteorder;

use std::slice;
use std::mem;
use libc::c_void;

use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
use byteorder::{Result, LittleEndian, BigEndian, ReadBytesExt};

trait FromBytes {
	fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl FromBytes for Ipv4Addr {
	fn from_bytes(addr: &[u8]) -> Result<Ipv4Addr> {
		let mut rdr = Cursor::new(addr);
		let a = try!(rdr.read_u8());
		let b = try!(rdr.read_u8());
		let c = try!(rdr.read_u8());
		let d = try!(rdr.read_u8());
		Ok(Ipv4Addr::new(a, b, c, d))
	}
}

impl FromBytes for Ipv6Addr {
	fn from_bytes(addr: &[u8]) -> Result<Ipv6Addr> {
		let mut rdr = Cursor::new(addr);
		let a = try!(rdr.read_u16::<BigEndian>());
		let b = try!(rdr.read_u16::<BigEndian>());
		let c = try!(rdr.read_u16::<BigEndian>());
		let d = try!(rdr.read_u16::<BigEndian>());
		let e = try!(rdr.read_u16::<BigEndian>());
		let f = try!(rdr.read_u16::<BigEndian>());
		let g = try!(rdr.read_u16::<BigEndian>());
		let h = try!(rdr.read_u16::<BigEndian>());
		Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
	}
}

struct Ipv4Header {
	version: u8,
	hlen: usize,
	tos: u8,
	len: u16,
	id: u16,
	offset: u16,
	ttl: u8,
	proto: u8,
	chksum: u16,
	src: Ipv4Addr,
	dest: Ipv4Addr,
}

impl FromBytes for Ipv4Header {
	fn from_bytes(packet: &[u8]) -> Result<Ipv4Header> {
		let mut rdr = Cursor::new(packet);
		let v_hl = rdr.read_u8().unwrap();
		let tos = rdr.read_u8().unwrap();
		let len = rdr.read_u16::<BigEndian>().unwrap();
		let id = rdr.read_u16::<LittleEndian>().unwrap();
		let offset = rdr.read_u16::<LittleEndian>().unwrap();
		let ttl = rdr.read_u8().unwrap();
		let proto = rdr.read_u8().unwrap();
		let chksum = rdr.read_u16::<LittleEndian>().unwrap();

		let pos = rdr.position() as usize;
		let src = try!(Ipv4Addr::from_bytes(&packet[pos..pos+4]));
		let dest = try!(Ipv4Addr::from_bytes(&packet[pos+4..pos+8]));

		Ok(Ipv4Header {
		    version: (v_hl >> 4),
		    hlen: ((v_hl & 0xF) * 4) as usize,
		    tos: tos,
		    len: len,
		    id: id,
		    offset: offset,
		    ttl: ttl,
		    proto: proto,
		    chksum: chksum,
		    src: src,
		    dest: dest,
		})
	}
}

impl Ipv4Header {
	fn checksum_valid(&self) -> bool {
		let src = self.src.octets();
		let dest = self.dest.octets();
		let sum = (((self.version as u32) << 4) | ((self.hlen / 4) as u32) | (self.tos as u32) << 16) +
				  ((self.len >> 8 | self.len << 8) as u32) +
				  self.id as u32 +
				  self.offset as u32 +
				  (self.ttl as u32 | (self.proto as u32) << 8) +
				  (((src[1] as u32) << 8) | src[0] as u32) +
  				  (((src[3] as u32) << 8) | src[2] as u32) +
  				  (((dest[1] as u32) << 8) | dest[0] as u32) +
				  (((dest[3] as u32) << 8) | dest[2] as u32);
		let fold1 = (sum >> 16) + (sum & 0xFFFF);
		let fold2 = (fold1 >> 16) + (fold1 & 0xFFFF);
		let calculated = !(fold2 as u16);
		(self.chksum == calculated)
	}
}

struct Ipv6Header {
	v_tc_fl: u32,
	plen: u16,
	nexth: u8,
	hoplim: u8,
	src: Ipv6Addr,
	dest: Ipv6Addr,
}

impl FromBytes for Ipv6Header {
	fn from_bytes(packet: &[u8]) -> Result<Ipv6Header> {
		let mut rdr = Cursor::new(packet);
		let v_tc_fl = try!(rdr.read_u32::<BigEndian>());
		let plen = rdr.read_u16::<LittleEndian>().unwrap();
		let nexth = rdr.read_u8().unwrap();
		let hoplim = rdr.read_u8().unwrap();

		let pos = rdr.position() as usize;
		let src = try!(Ipv6Addr::from_bytes(&packet[pos..pos+16]));
		let dest = try!(Ipv6Addr::from_bytes(&packet[pos+16..pos+32]));

		Ok(Ipv6Header {
		    v_tc_fl: v_tc_fl,
		    plen: plen,
		    nexth: nexth,
		    hoplim: hoplim,
		    src: src,
		    dest: dest,
		})
	}
}

enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

struct TcpPcb {
	lol: u8,
}

pub struct TunIf {
	lol: u8
}

impl TunIf {
	fn new() -> TunIf {
		TunIf {
			lol: 0
		}
	}

	fn input_packet(&self, packet: &[u8]) {
		let header = match packet[0] >> 4 {
			4 => match Ipv4Header::from_bytes(packet) {
				Ok(header) => Some(IpHeader::V4(header)),
				_ => None,
			},
			6 => match Ipv6Header::from_bytes(packet) {
				Ok(header) => Some(IpHeader::V6(header)),
				_ => None,
			},
			_ => None,
		};
		match header {
			Some(IpHeader::V4(header)) => {
				if header.hlen > packet.len() {
					return println!("IP header length is greater than total packet length, packet dropped");
				}
				if header.checksum_valid() == false {
					return println!("IP header checksum is invalid, packet dropped");
				}

			},
			Some(IpHeader::V6(header)) => {
				println!("WOOHOO {:?}", header.src);
			},
			None => ()
		};
	}
}

#[no_mangle]
#[allow(dead_code)]
pub extern fn tunif_new() -> *mut TunIf {
	unsafe {
	    let ptr: *mut TunIf = mem::transmute(Box::new(TunIf::new()));
	    ptr
	}
}

#[no_mangle]
#[allow(dead_code)]
pub extern fn tunif_free(tunif: *mut TunIf) {
	unsafe {
	    let tunif: Box<TunIf> = mem::transmute(tunif);
	    drop(tunif)
	}
}

#[no_mangle]
#[allow(dead_code)]
pub extern fn tunif_input_packet(tunif: *mut TunIf, buffer: *const c_void, len: usize) {
	unsafe {
		let packet = std::slice::from_raw_parts(buffer as *const u8, len);
		(*tunif).input_packet(packet);
	}
}
