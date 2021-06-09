use crate::error::err_t;

use std::io;
use std::os::raw::c_void;


// Consts and enums copied from lwip/src/include/lwip/pbuf.h.

/// Indicates that the payload directly follows the struct pbuf.
/// This makes @ref pbuf_header work in both directions.
const PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS: i32 = 0x80;

/// Indicates the data stored in this pbuf can change. If this pbuf needs
/// to be queued, it must be copied/duplicated.
const PBUF_TYPE_FLAG_DATA_VOLATILE: i32 = 0x40;

/// Indicates this pbuf is used for RX (if not set, indicates use for TX).
/// This information can be used to keep some spare RX buffers e.g. for
/// receiving TCP ACKs to unblock a connection)
const PBUF_ALLOC_FLAG_RX: i32 = 0x0100;

/// Indicates the application needs the pbuf payload to be in one piece
const PBUF_ALLOC_FLAG_DATA_CONTIGUOUS: i32 = 0x0200;

const PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP: i32 = 0x00;

const PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF: i32 = 0x01;

const PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL: i32 = 0x02;

/// Enumeration of pbuf types
#[repr(i32)]
#[allow(dead_code)]
#[derive(Debug)]
pub enum pbuf_type {
    /// pbuf data is stored in RAM, used for TX mostly, struct pbuf and its payload
    /// are allocated in one piece of contiguous memory (so the first payload byte
    /// can be calculated from struct pbuf).
    /// pbuf_alloc() allocates PBUF_RAM pbufs as unchained pbufs (although that might
    /// change in future versions).
    /// This should be used for all OUTGOING packets (TX).
    PBUF_RAM = (PBUF_ALLOC_FLAG_DATA_CONTIGUOUS | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP),

    /// pbuf data is stored in ROM, i.e. struct pbuf and its payload are located in
    /// totally different memory areas. Since it points to ROM, payload does not
    /// have to be copied when queued for transmission.
    PBUF_ROM = PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF,

    /// pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change
    /// so it has to be duplicated when queued before transmitting, depending on
    /// who has a 'ref' to it.
    PBUF_REF = (PBUF_TYPE_FLAG_DATA_VOLATILE | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF),

    /// pbuf payload refers to RAM. This one comes from a pool and should be used
    /// for RX. Payload can be chained (scatter-gather RX) but like PBUF_RAM, struct
    /// pbuf and its payload are allocated in one piece of contiguous memory (so
    /// the first payload byte can be calculated from struct pbuf).
    /// Don't use this for TX, if the pool becomes empty e.g. because of TCP queuing,
    /// you are unable to receive TCP acks! */
    PBUF_POOL = (PBUF_ALLOC_FLAG_RX | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL)
}

const PBUF_TRANSPORT_HLEN: i32 = 20;

const PBUF_IP_HLEN: i32 = 40;

/// PBUF_LINK_ENCAPSULATION_HLEN: the number of bytes that should be allocated
/// for an additional encapsulation header before ethernet headers (e.g. 802.11)
const PBUF_LINK_ENCAPSULATION_HLEN: i32 = 0;

/// PBUF_LINK_HLEN: the number of bytes that should be allocated for a
/// link level header. The default is 14, the standard value for Ethernet.
const PBUF_LINK_HLEN: i32 = 14;


/// Enumeration of pbuf layers
#[repr(i32)]
#[allow(dead_code)]
#[derive(Debug)]
pub enum pbuf_layer {
    /// Includes spare room for transport layer header, e.g. UDP header.
    /// Use this if you intend to pass the pbuf to functions like udp_send().
    PBUF_TRANSPORT = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN + PBUF_TRANSPORT_HLEN,

    /// Includes spare room for IP header.
    /// Use this if you intend to pass the pbuf to functions like raw_send().
    PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN,

    /// Includes spare room for link layer header (ethernet header).
    /// Use this if you intend to pass the pbuf to functions like ethernet_output().
    PBUF_LINK = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN,

    /// Includes spare room for additional encapsulation header before ethernet
    /// headers (e.g. 802.11).
    /// Use this if you intend to pass the pbuf to functions like netif->linkoutput().
    PBUF_RAW_TX = PBUF_LINK_ENCAPSULATION_HLEN,

    // Use this for input packets in a netif driver when calling netif->input()
    // in the most common case - ethernet-layer netif driver.
    // Rust doesn't allow enums with the same value. Disabled, not needed anyway.
    // PBUF_RAW = 0
}

#[repr(C)]
#[derive(Debug)]
pub struct pbuf {
    pub next: *mut pbuf,
    pub payload: *mut c_void,
    pub tot_len: u16,
    pub len: u16,
    pub pbuf_type: u8,
    pub flags: u8,
    pub pbuf_ref: u8,
    pub if_idx: u8,
}

pub trait Pbuf {
    unsafe fn into_pbuf(buf: Self) -> *mut pbuf;
    unsafe fn from_pbuf(pbuf: *mut pbuf) -> Self;
}

impl Pbuf for Box<[u8]> {
    unsafe fn into_pbuf(buf: Box<[u8]>) -> *mut pbuf {
        let p = pbuf_alloc(pbuf_layer::PBUF_IP, buf.len() as u16, pbuf_type::PBUF_RAM);
        let result: io::Result<()> = pbuf_take(p,
                                               buf.as_ref() as *const _ as *const c_void,
                                               buf.len() as u16)
            .into();
        result.unwrap();
        p
    }

    unsafe fn from_pbuf(pbuf: *mut pbuf) -> Box<[u8]> {
        let mut buf = vec![0; (&mut *pbuf).tot_len as usize];
        let len =
            pbuf_copy_partial(pbuf, buf.as_mut_ptr() as *mut c_void, buf.len() as u16, 0) as usize;

        // FIXME(ahf): We seem to never hit the right size here? Do we really need to truncate?
        buf.truncate(len);
        buf.into_boxed_slice()
    }
}

#[link(name = "lwip", kind = "static")]
extern "C" {
    pub fn pbuf_alloc(layer: pbuf_layer, length: u16, pbuf_type: pbuf_type) -> *mut pbuf;
    pub fn pbuf_free(p: *mut pbuf) -> u8;

    pub fn pbuf_copy_partial(p: *const pbuf, dataptr: *mut c_void, len: u16, offset: u16) -> u16;
    pub fn pbuf_take(buf: *mut pbuf, dataptr: *const c_void, len: u16) -> err_t;
    pub fn pbuf_chain(h: *mut pbuf, y: *mut pbuf);
    pub fn pbuf_dechain(h: *mut pbuf) -> *mut pbuf;

    pub fn pbuf_header(p: *mut pbuf, header_size_increment: i16);
}
