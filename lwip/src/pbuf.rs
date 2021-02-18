use std::io;
use std::os::raw::c_void;

use error::err_t;

#[repr(i32)]
#[allow(dead_code)]
#[derive(Debug)]
pub enum pbuf_type {
    PBUF_RAM = 0,
    PBUF_ROM = 1,
    PBUF_REF = 2,
    PBUF_POOL = 3,
}

#[repr(i32)]
#[allow(dead_code)]
#[derive(Debug)]
pub enum pbuf_layer {
    PBUF_TRANSPORT = 0,
    PBUF_IP = 1,
    PBUF_LINK = 2,
    PBUF_RAW_TX = 3,
    PBUF_RAW = 4,
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
    pub pbuf_ref: u16,
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
