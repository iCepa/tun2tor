//! A module exposing a C FFI for `tun2tor`.
//!
//! The `ffi` module exposes the functionality of the `tunif` module as a
//! number of C functions
#![deny(missing_docs)]
#![allow(unsafe_code)]

use std::net::IpAddr;
use std::mem;
use std::slice;
use std::sync::Arc;
use std::ptr;
use libc::{c_void, uint8_t, size_t, AF_INET, AF_INET6};

use tunif::TunIf;

macro_rules! try_log {
    ($expr:expr) => (match $expr {
        Ok(val) => val,
        Err(err) => {
            println!("Error: {:}", err);
            return;
        }
    })
}

/// A callback that is called every time a packet
/// is received over the interface
pub type TunIfCallback = extern "C" fn(*mut c_void, *const c_void, size_t, uint8_t) -> c_void;

/// Creates a new tunnel interface and returns a pointer to it
/// ```c
/// tunif *interface = tunif_new();
/// ```
#[no_mangle]
pub unsafe extern "C" fn tunif_new(context: *mut c_void,
                                   callback: Option<TunIfCallback>)
                                   -> *mut TunIf {
    let context: usize = mem::transmute(context);
    if let Some(cb) = callback {
        cb(ptr::null_mut(), ptr::null(), 0, AF_INET as uint8_t);
    }
    match callback {
        Some(callback) => {
            let callback = Arc::new(move |packet: Vec<u8>, hint: IpAddr| {
                let slice = packet.into_boxed_slice();
                let len = slice.len();
                let ptr = Box::into_raw(slice) as *const c_void;
                let context: *mut c_void = mem::transmute(context);
                let proto = match hint {
                    IpAddr::V4(_a) => AF_INET as uint8_t,
                    IpAddr::V6(_a) => AF_INET6 as uint8_t,
                };
                callback(context, ptr, len, proto);
            });
            Box::into_raw(Box::new(TunIf::new(callback)))
        }
        None => ptr::null_mut(),
    }
}

/// Frees an existing tunnel interface
#[no_mangle]
pub unsafe extern "C" fn tunif_free(tunif: *mut TunIf) {
    drop(Box::from_raw(tunif))
}

/// Sends a packet to the given tunnel interface
#[no_mangle]
pub unsafe extern "C" fn tunif_input_packet(tunif: *mut TunIf,
                                            buffer: *const c_void,
                                            len: size_t) {
    let packet = slice::from_raw_parts(buffer as *const u8, len);
    try_log!((*tunif).input_packet(packet));
}
