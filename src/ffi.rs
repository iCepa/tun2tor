//! A module exposing a C FFI for `tun2tor`.
//!
//! The `ffi` module exposes the functionality of the `tunif` module as a
//! number of C functions
#![deny(missing_docs)]
#![allow(unsafe_code)]
#![allow(dead_code)]

use std::mem;
use std::slice;
use std::sync::{Arc, Mutex};
use libc::{c_void, size_t};

use tunif::{TunIf, PktHandler};

/// Creates a new tunnel interface and returns a pointer to it
/// ```c
/// tunif *interface = tunif_new();
/// ```
#[no_mangle]
pub unsafe extern "C" fn tunif_new() -> *mut Arc<Mutex<TunIf>> {
    Box::into_raw(Box::new(Arc::new(Mutex::new(TunIf::new()))))
}

/// Frees an existing tunnel interface
#[no_mangle]
pub unsafe extern "C" fn tunif_free(tunif: *mut Arc<Mutex<TunIf>>) {
    let tunif = Box::from_raw(tunif);
    (*tunif).set_packet_callback(None);
    drop(tunif);
}

/// Sends a packet to the given tunnel interface
#[no_mangle]
pub unsafe extern "C" fn tunif_input_packet(tunif: *mut Arc<Mutex<TunIf>>,
                                            buffer: *const c_void,
                                            len: usize) {
    let packet = slice::from_raw_parts(buffer as *const u8, len);
    (*tunif).input_packet(packet);
}

/// Sets a callback to be called every time a packet
/// is received over the interface
#[no_mangle]
pub unsafe extern "C" fn tunif_set_packet_callback(tunif: *mut Arc<Mutex<TunIf>>,
                                                   context: *mut c_void,
                                                   cb: Option<extern "C" fn(*mut Arc<Mutex<TunIf>>, *mut c_void, *const c_void, size_t) -> c_void>) {
    let ptr: usize = mem::transmute(tunif);
    let context: usize = mem::transmute(context);
    (*tunif).set_packet_callback(match cb {
        Some(cb) => Some(Box::new(move |packet| {
            let tunif: *mut Arc<Mutex<TunIf>> = mem::transmute(ptr);
            let context: *mut c_void = mem::transmute(context);
            let bytes: *const c_void = mem::transmute(&packet[0]);
            let len = packet.len() as size_t;
            cb(tunif, context, bytes, len);
        })),
        _ => None,
    });
}
