//! A module exposing a C FFI for `tun2tor`.
//!
//! The `ffi` module exposes the functionality of the `tunif` module as a
//! number of C functions
#![allow(unsafe_code)]
#![deny(missing_docs)]

use std::mem;
use std::slice;
use libc::c_void;

use tunif::TunIf;

/// Creates a new tunnel interface and returns a pointer to it
/// ```c
/// tunif *interface = tunif_new();
/// ```
#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn tunif_new() -> *mut TunIf {
    let ptr: *mut TunIf = mem::transmute(Box::new(TunIf::new()));
    ptr
}

/// Frees an existing tunnel interface
#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn tunif_free(tunif: *mut TunIf) {
    let tunif: Box<TunIf> = mem::transmute(tunif);
    drop(tunif)
}

/// Sends a packet to the given tunnel interface
#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn tunif_input_packet(tunif: *mut TunIf, buffer: *const c_void, len: usize) {
    let packet = slice::from_raw_parts(buffer as *const u8, len);
    (*tunif).input_packet(packet);
}
