use std::mem;
use std::slice;
use libc::c_void;

use tunif::TunIf;

#[no_mangle]
#[allow(dead_code)]
pub extern "C" fn tunif_new() -> *mut TunIf {
    unsafe {
        let ptr: *mut TunIf = mem::transmute(Box::new(TunIf::new()));
        ptr
    }
}

#[no_mangle]
#[allow(dead_code)]
pub extern "C" fn tunif_free(tunif: *mut TunIf) {
    unsafe {
        let tunif: Box<TunIf> = mem::transmute(tunif);
        drop(tunif)
    }
}

#[no_mangle]
#[allow(dead_code)]
pub extern "C" fn tunif_input_packet(tunif: *mut TunIf, buffer: *const c_void, len: usize) {
    unsafe {
        let packet = slice::from_raw_parts(buffer as *const u8, len);
        (*tunif).input_packet(packet);
    }
}
