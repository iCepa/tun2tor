#![deny(unsafe_code,
        unstable_features,
        unused_extern_crates,
        unused_import_braces,
        unused_qualifications,
        warnings,
        missing_debug_implementations,
        trivial_casts,
        trivial_numeric_casts)]

extern crate libc;
extern crate mio;

#[macro_use]
mod result;
mod packet;
mod ip;
mod udp;
mod tcp;
mod tunif;
pub mod ffi;

pub use result::{Result, Error};
pub use tunif::TunIf;
