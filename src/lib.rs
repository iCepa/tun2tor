#![deny(unsafe_code,
        dead_code,
        unstable_features,
        unused_extern_crates,
        unused_imports,
        unused_features,
        unused_assignments,
        unused_variables,
        unused_import_braces,
        unused_qualifications,
        warnings,
        missing_debug_implementations,
        trivial_casts,
        trivial_numeric_casts)]
#![allow(dead_code,
         unused_imports,
         unused_variables,
         missing_debug_implementations)]

extern crate libc;
extern crate rand;
extern crate socks;

pub mod packet;
pub mod tunif;
pub mod ffi;
