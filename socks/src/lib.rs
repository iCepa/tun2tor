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

mod result;
mod version;
mod address;
mod command;
mod auth;
mod request;
mod response;
mod connect;

pub use result::{Result, Error};
pub use version::Version;
pub use address::Address;
pub use command::Command;
pub use auth::AuthMethod;
pub use connect::Connect;
