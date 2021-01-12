#![allow(non_camel_case_types)]

extern crate byteorder;
extern crate futures;
extern crate tokio_core;

mod error;
mod addr;
mod pbuf;
mod netif;
mod tcp;

pub use netif::NetIf;
pub use tcp::{TcpListener, TcpStream, EventedTcpStream};

fn lwip_init() {
    use std::sync::Once;

    #[link(name = "lwip", kind = "static")]
    extern "C" {
        fn lwip_init();
    }

    static LWIP_INIT: Once = Once::new();
    LWIP_INIT.call_once(|| unsafe { lwip_init() });
}
