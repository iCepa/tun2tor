#![allow(non_camel_case_types)]

mod error;
mod addr;
mod pbuf;
pub mod netif;
pub mod tcp;

fn lwip_init() {
    use std::sync::Once;

    #[link(name = "lwip", kind = "static")]
    extern "C" {
        fn lwip_init();
    }

    static LWIP_INIT: Once = Once::new();
    LWIP_INIT.call_once(|| unsafe { lwip_init() });
}
