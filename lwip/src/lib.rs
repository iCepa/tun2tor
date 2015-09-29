extern crate libc;

#[allow(dead_code, non_camel_case_types)]
mod ffi;

use ffi::*;
use std::net::Ipv4Addr;

trait IpAddrT {
    fn ip_addr(&self) -> ip_addr_t;
}

impl IpAddrT for Ipv4Addr {
    fn ip_addr(&self) -> ip_addr_t {
        let octets = self.octets();
        ((octets[0] as u32) << 24 | (octets[1] as u32) << 16 | (octets[2] as u32) << 8 | octets[3] as u32)
    }
}

#[derive(Default)]
pub struct NetworkInterface {
    netif: netif,
}

extern "C" fn init_fn(netif: *mut netif) -> err_t {
    let interface = unsafe { &mut *((&mut *netif).state as *mut NetworkInterface) };
    match interface.init() {
        Ok(t) => 0,
        Err(e) => 1
    }
}

extern "C" fn input_fn(p: *mut c_void, netif: *mut netif) -> err_t {
    let interface = unsafe { &mut *((&mut *netif).state as *mut NetworkInterface) };
    match interface.input(p) {
        Ok(t) => 0,
        Err(e) => 1
    }
}

impl NetworkInterface {
    pub fn add(addr: Ipv4Addr, netmask: Ipv4Addr, gw: Ipv4Addr) -> NetworkInterface {
        let mut interface = NetworkInterface::default();
        unsafe { netif_add(&mut interface.netif, &mut addr.ip_addr(), &mut netmask.ip_addr(), &mut gw.ip_addr(), &mut interface as *mut _ as *mut c_void, init_fn, input_fn); }
        interface
    }

    pub fn set_default(&mut self) {
        unsafe { netif_set_default(&mut self.netif); }
    }

    pub fn set_up(&mut self) {
        unsafe { netif_set_up(&mut self.netif); }
    }

    pub fn set_down(&mut self) {
        unsafe { netif_set_down(&mut self.netif); }
    }

    pub fn set_pretend_tcp(&mut self, pretend: bool) {
        unsafe { netif_set_pretend_tcp(&mut self.netif, pretend ? 1 : 0); }
    }

    fn init(&self) -> Result<(), ()> {
        Ok(())
    }

    fn input(&self, p: *mut c_void) -> Result<(), ()>  {
        Ok(())
    }
}

impl Drop for NetworkInterface {
    fn drop(&mut self) {
        unsafe { netif_remove(&mut self.netif); }
    }
}

pub fn init() {
    unsafe { lwip_init(); }
}
    // unsafe {
    // // init netif
 //    if (!netif_add(&the_netif, &addr, &netmask, &gw, NULL, netif_init_func, netif_input_func)) {
 //        BLog(BLOG_ERROR, "netif_add failed");
 //        goto fail;
 //    }
 //    have_netif = 1;
    
 //    // set netif up
 //    netif_set_up(&the_netif);
    
 //    // set netif pretend TCP
 //    netif_set_pretend_tcp(&the_netif, 1);
    
 //    // set netif default
 //    netif_set_default(&the_netif);
    //  // lwip_init();
    // }
