pub use libc::{c_void, c_char, int8_t, uint8_t, uint16_t, uint32_t};

use std::ptr;

const NETIF_MAX_HWADDR_LEN: usize = 6;

#[repr(C)]
pub struct netif {
    next: *mut netif,
    ip_addr: ip_addr_t,
    netmask: ip_addr_t,
    gw: ip_addr_t,
    ip6_addr: [ip6_addr_t; 3],
    ip6_addr_state: [uint8_t; 3],
    input: Option<netif_input_fn>,
    output: Option<netif_output_fn>,
    output_ip6: Option<netif_output_ip6_fn>,
    pub state: *mut c_void,
    ip6_autoconfig_enabled: uint8_t,
    rs_count: uint8_t,
    mtu: uint16_t,
    hwaddr_len: uint8_t,
    hwaddr: [uint8_t; NETIF_MAX_HWADDR_LEN],
    flags: uint8_t,
    name: [c_char; 2],
    num: uint8_t,
    mld_mac_filter: Option<netif_mld_mac_filter_fn>,
}

impl Default for netif {
    fn default() -> netif {
        netif {
            next: ptr::null_mut(),
            ip_addr: 0,
            netmask: 0,
            gw: 0,
            ip6_addr: [[0,0,0,0]; 3],
            ip6_addr_state: [0,0,0],
            input: None,
            output: None,
            output_ip6: None,
            state: ptr::null_mut(),
            ip6_autoconfig_enabled: 0,
            rs_count: 0,
            mtu: 0,
            hwaddr_len: 0,
            hwaddr: [0; NETIF_MAX_HWADDR_LEN],
            flags: 0,
            name: [0; 2],
            num: 0,
            mld_mac_filter: None,
        }
    }
}

pub type err_t = int8_t;
pub type ip_addr_t = uint32_t;
pub type ip6_addr_t = [uint32_t; 4];

pub type netif_init_fn = extern "C" fn(netif: *mut netif) -> err_t;
pub type netif_input_fn = extern "C" fn(p: *mut c_void, inp: *mut netif) -> err_t;
pub type netif_output_fn = extern "C" fn(netif: *mut netif, p: *mut c_void, ipaddr: *mut ip_addr_t) -> err_t;
pub type netif_output_ip6_fn = extern "C" fn(netif: *mut netif, p: *mut c_void, ipaddr: *mut ip6_addr_t) -> err_t;
pub type netif_mld_mac_filter_fn = extern "C" fn(netif: *mut netif, group: *mut ip_addr_t, action: uint8_t) -> err_t;

extern "C" {
    pub fn lwip_init() -> c_void;

    pub fn netif_add(netif: *mut netif, addr: *mut ip_addr_t, netmask: *mut ip_addr_t, gw: *mut ip_addr_t, state: *mut c_void, init_fn: netif_init_fn, input_fn: netif_input_fn) -> *mut netif;
    pub fn netif_remove(netif: *mut netif) -> c_void;
    pub fn netif_set_default(netif: *mut netif) -> c_void;
    pub fn netif_set_up(netif: *mut netif) -> c_void;
    pub fn netif_set_down(netif: *mut netif) -> c_void;
}

