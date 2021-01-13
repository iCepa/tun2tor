use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::raw::{c_void, c_char};
use std::mem;
use std::collections::VecDeque;

use futures::{Stream, Sink, Poll, Async, AsyncSink, StartSend};
use futures::task::{self, Task};

use addr::{ip_addr_t, ip4_addr_t, ip6_addr_t};
use error::{err_t};
use pbuf::{pbuf, Pbuf};

fn netif_common_output(netif: *mut netif, p: *mut pbuf, ipaddr: IpAddr) -> err_t {
    unsafe {
        let netif: &mut NetIf = &mut *((&mut *netif).state as *mut NetIf);
        netif.queue.push_back((Box::from_pbuf(p), ipaddr));
        if let Some(ref task) = netif.read_task {
            task.notify();
        }
    }
    err_t::ERR_OK
}

extern "C" fn netif_output(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t {
    netif_common_output(netif, p, unsafe{ IpAddr::V4((&*ipaddr).into()) })
}

extern "C" fn netif_output_ip6(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip6_addr_t) -> err_t {
    netif_common_output(netif, p, unsafe { IpAddr::V6((&*ipaddr).into()) })
}

extern "C" fn netif_init(netif: *mut netif) -> err_t {
    unsafe {
        let netif_ref = &mut *netif;
        netif_ref.output = netif_output;
        netif_ref.output_ip6 = netif_output_ip6;
        netif_set_up(netif);
    }
    err_t::ERR_OK
}

#[derive(Debug)]
pub struct NetIf {
    inner: netif,
    read_task: Option<Task>,
    queue: VecDeque<(Box<[u8]>, IpAddr)>
}

impl NetIf {
    pub fn add(addr: Ipv4Addr, netmask: Ipv4Addr, gw: Ipv4Addr) -> Box<NetIf> {
        ::lwip_init();
        let inner = unsafe {
            mem::zeroed()
        };
        let mut netif = Box::new(NetIf { inner: inner, read_task: None, queue: VecDeque::new() });
        let (addr, netmask, gw) = (ip4_addr_t::from(addr), ip4_addr_t::from(netmask), ip4_addr_t::from(gw));
        unsafe { netif_add(&mut netif.inner, &addr, &netmask, &gw, netif.as_mut() as *mut NetIf as *mut _, netif_init, netif_input); }
        netif
    }
}

impl Sink for NetIf {
    type SinkItem = Box<[u8]>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Box<[u8]>) -> StartSend<Box<[u8]>, io::Error> {
        unsafe {
            let input = self.inner.input;
            let result: io::Result<()> = input(Box::into_pbuf(item), &mut self.inner).into();
            result.map(|_| AsyncSink::Ready)
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        Ok(Async::Ready(()))
    }
}

impl Stream for NetIf {
    type Item = (Box<[u8]>, IpAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<(Box<[u8]>, IpAddr)>, io::Error> {
        if self.read_task.is_none() {
            self.read_task = Some(task::current());
        }
        self.queue.pop_front()
            .map(|s| Ok(Async::Ready(Some(s))))
            .unwrap_or(Ok(Async::NotReady))
    }
}

impl Drop for NetIf {
    fn drop(&mut self) {
        unsafe { netif_remove(&mut self.inner); }
    }
}

#[repr(C)]
#[derive(Debug)]
struct netif {
    next: *mut netif,
    ip_addr: ip_addr_t,
    netmask: ip_addr_t,
    gw: ip_addr_t,
    ip6_addr: [ip_addr_t; 3],
    ip6_addr_state: [u8; 3],
    input: netif_input_fn,
    output: netif_output_fn,
    linkoutput: netif_linkoutput_fn,
    output_ip6: netif_output_ip6_fn,
    state: *mut c_void,
    ip6_autoconfig_enabled: u8,
    mtu: u16,
    hwaddr_len: u8,
    hwaddr: [u8; NETIF_MAX_HWADDR_LEN],
    flags: u8,
    name: [c_char; 2],
    num: u8,
}

const NETIF_MAX_HWADDR_LEN: usize = 6;

type netif_input_fn = unsafe extern "C" fn(p: *mut pbuf, inp: *mut netif) -> err_t;
type netif_output_fn = extern "C" fn(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t;
type netif_linkoutput_fn = extern "C" fn(netif: *mut netif, p: *mut pbuf) -> err_t;
type netif_output_ip6_fn = extern "C" fn(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip6_addr_t) -> err_t;
type netif_init_fn = extern "C" fn(netif: *mut netif) -> err_t;

#[link(name = "lwip", kind = "static")]
extern "C" {
    fn netif_add(netif: *mut netif, ipaddr: *const ip4_addr_t, netmask: *const ip4_addr_t, gw: *const ip4_addr_t, state: *mut c_void, init: netif_init_fn, input: netif_input_fn) -> *mut netif;
    fn netif_remove(netif: *mut netif);
    fn netif_set_up(netif: *mut netif);
    fn netif_input(p: *mut pbuf, inp: *mut netif) -> err_t;
}
