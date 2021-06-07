use crate::addr::{ip_addr_t, ip4_addr_t, ip6_addr_t};
use crate::error::{err_t};
use crate::pbuf::{pbuf, Pbuf};
use crate::lwip_init;

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::raw::{c_void, c_char};
use std::ptr::null_mut;

use futures::{Stream, Sink, Poll, Async, AsyncSink, StartSend};
use futures::task::{self, Task};

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

unsafe extern "C" fn input_noop(_var1: *mut pbuf, _var2: *mut netif) -> err_t {
    err_t::ERR_OK
}

extern "C" fn linkoutput_noop(_var1: *mut netif, _var2: *mut pbuf) -> err_t {
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
        lwip_init();

        let inner = netif {
            next: null_mut(),
            ip_addr: ip_addr_t::localhost(),
            netmask: ip_addr_t::localhost(),
            gw: ip_addr_t::localhost(),
            ip6_addr: [ip_addr_t::localhost(), ip_addr_t::localhost(), ip_addr_t::localhost()],
            ip6_addr_state: [0, 0, 0],
            input: input_noop,
            output: netif_output,
            linkoutput: linkoutput_noop,
            output_ip6: netif_output_ip6,
            state: null_mut(),
            ip6_autoconfig_enabled: 0,
            mtu: 0,
            hwaddr_len: 0,
            hwaddr: [0, 0, 0, 0, 0, 0],
            flags: 0,
            name: [0, 0],
            num: 0
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
            // FIXME(ahf) 2021/01/27: Can we find a way to avoid converting this to/from our [u8]
            // into the LwIP internal pbuf? We spend quite some time (and twice the memory) when
            // converting back and forward?
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
