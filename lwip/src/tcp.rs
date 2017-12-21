use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::raw::c_void;
use std::ptr;

use futures::{Stream, Poll, Async};
use futures::task::{self, Task};

use addr::ip_addr_t;
use error::err_t;
use pbuf::{pbuf, pbuf_chain, pbuf_dechain, pbuf_free, pbuf_header};

#[derive(Debug)]
struct TcpPcb(*mut tcp_pcb);

impl TcpPcb {
    fn new() -> TcpPcb {
        ::lwip_init();
        TcpPcb(unsafe { tcp_new() })
    }

    fn bind(&mut self, addr: &SocketAddr) -> io::Result<()> {
        let ip = ip_addr_t::from(addr.ip());
        let err = unsafe { tcp_bind(self.0, &ip, addr.port()) };
        err.into()
    }

    fn listen(&mut self, backlog: u8) {
        self.0 = unsafe { tcp_listen_with_backlog(self.0, backlog) };
    }

    fn local(&self) -> Option<SocketAddr> {
        unsafe {
            let pcb = &*self.0;
            let ip = pcb.local_ip.into_addr();
            ip.map(|ip| SocketAddr::new(ip, pcb.local_port))
        }
    }
}

impl Drop for TcpPcb {
    fn drop(&mut self) {
        unsafe {
            tcp_close(self.0);
        }
    }
}

extern "C" fn listener_accept(arg: *mut c_void, newpcb: *mut tcp_pcb, err: err_t) -> err_t {
    let result: io::Result<()> = err.into();
    unsafe {
        let listener: &mut TcpListener = &mut *(arg as *mut TcpListener);
        listener.queue.push_back(result.and_then(|_| TcpStream::new(newpcb)));
        if let Some(ref task) = listener.task {
            task.notify();
        }
    }
    err_t::ERR_OK
}

#[derive(Debug)]
pub struct TcpListener {
    pcb: TcpPcb,
    task: Option<Task>,
    queue: VecDeque<io::Result<Box<TcpStream>>>,
}

impl TcpListener {
    pub fn bind(addr: &SocketAddr) -> io::Result<Box<TcpListener>> {
        let mut pcb = TcpPcb::new();
        pcb.bind(addr)?;
        pcb.listen(TCP_DEFAULT_LISTEN_BACKLOG);
        let mut listener = Box::new(TcpListener {
            pcb: pcb,
            task: None,
            queue: VecDeque::new(),
        });
        unsafe {
            let arg = &mut *listener as *mut _ as *mut c_void;
            tcp_arg(listener.pcb.0, arg);
            tcp_accept(listener.pcb.0, listener_accept);
        }
        Ok(listener)
    }
}

impl Stream for TcpListener {
    type Item = Box<TcpStream>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Box<TcpStream>>, io::Error> {
        if self.task.is_none() {
            self.task = Some(task::current());
        }
        match self.queue.pop_front() {
            Some(Ok(s)) => Ok(Async::Ready(Some(s))),
            Some(Err(e)) => Err(e),
            None => Ok(Async::NotReady),
        }
    }
}

extern "C" fn stream_recv(arg: *mut c_void,
                          _tpcb: *mut tcp_pcb,
                          p: *mut pbuf,
                          _err: err_t)
                          -> err_t {
    unsafe {
        // TODO: Pass err_t through
        let stream: &mut TcpStream = &mut *(arg as *mut TcpStream);
        if p.is_null() {
            return err_t::ERR_OK;
        }
        if stream.buf.is_null() {
            stream.buf = p;
        } else {
            pbuf_chain(stream.buf, p);
        }
        if let Some(ref task) = stream.read_task {
            task.notify();
        }
        err_t::ERR_OK
    }
}

extern "C" fn stream_sent(arg: *mut c_void, _tpcb: *mut tcp_pcb, _len: u16) -> err_t {
    unsafe {
        let stream: &mut TcpStream = &mut *(arg as *mut TcpStream);
        if let Some(ref task) = stream.write_task {
            task.notify();
        }
        err_t::ERR_OK
    }
}

#[derive(Debug)]
pub struct TcpStream {
    pcb: TcpPcb,
    read_task: Option<Task>,
    write_task: Option<Task>,
    buf: *mut pbuf,
}

impl TcpStream {
    fn new(pcb: *mut tcp_pcb) -> io::Result<Box<TcpStream>> {
        let mut stream = Box::new(TcpStream {
            pcb: TcpPcb(pcb),
            read_task: None,
            write_task: None,
            buf: ptr::null_mut(),
        });
        unsafe {
            let arg = &mut *stream as *mut _ as *mut c_void;
            tcp_arg(stream.pcb.0, arg);
            tcp_recv(stream.pcb.0, stream_recv);
            tcp_sent(stream.pcb.0, stream_sent);
        }
        Ok(stream)
    }

    pub fn local(&self) -> Option<SocketAddr> {
        self.pcb.local()
    }

    pub fn remote(&self) -> Option<SocketAddr> {
        unsafe {
            let pcb = &*self.pcb.0;
            let ip = pcb.remote_ip.into_addr();
            ip.map(|ip| SocketAddr::new(ip, pcb.remote_port))
        }
    }

    pub fn poll_read(&mut self) -> Async<()> {
        if self.read_task.is_none() {
            self.read_task = Some(task::current());
        }
        if self.buf.is_null() {
            Async::NotReady
        } else {
            Async::Ready(())
        }
    }

    pub fn poll_write(&mut self) -> Async<()> {
        if self.write_task.is_none() {
            self.write_task = Some(task::current());
        }
        let snd_buf = unsafe { (&*self.pcb.0).snd_buf };
        if snd_buf > 0 {
            Async::Ready(())
        } else {
            Async::NotReady
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let tot_len = dst.len() as u16;
        let mut offset = 0;
        unsafe {
            while let Some(current) = self.buf.as_mut() {
                let remaining = tot_len - offset;
                let len = if remaining > current.len {
                    current.len
                } else {
                    remaining
                };
                if len == 0 {
                    break;
                }

                ptr::copy_nonoverlapping(current.payload,
                                         (&mut dst[offset as usize..]).as_mut_ptr() as *mut _,
                                         len as usize);
                offset += len;

                if len == current.len {
                    self.buf = pbuf_dechain(current);
                    pbuf_free(current);
                } else {
                    pbuf_header(current, -(len as i16));
                    break;
                }
            }
        }
        unsafe {
            tcp_recved(self.pcb.0, offset);
        }
        Ok(offset as usize)
    }
}

impl Write for TcpStream {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        let snd_buf = unsafe { (&*self.pcb.0).snd_buf };
        let len = src.len() as u16;
        let len = if len > snd_buf { snd_buf } else { len };
        let result: io::Result<()> = unsafe {
            tcp_write(self.pcb.0,
                      src.as_ptr() as *const _,
                      len,
                      TCP_WRITE_FLAG_COPY)
                .into()
        };
        result.map(|_| len as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe { tcp_output(self.pcb.0).into() }
    }
}

pub struct EventedTcpStream {
    inner: Box<TcpStream>,
}

impl EventedTcpStream {
    pub fn new(stream: Box<TcpStream>) -> EventedTcpStream {
        EventedTcpStream { inner: stream }
    }

    pub fn poll_read(&mut self) -> Async<()> {
        self.inner.poll_read()
    }

    pub fn poll_write(&mut self) -> Async<()> {
        self.inner.poll_write()
    }
}

impl Read for EventedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Async::NotReady = self.poll_read() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
        }
        self.inner.read(buf)
    }
}

impl Write for EventedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Async::NotReady = self.poll_write() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
        }
        let size = self.inner.write(buf)?;
        self.inner.flush()?;
        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Async::NotReady = self.poll_write() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
        }
        self.inner.flush()
    }
}

const TCP_DEFAULT_LISTEN_BACKLOG: u8 = 0xFF;
const TCP_WRITE_FLAG_COPY: u8 = 0x01;

#[repr(i32)]
#[allow(dead_code)]
#[derive(Debug)]
enum tcp_state {
    CLOSED = 0,
    LISTEN = 1,
    SYN_SENT = 2,
    SYN_RCVD = 3,
    ESTABLISHED = 4,
    FIN_WAIT_1 = 5,
    FIN_WAIT_2 = 6,
    CLOSE_WAIT = 7,
    CLOSING = 8,
    LAST_ACK = 9,
    TIME_WAIT = 10,
}

#[repr(C)]
#[derive(Debug)]
struct tcp_pcb {
    local_ip: ip_addr_t,
    remote_ip: ip_addr_t,
    so_options: u8,
    tos: u8,
    ttl: u8,
    next: *mut tcp_pcb,
    callback_arg: *mut c_void,
    state: tcp_state,
    prio: u8,
    local_port: u16,
    remote_port: u16,
    flags: tcpflags_t,
    polltmr: u8,
    pollinterval: u8,
    last_timer: u8,
    tmr: u32,
    rcv_next: u32,
    rcv_wnd: tcpwnd_size_t,
    rcv_ann_wnd: tcpwnd_size_t,
    rcv_ann_right_edge: u32,
    rtime: i16,
    mss: u16,
    rttest: u32,
    rtseq: u32,
    sa: i16,
    sv: i16,
    rto: i16,
    nrtx: u8,
    dupacks: u8,
    lastack: u32,
    cwnd: tcpwnd_size_t,
    ssthresh: tcpwnd_size_t,
    snd_nxt: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_lbb: u32,
    snd_wnd: tcpwnd_size_t,
    snd_wnd_max: tcpwnd_size_t,
    snd_buf: tcpwnd_size_t,
}

type tcpwnd_size_t = u16;
type tcpflags_t = u8;
type tcp_accept_fn = extern "C" fn(arg: *mut c_void, snewpcb: *mut tcp_pcb, err: err_t) -> err_t;
type tcp_recv_fn = extern "C" fn(arg: *mut c_void,
                                 tpcb: *mut tcp_pcb,
                                 p: *mut pbuf,
                                 err: err_t)
                                 -> err_t;
type tcp_sent_fn = extern "C" fn(arg: *mut c_void, tpcb: *mut tcp_pcb, len: u16) -> err_t;

#[link(name = "lwip", kind = "static")]
extern "C" {
    fn tcp_new() -> *mut tcp_pcb;
    fn tcp_close(pcb: *mut tcp_pcb) -> err_t;
    fn tcp_bind(pcb: *mut tcp_pcb, ipaddr: *const ip_addr_t, port: u16) -> err_t;
    fn tcp_listen_with_backlog(pcb: *mut tcp_pcb, backlog: u8) -> *mut tcp_pcb;
    fn tcp_arg(pcb: *mut tcp_pcb, arg: *mut c_void);
    fn tcp_accept(pcb: *mut tcp_pcb, accept: tcp_accept_fn);
    fn tcp_recv(pcb: *mut tcp_pcb, recv: tcp_recv_fn);
    fn tcp_recved(pcb: *mut tcp_pcb, len: u16);
    fn tcp_write(pcb: *mut tcp_pcb, arg: *const c_void, len: u16, apiflags: u8) -> err_t;
    fn tcp_sent(pcb: *mut tcp_pcb, sent: tcp_sent_fn);
    fn tcp_output(pcb: *mut tcp_pcb) -> err_t;
}
