extern crate mio;
extern crate socks;
extern crate lwip;

use mio::*;
use socks::*;
use lwip::*;
use mio::tcp::TcpStream;

const SOCKS_CLIENT: Token = Token(1);

struct SocksHandler(TcpStream);

impl Handler for SocksHandler {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        match token {
            SOCKS_CLIENT => {

            }
            _ => panic!("unexpected token")
        }
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {

    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, timeout: Self::Timeout) {

    }

    fn interrupted(&mut self, event_loop: &mut EventLoop<Self>) {

    }

    fn tick(&mut self, event_loop: &mut EventLoop<Self>) {

    }
}

fn main() {
    // let mut event_loop = EventLoop::new().unwrap();

    let addr = "127.0.0.1:2001".parse().unwrap();
    let sock = TcpStream::connect(&addr).unwrap();

    // let mut buf = Cursor::new(vec);
    // try!(sock.try_write_buf(&mut buf));
    
    // Register the socket
    // event_loop.register(&sock, SOCKS_CLIENT).unwrap();
    // event_loop.run(&mut SocksHandler(sock)).unwrap();

    init();
    
    let mut interface = NetworkInterface::add(Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(255,255,255,255), Ipv4Addr::new(0,0,0,0));
    interface.set_default();
    interface.set_up();

    println!("hello world!");
}
