# tun2tor

[![Build Status](https://travis-ci.org/iCepa/tun2tor.svg?branch=master)](https://travis-ci.org/iCepa/tun2tor)

`tun2tor` is a Rust library that creates a `utun` (userspace tunnel) interface, and connects it to to a stream-based proxy like `tor`. It is primarily intended to be embedded in the [iCepa](https://github.com/iCepa/iCepa) project, but it can also be used as a standalone utility.

Currently, only macOS and iOS are supported, although Linux support is almost there.

`tun2tor` uses [`tokio`](https://github.com/tokio-rs/tokio) for async IO and [`LwIP`](http://savannah.nongnu.org/projects/lwip/) for its TCP implementation (for now).

[API Documentation](https://conradev.github.io/tun2tor)

## Running

Running `tun2tor` as a standalone utility is primarily useful for debugging at the moment. Here is how to get it running:

```bash
$ git clone --recursive https://github.com/iCepa/tun2tor.git
$ cd tun2tor
$ cargo build
$ sudo target/debug/tun2tor
```

```bash
$ tor --DnsPort 12345
```

Running it requires root privileges in order to create a `utun` interface. `tun2tor` is currently hardcoded in [`main.rs`](https://github.com/iCepa/tun2tor/blob/master/src/main.rs) to create an interface with an IP address of `172.30.20.1`, look for a SOCKS proxy at `127.0.0.1:9050`, and look for a DNS server at `127.0.0.1:12345`.

In order to route traffic through the interface, you need to modify the route table:

```bash
$ sudo route add 8.8.8.8 172.30.20.1
$ dig @8.8.8.8 facebookcorewwwi.onion
```

## Notes from/to Alex

- You need to pull in your own LWIP git checkout in the lwip directory of the root of the repository.
- When starting Instruments.app on macOS make sure you BOTH trace the Tor
  process and the application you use for testing the Tun interface with. You
  can add both processes in a single trace, but it is useful to have them
  side-by-side.
- How could we pre-rebase of lwip build without ARP support? That makes no sense.
- Remember to update RunThread.swift from iCepa such that it runs `tun2tor_run(packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32, 12345 as! Int32, 9050 as! Int32)`.
- Talk with Benjamin about moving to `async` for Tokio code (and bump Tokio version).
