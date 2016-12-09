extern crate gcc;

use std::env;

fn main() {
    let mut config = gcc::Config::new();
    if env::var("PROFILE").map(|v| &v[..] == "debug").unwrap_or(false) {
        config.define("LWIP_DEBUG", Some("1"));
    }

    config.file("lwip/src/core/def.c")
        .file("lwip/src/core/inet_chksum.c")
        .file("lwip/src/core/init.c")
        .file("lwip/src/core/ip.c")
        .file("lwip/src/core/ipv4/ip4.c")
        .file("lwip/src/core/ipv4/ip4_addr.c")
        .file("lwip/src/core/ipv4/ip4_frag.c")
        .file("lwip/src/core/ipv6/icmp6.c")
        .file("lwip/src/core/ipv6/ip6.c")
        .file("lwip/src/core/ipv6/ip6_addr.c")
        .file("lwip/src/core/ipv6/ip6_frag.c")
        .file("lwip/src/core/ipv6/nd6.c")
        .file("lwip/src/core/mem.c")
        .file("lwip/src/core/memp.c")
        .file("lwip/src/core/netif.c")
        .file("lwip/src/core/pbuf.c")
        .file("lwip/src/core/stats.c")
        .file("lwip/src/core/tcp.c")
        .file("lwip/src/core/tcp_in.c")
        .file("lwip/src/core/tcp_out.c")
        .file("lwip/src/core/timeouts.c")
        .file("lwip/src/api/err.c")
        .file("lwip-contrib/ports/unix/port/perf.c")
        .file("lwip-contrib/ports/unix/port/sys_arch.c")
        .include(".")
        .include("lwip-contrib/ports/unix")
        .include("lwip-contrib/ports/unix/port/include")
        .include("lwip/src/include")
        .compile("liblwip.a");
}
