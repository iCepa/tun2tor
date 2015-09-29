extern crate gcc;
extern crate glob;

use glob::glob;

fn main() {
    let mut config = gcc::Config::new();
    config.include("lwip/src/include");
    config.include("lwip/src/include/ipv4");
    config.include("lwip/src/include/ipv6");
    config.include("lwip-contrib/ports/unix/include");
    config.include(".");

    for path in glob("lwip/src/**/*.c").unwrap().filter_map(Result::ok) {
        config.file(path);
    }

    for path in glob("lwip-contrib/ports/unix/*.c").unwrap().filter_map(Result::ok) {
        config.file(path);
    }

    config.compile("liblwip.a")
}
