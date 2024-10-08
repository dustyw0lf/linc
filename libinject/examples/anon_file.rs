#![allow(unused_imports)]
extern crate libinject;
use libinject::{anon_file, get_binary_filesystem, get_binary_http};

fn main() {
    // let binary_location = "/usr/bin/ls";
    let binary_location = "http://127.0.0.1:8081/ls";
    let binary_name = binary_location.split('/').last().unwrap();
    // let binary_bytes = get_binary_filesystem(binary_location);
    let binary_bytes = get_binary_http(binary_location);

    match anon_file(binary_name, "-l -A -h", &binary_bytes) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
