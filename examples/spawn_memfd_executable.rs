use linc::payload::{Payload, PayloadResultExt, Spawn};
use linc::techniques::spawn::memfd;

fn main() {
    let payload = Payload::<Spawn>::from_file("/usr/bin/ls").set_args("-l -a -h");
    // let payload = Payload::from_url("http://127.0.0.1:8081/ls", PayloadType::Executable).set_args("-l -a -h");

    let payload = match payload {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to create payload: {:?}", e);
            return;
        }
    };

    if let Err(e) = memfd(payload) {
        eprintln!("An error occurred: {:?}", e);
    }
}
