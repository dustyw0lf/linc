use linc::{memfd, Payload, PayloadResultExt, PayloadType};

fn main() {
    let payload = Payload::from_file("/usr/bin/ls", PayloadType::Executable).set_args("-l -a -h");
    // let payload = Payload::from_url("http://127.0.0.1:8081/ls", PayloadType::Executable).set_args("-l -a -h");

    // Check if the payload was created successfully
    if let Err(e) = payload {
        eprintln!("Failed to create payload: {:?}", e);
        return;
    }

    if let Err(e) = memfd(payload.unwrap()) {
        eprintln!("An error occurred: {:?}", e);
    }
}
