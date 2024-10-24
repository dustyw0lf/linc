use linc::{memfd, Payload, PayloadType};

fn main() {
    let payload = Payload::from_file("/usr/bin/ls", PayloadType::Executable).set_args("-l -a -h");
    // let payload = Payload::from_url("http://127.0.0.1:8081/ls", PayloadType::Executable).set_args("-l -a -h");

    if let Err(e) = memfd(payload) {
        panic!("An error occured: {e:?}");
    }
}
