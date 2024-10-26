use std::fs;

use linc::payload::{Payload, PayloadType};
use utils::create_test_binary;

mod utils;

#[test]
fn test_payload_from_file() {
    let bin_path = create_test_binary().to_str().unwrap().to_owned();
    let bin_bytes = fs::read(bin_path.clone()).unwrap();
    let bin_name = bin_path.split('/').last().unwrap();

    let payload = Payload::from_file(bin_path.clone(), PayloadType::Executable).unwrap();

    assert_eq!(payload.name, bin_name);
    assert_eq!(payload.bytes, bin_bytes);
}

#[test]
fn test_payload_from_bytes() {
    let test_bytes = vec![0x90, 0x90, 0x90]; // NOP sled
    let payload = Payload::from_bytes(test_bytes.clone(), PayloadType::Shellcode).unwrap();
    assert_eq!(payload.bytes, test_bytes);
}

#[cfg(feature = "http")]
mod http_tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    fn start_test_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    // Send minimal valid response
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
                    stream.write_all(response).unwrap();
                }
            }
        });

        port
    }

    #[test]
    fn test_payload_from_url() {
        let port = start_test_server();
        let url = format!("http://127.0.0.1:{}/test.bin", port);

        let result = Payload::from_url(url, PayloadType::Executable);
        assert!(result.is_ok());
    }
}
