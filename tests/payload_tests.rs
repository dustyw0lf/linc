use std::fs;
use std::io::Write;

use linc::payload::{New, Payload, PayloadType};
use tempfile::NamedTempFile;

#[test]
fn test_payload_from_bytes() {
    let test_bytes = vec![0x90, 0x90, 0x90]; // NOP sled
    let payload = Payload::<New>::from_bytes(test_bytes.clone(), PayloadType::Shellcode).unwrap();
    assert_eq!(payload.bytes(), test_bytes);
}

#[test]
fn test_payload_from_file() {
    // Test binary generated using code from
    // https://github.com/tchajed/minimal-elf
    let test_binary: &[u8] = &[
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6a, 0x3c, 0x58, 0x31, 0xff, 0x0f, 0x05,
    ];

    let mut tmpfile = NamedTempFile::new().unwrap();
    tmpfile.write_all(test_binary).unwrap();

    let bin_path = tmpfile.path().to_str().unwrap();
    let bin_bytes = fs::read(bin_path).unwrap();
    let bin_name = bin_path.split('/').last().unwrap();

    let payload = Payload::<New>::from_file(bin_path, PayloadType::Executable).unwrap();

    assert_eq!(payload.name(), bin_name);
    assert_eq!(payload.bytes(), bin_bytes);
}

#[cfg(feature = "http")]
mod http_tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    use super::*;

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

        let result = Payload::<New>::from_url(url, PayloadType::Executable);
        assert!(result.is_ok());
    }
}
