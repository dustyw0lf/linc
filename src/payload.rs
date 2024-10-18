use std::fs;

pub struct Payload {
    pub name: String,
    pub args: String,
    pub payload_type: PayloadType,
    pub bytes: Vec<u8>,
}

pub enum PayloadType {
    Executable,
    Shellcode,
}

impl Payload {
    pub fn from_file(path: &str, payload_type: PayloadType) -> Self {
        Self {
            name: path.split('/').last().unwrap().to_string(),
            args: String::new(),
            payload_type: payload_type,
            bytes: fs::read(&path).expect("Faild to open file"),
        }
    }

    pub fn from_url(url: &str, payload_type: PayloadType) -> Self {
        let mut payload_bytes: Vec<u8> = Vec::new();

        let response = ureq::get(url)
            .call()
            .expect("Failed to download payload from server");

        response
            .into_reader()
            .read_to_end(&mut payload_bytes)
            .expect("Failed to read payload bytes");

        Self {
            name: url.split('/').last().unwrap().to_string(),
            args: String::new(),
            payload_type: payload_type,
            bytes: payload_bytes,
        }
    }

    pub fn set_args(mut self, args: &str) -> Self {
        self.args = args.to_string();
        self
    }
}
