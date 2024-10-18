use std::fs;

// region:    --- Payload

pub struct Payload {
    pub name: String,
    pub args: String,
    pub payload_type: PayloadType,
    pub bytes: Vec<u8>,
    pub target: String,
    pub target_args: String,
}

pub enum PayloadType {
    Executable,
    Shellcode,
}

// Constructors
impl Payload {
    pub fn from_bytes(bytes: Vec<u8>, payload_type: PayloadType) -> Self {
        Self {
            name: String::new(),
            args: String::new(),
            payload_type: payload_type,
            bytes: bytes,
            target: String::new(),
            target_args: String::new(),
        }
    }

    pub fn from_file(path: &str, payload_type: PayloadType) -> Self {
        Self {
            name: path.split('/').last().unwrap().to_string(),
            args: String::new(),
            payload_type: payload_type,
            bytes: fs::read(path).expect("Faild to open file"),
            target: String::new(),
            target_args: String::new(),
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
            target: String::new(),
            target_args: String::new(),
        }
    }
}

// Chainable setters
impl Payload {
    pub fn set_args(mut self, args: &str) -> Self {
        self.args = args.to_string();
        self
    }

    pub fn set_target(mut self, target: &str) -> Self {
        self.target = target.to_string();
        self
    }

    pub fn set_target_args(mut self, target_args: &str) -> Self {
        self.target_args = target_args.to_string();
        self
    }
}

// endregion: --- Payload
