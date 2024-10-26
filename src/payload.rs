//! Defines types and implementations for working with executable payloads.
use std::fs;

use crate::error::Result;

// region:    --- Payload

/// Represents an executable payload that can be either a complete ELF executable
/// or raw shellcode.
#[derive(Debug)]
pub struct Payload {
    pub name: String,
    pub args: String,
    pub payload_type: PayloadType,
    pub bytes: Vec<u8>,
    pub target: String,
    pub target_args: String,
}

/// Specifies the type of payload being used.
#[derive(Debug)]
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
            payload_type,
            bytes,
            target: String::new(),
            target_args: String::new(),
        }
    }

    pub fn from_file(path: impl Into<String>, payload_type: PayloadType) -> Result<Self> {
        let path = path.into();

        Ok(Self {
            name: path.split('/').last().unwrap_or("").to_string(),
            args: String::new(),
            payload_type,
            bytes: fs::read(path).expect("Faild to open file"),
            target: String::new(),
            target_args: String::new(),
        })
    }

    #[cfg(feature = "http")]
    pub fn from_url(url: impl Into<String>, payload_type: PayloadType) -> Result<Self> {
        let url = url.into();

        let response = ureq::get(&url).call()?;

        let mut payload_bytes: Vec<u8> = Vec::new();
        response.into_reader().read_to_end(&mut payload_bytes)?;

        Ok(Self {
            name: url.split('/').last().unwrap_or("").to_string(),
            args: String::new(),
            payload_type,
            bytes: payload_bytes,
            target: String::new(),
            target_args: String::new(),
        })
    }
}

// Chainable setters
impl Payload {
    pub fn set_args(mut self, args: &str) -> Self {
        self.args = self.name.clone() + " " + args;
        self
    }

    pub fn set_target(mut self, target: &str) -> Self {
        self.target = target.to_string();
        self
    }

    pub fn set_target_args(mut self, target_args: &str) -> Self {
        self.target_args = self.target.clone() + " " + target_args;
        self
    }
}

// Extension trait for Result<Payload>
pub trait PayloadResultExt {
    fn set_args(self, args: &str) -> Result<Payload>;
    fn set_target(self, target: &str) -> Result<Payload>;
    fn set_target_args(self, target_args: &str) -> Result<Payload>;
}

impl PayloadResultExt for Result<Payload> {
    fn set_args(self, args: &str) -> Result<Payload> {
        self.map(|payload| payload.set_args(args))
    }

    fn set_target(self, target: &str) -> Result<Payload> {
        self.map(|payload| payload.set_target(target))
    }

    fn set_target_args(self, target_args: &str) -> Result<Payload> {
        self.map(|payload| payload.set_target_args(target_args))
    }
}

// endregion: --- Payload
