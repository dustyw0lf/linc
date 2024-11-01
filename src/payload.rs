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
    /// Creates a new payload from a byte vector.
    ///
    /// The bytes can represent either a complete ELF executable or raw shellcode, as specified by
    /// the `payload_type` parameter.
    ///
    /// # Errors
    /// Currently infallible, but returns `Result` for consistency with other constructors.
    ///
    /// # Examples
    ///
    /// ```
    /// use linc::payload::{Payload, PayloadType};
    ///
    /// // Create a payload from shellcode bytes
    /// let shellcode = vec![0x90, 0x90, 0x90];  // NOP sled
    /// let payload = Payload::from_bytes(shellcode, PayloadType::Shellcode).unwrap();
    ///
    /// // Create a payload from an ELF executable's bytes
    /// let elf_bytes = vec![/* ... */];  // ELF file contents
    /// let payload = Payload::from_bytes(elf_bytes, PayloadType::Executable).unwrap();
    /// ```
    pub fn from_bytes(bytes: Vec<u8>, payload_type: PayloadType) -> Result<Self> {
        Ok(Self {
            name: String::new(),
            args: String::new(),
            payload_type,
            bytes,
            target: String::new(),
            target_args: String::new(),
        })
    }

    /// Creates a new payload by reading from a file.
    ///
    /// The file can contain either a complete ELF executable or raw shellcode, as specified by
    /// the `payload_type` parameter.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be read
    /// - The file path contains invalid UTF-8 characters
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use linc::payload::{Payload, PayloadType};
    ///
    /// // Load a shellcode file
    /// let payload = Payload::from_file("shellcode.bin", PayloadType::Shellcode).unwrap();
    ///
    /// // Load an existing ELF executable
    /// let payload = Payload::from_file("/usr/bin/ls", PayloadType::Executable).unwrap();
    /// ```
    pub fn from_file(path: impl Into<String>, payload_type: PayloadType) -> Result<Self> {
        let path = path.into();

        Ok(Self {
            name: path.split('/').last().unwrap_or("").to_string(),
            args: String::new(),
            payload_type,
            bytes: fs::read(path)?,
            target: String::new(),
            target_args: String::new(),
        })
    }

    #[cfg(feature = "http")]
    /// Creates a new payload by downloading from a URL.
    ///
    /// The downloaded content can be either a complete ELF executable or raw shellcode, as specified by
    /// the `payload_type` parameter.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The URL is invalid or unreachable
    /// - The network request fails
    /// - Reading the response body fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use linc::payload::{Payload, PayloadType};
    ///
    /// // Download and load an ELF executable
    /// let payload = Payload::from_url(
    ///     "http://example.com/executable",
    ///     PayloadType::Executable
    /// ).unwrap();
    ///
    /// // Download and load shellcode
    /// let payload = Payload::from_url(
    ///     "http://example.com/shellcode.bin",
    ///     PayloadType::Shellcode
    /// ).unwrap();
    /// ```
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

/// Extension trait for `Result<Payload>` that provides chainable configuration methods.
///
/// This trait allows for payload configuration even when the payload creation
/// might fail. It provides the same configuration methods as `Payload` but works on
/// `Result<Payload>` directly, making it easier to chain operations without explicit
/// error handling.
pub trait PayloadResultExt {
    /// Sets the arguments for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
    fn set_args(self, args: &str) -> Result<Payload>;

    /// Sets the target executable for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
    fn set_target(self, target: &str) -> Result<Payload>;

    /// Sets the target executable's arguments for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
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
