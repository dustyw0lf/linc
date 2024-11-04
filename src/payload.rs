//! Defines types and implementations for working with executable payloads.
use std::fs;

use nix::unistd::Pid;

use crate::error::Result;

// region:    --- Payload

// Marker trait
pub trait ProcessState {}

// Possible process states
pub struct New {
    pub name: String,
    pub args: String,
    pub target: String,
    pub target_args: String,
}

pub struct Existing {
    pub pid: Pid,
}

// Make sure that ProcessState can be either New or Existing
impl ProcessState for New {}
impl ProcessState for Existing {}

// Base struct with common fields
pub struct Payload<S: ProcessState> {
    pub payload_type: PayloadType,
    pub bytes: Vec<u8>,
    pub state: S,
}

/// Specifies the type of payload being used.
#[derive(Debug)]
pub enum PayloadType {
    Executable,
    Shellcode,
}

// Constructors
impl Payload<New> {
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
            payload_type,
            bytes,
            state: New {
                name: String::new(),
                args: String::new(),
                target: String::new(),
                target_args: String::new(),
            },
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
            payload_type,
            bytes: fs::read(&path)?,
            state: New {
                name: path.split('/').last().unwrap_or("").to_string(),
                args: String::new(),
                target: String::new(),
                target_args: String::new(),
            },
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
            payload_type,
            bytes: payload_bytes,
            state: New {
                name: url.split('/').last().unwrap_or("").to_string(),
                args: String::new(),
                target: String::new(),
                target_args: String::new(),
            },
        })
    }
}

impl Payload<Existing> {
    pub fn from_bytes(bytes: Vec<u8>, payload_type: PayloadType, pid: i32) -> Result<Self> {
        Ok(Self {
            payload_type,
            bytes,
            state: Existing {
                pid: Pid::from_raw(pid),
            },
        })
    }

    pub fn from_file(path: impl Into<String>, payload_type: PayloadType, pid: i32) -> Result<Self> {
        let path = path.into();

        Ok(Self {
            payload_type,
            bytes: fs::read(&path)?,
            state: Existing {
                pid: Pid::from_raw(pid),
            },
        })
    }

    #[cfg(feature = "http")]
    pub fn from_url(url: impl Into<String>, payload_type: PayloadType, pid: i32) -> Result<Self> {
        let url = url.into();

        let response = ureq::get(&url).call()?;

        let mut payload_bytes: Vec<u8> = Vec::new();
        response.into_reader().read_to_end(&mut payload_bytes)?;

        Ok(Self {
            payload_type,
            bytes: payload_bytes,
            state: Existing {
                pid: Pid::from_raw(pid),
            },
        })
    }
}

// Common getters for all states
impl<S: ProcessState> Payload<S> {
    pub fn payload_type(&self) -> &PayloadType {
        &self.payload_type
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Variant-specific getters
impl Payload<New> {
    pub fn name(&self) -> &str {
        &self.state.name
    }

    pub fn args(&self) -> &str {
        &self.state.args
    }

    pub fn target(&self) -> &str {
        &self.state.target
    }

    pub fn target_args(&self) -> &str {
        &self.state.target_args
    }
}

impl Payload<Existing> {
    pub fn pid(&self) -> Pid {
        self.state.pid
    }
}

// Chainable setters
impl Payload<New> {
    pub fn set_args(mut self, args: &str) -> Self {
        self.state.args = self.state.name.clone() + " " + args;
        self
    }

    pub fn set_target(mut self, target: &str) -> Self {
        self.state.target = target.to_string();
        self
    }

    pub fn set_target_args(mut self, target_args: &str) -> Self {
        self.state.target_args = self.state.target.clone() + " " + target_args;
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
