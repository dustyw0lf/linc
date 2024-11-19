//! Rust implementations for process injection and fileless ELF execution techniques on Linux.
//!
//! The crate provides two categories of techniques:
//!
//! - Injection: Techniques that manipulate an existing process to execute injected payload.
//! - Spawning: Techniques that create a new process to execute a payload.
//!
//! Both categories support 64-bit shellcode and ELF executables.
//!
//! # Features
//!
//! - `http`: Enables payload downloads via HTTP/S

// region:    --- Modules

mod error;
pub mod payload;
mod primitives;
pub mod techniques;
mod utils;

// endregion: --- Modules
