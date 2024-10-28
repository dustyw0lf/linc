//! Rust implementations for process injection and
//! fileless ELF execution techniques on Linux.
//!
//! # Features
//!
//! - `http`: Enables payload downloads via HTTP/S.

// region:    --- Modules

mod error;
pub mod payload;
pub mod techniques;
mod utils;

// endregion: --- Modules
