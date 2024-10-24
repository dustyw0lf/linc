// region:    --- Modules

mod elf;
mod error;
mod payload;
mod techniques;
mod utils;

// endregion: --- Modules

// region:    --- Public API

pub use payload::{Payload, PayloadType};
pub use techniques::{hollow, memfd};

// endregion: --- Public API
