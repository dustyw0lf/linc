mod core;

pub use crate::core::{hollow, memfd};

mod utils;

pub use crate::utils::{get_binary_filesystem, get_binary_http};
