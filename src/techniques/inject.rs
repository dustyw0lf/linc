//! Techniques that inject into an existing process.

use crate::error::{Error, Result};
use crate::payload::{Existing, Payload, PayloadType};
use crate::primitives::ptrace::ptace_write_rip;

pub fn hollow(payload: Payload<Existing>) -> Result<()> {
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
