use crate::utils::{get_env_vars, parse_args_for_fexecve};

use nix::errno::Errno;
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::unistd::{fexecve, write};
use std::ffi::CString;
use std::os::fd::AsRawFd;

pub fn anon_file(binary_name: &str, args: &str, binary_bytes: &[u8]) -> Result<(), Errno> {
    let anon_file_name = CString::new("").unwrap();
    let p_file_name = anon_file_name.as_c_str();

    let fd = memfd_create(p_file_name, MemFdCreateFlag::MFD_CLOEXEC)?;

    write(&fd, binary_bytes)?;

    let parsed_args = parse_args_for_fexecve(binary_name, args);
    let parsed_args_as_slice = parsed_args.as_slice();

    let env = get_env_vars();
    let env_as_slice = env.as_slice();

    fexecve(fd.as_raw_fd(), parsed_args_as_slice, env_as_slice)?;
    Ok(())
}
