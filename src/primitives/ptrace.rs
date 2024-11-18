use std::ffi::c_void;

use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

use crate::error::Result;

pub(crate) fn ptace_write_rip(pid: Pid, bytes: &[u8], is_forked: bool) -> Result<()> {
    if is_forked {
        waitpid(pid, None)?;
    } else {
        ptrace::attach(pid)?;
        waitpid(pid, None)?;
    }

    let regs = ptrace::getregs(pid)?;

    let mut addr = regs.rip;

    for byte in bytes {
        ptrace::write(pid, addr as *mut c_void, i64::from(*byte))?;
        addr += 1;
    }

    ptrace::detach(pid, None)?;

    Ok(())
}
