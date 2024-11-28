use std::fs;
use std::io::{Seek, SeekFrom, Write};

use nix::unistd::Pid;

use crate::error::{Error, Result};

pub(crate) fn find_mem_region(
    pid: Pid,
    get_start_addr: bool,
    permissions: &str,
) -> Result<Vec<u64>> {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid.as_raw()))?;

    // Filter for lines with the right permissions
    let matching_lines = maps.lines().filter(|line| {
        line.split_whitespace()
            .nth(1) // get the memory permissions
            .map_or(false, |perms| perms.contains(permissions))
    });

    // Extract memory addresses from the filtered lines
    let addrs = matching_lines
        .map(|line| {
            let addr_range = if get_start_addr {
                &line[..12]
            } else {
                &line[13..25]
            };
            u64::from_str_radix(addr_range, 16)
        })
        .map(|r| r.map_err(Error::ParseInt))
        .collect::<Result<Vec<u64>>>()?;

    Ok(addrs)
}

pub(crate) fn mem_write(pid: Pid, addr: u64, bytes: &[u8]) -> Result<()> {
    let mut file = fs::File::options()
        .write(true)
        .open(format!("/proc/{}/mem", pid.as_raw()))?;

    file.seek(SeekFrom::Start(addr))?;

    file.write_all(bytes)?;

    Ok(())
}

pub(crate) fn mem_rip(pid: Pid) -> Result<u64> {
    let binding = fs::read_to_string(format!("/proc/{}/syscall", pid.as_raw()))?;
    let rip = binding.split_whitespace().last().unwrap();

    Ok(u64::from_str_radix(&rip[2..], 16)?)
}

pub(crate) fn mem_exec(pid: Pid, addr: u64) -> Result<()> {
    let rip = mem_rip(pid)?;

    let mut buf = [
        0x48, 0xB8, // mov rax
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved for memory addr bytes
        0xFF, 0xE0, // jmp rax
    ];
    buf[2..10].copy_from_slice(&addr.to_le_bytes());

    mem_write(pid, rip, &buf)?;

    Ok(())
}
