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

    let matching_lines = maps.lines().filter(|line| {
        line.split_whitespace()
            .nth(1) // get the memory permissions
            .map_or(false, |perms| perms.contains(permissions))
    });

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
