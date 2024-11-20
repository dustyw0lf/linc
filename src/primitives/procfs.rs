use nix::unistd::Pid;

use std::fs;

use crate::error::{Error, Result};

pub(crate) fn find_memory_region(
    pid: Pid,
    get_start_address: bool,
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
            let addr_range = if get_start_address {
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
