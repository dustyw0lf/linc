# LINC - Linux INjection Crate
`linc` is a Rust crate containing implementations for process injection and fileless ELF execution techniques on Linux, supporting both 64-bit shellcode and ELF executables.

## Functionality
`linc`'s functionality is divided into two modules of injection techniques:
- `linc::inject`: Techniques that manipulate an existing process to execute injected payload.
- `linc::spawn`: Techniques that fork a new process to execute a payload.

Each module has implementations for the following techniques:
- Using [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) to inject shellcode into an existing process by overwriting its RIP register.
- Using [/proc/pid](https://man7.org/linux/man-pages/man5/proc_pid.5.html) to:
    1. Find an executable memory section by parsing [/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
    2. Write payload to said section in [/proc/pid/mem](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html).
    3. Find the RIP register by parsing [/proc/pid/syscall](https://man7.org/linux/man-pages/man5/proc_pid_syscall.5.html).
    4. Jump to the payload address by overwrting RIP in [/proc/pid/mem](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html).

Additional techniques supported by the `linc::spawn` module:
- Using [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file in memory, write an ELF to it, and then execute.

## Limitations
Process interaction on Linux is subject to several security restrictions:

### ptrace_scope
The [ptrace_scope](https://www.kernel.org/doc/Documentation/security/Yama.txt) setting controls process attachment permissions and affects all techniques in this crate:

- 0: Processes can attach to any other process running under same UID
- 1: Processes can only attach to their children (default on many distributions)
- 2: Only processes with CAP_SYS_PTRACE capability can attach
- 3: Process attachment disabled entirely

The current `ptrace_scope` can be checked using
```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

### Process Dumpability
A process must have the [dumpable](https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html) attribute set to true (which is the default for most user processes) so another process may be able to attach to it.

Process' dumpability can be checked using
```bash
[ -r /proc/<pid>/mem ] && echo "Process is dumpable" || echo "Process is not dumpable or protected by ptrace_scope"
```

## Usage
Add `linc` as a dependency to your Rust project
```bash
cargo add --git https://github.com/dustyw0lf/linc.git
```

Add `linc` with the feature `http` to enable downloading a payload via HTTP/S
```bash
cargo add --git https://github.com/dustyw0lf/linc.git --features http
```

## Features
`linc` has the following features, not enabled by default:
- `http`: Adds functionality to download payloads over HTTP/S.

## Examples
Clone the repo
```bash
git clone https://github.com/dustyw0lf/linc.git
```

Change directory into `linc`
```bash
cd linc
```

Examples are named like so:
```unknown
[technique type]_[technique name]_[payload type]
```

and some of them may require additional setup, like setting up a Netcat listener.

### spawn_memfd_executable
Run the spawn_memfd_executable example with an ELF file
```bash
cargo run --example spawn_memfd_executable
```

### inject_procfs_overwrite_rip_shellcode
Start a listener
```bash
nc -lvnp 1234
```

Find a process ID or create a process for testing
```bash
sleep 10 &
```

Run the example and pass the PID as an argument
```bash
cargo run --example inject_procfs_overwrite_rip_shellcode -- <pid>
```

## Testing
Run tests
```bash
cargo test
```

## Documentation
Build the documentation
```bash
cargo doc --no-deps
```

The documentation will be in `target/doc/linc/index.html`.

## Acknowledgments
- Series of [blogposts](https://blog.f0b.org) on Linux process injection by Philippe Grégoire.
- [The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection) by Ori David.