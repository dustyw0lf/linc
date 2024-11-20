# LINC - Linux INjection Crate
`linc` is a Rust crate containing implementations for process injection and fileless ELF execution techniques on Linux, supporting both 64-bit shellcode and ELF executables.

## Functionality
`linc`'s functionality is divided into two sets of techniques:
- `linc::inject`: Techniques that manipulate an existing process to execute injected payload.
- `linc::spawn`: Techniques that create a new process to execute a payload.

Currently implemented techniques:

### Spawn
- Using [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file in memory, write an ELF to it, and then execute.
- Using [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) to stop a forked process, overwrite its RIP register with shellcode, and then resume it.

### Inject
- Using [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) to inject shellcode into an existing process by overwriting its RIP register.
- Using [/proc/pid](https://man7.org/linux/man-pages/man5/proc_pid.5.html) to:
    1. Find an executable memory section by parsing [/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
    2. Write payload to said section in [/proc/pid/mem](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html).
    3. Find the RIP register by parsing [/proc/pid/syscall](https://man7.org/linux/man-pages/man5/proc_pid_syscall.5.html).
    4. Jump to the payload address by overwrting RIP in [/proc/pid/mem](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html).

## Usage
Add `linc` as a dependency to your Rust project
```bash
cargo add --git https://github.com/dustyw0lf/linc.git
```

Add `linc` with the feature `http` to enable payload downloads via HTTP/S
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
[technique type]_[name]_[payload type]
```

and some of them may require additional setup, like setting a Netcat listener.

### spawn_memfd_executable
Run the spawn_memfd_executable example with an ELF file
```bash
cargo run --example spawn_memfd_executable
```

### inject_hollow_shellcode
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
cargo run --example inject_hollow_shellcode -- <pid>
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