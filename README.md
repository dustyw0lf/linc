# libinject-linux

`libinject-linux` is a Rust crate containing implementations for process injection techniques on Linux.

## Functionality
The following process injection techniques are currently implemented:
- Using [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to create an anonymous file that lives in memory, write an ELF to it, and then execute.

## Usage
Add `libinject-linux` as a dependency to your Rust project
```bash
cargo add --git https://github.com/dustyw0lf/libinject-linux.git
```

or try out the code by building one of the examples
```bash
git clone https://github.com/dustyw0lf/libinject-linux.git
```

```bash
cargo run --example anon_file
```

## Acknowledgments
The `memfd_create(2)` implementation is based on an article by [@magisterquis](https://x.com/magisterquis): [In-Memory-Only ELF Execution (Without tmpfs)](https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html).