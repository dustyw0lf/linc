# libinject-linux

`libinject-linux` is a Rust crate containing implementations for process injection techniques on Linux.

## Functionality
The following process injection techniques are currently implemented:
- Using [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html) to execute an anonymous, in-memory, file. 

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