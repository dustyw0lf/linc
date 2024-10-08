extern crate libinject_linux;

use libinject_linux::anon_file;

fn main() {
    match anon_file("/usr/bin/ls", "-l -A -h") {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
