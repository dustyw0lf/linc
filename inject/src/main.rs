#![allow(unused_imports)]

mod cli;

use crate::cli::build_cli;

use libinject::{anon_file, get_binary_filesystem, get_binary_http};

fn main() {
    let args = build_cli().get_matches();

    let binary = args.get_one::<String>("binary").unwrap().to_string();
    let binary_args = args.get_one::<String>("args").unwrap().to_string();

    let binary_name = binary.split('/').last().unwrap();

    let binary_bytes = match binary.starts_with("http://") || binary.starts_with("https://") {
        true => get_binary_http(binary.as_str()),
        false => get_binary_filesystem(binary.as_str()),
    };

    match anon_file(binary_name, &binary_args, &binary_bytes) {
        Ok(res) => res,
        Err(error) => panic!("An error occured: {error:?}"),
    };
}
