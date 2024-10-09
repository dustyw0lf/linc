use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::{env, fs};

pub fn get_binary_filesystem(path: &str) -> Vec<u8> {
    fs::read(path).expect("Faild to open file")
}

pub fn get_binary_http(url: &str) -> Vec<u8> {
    let response = reqwest::blocking::get(url).expect("Failed to download file");
    response.bytes().unwrap().to_vec()
}

pub fn get_env() -> Vec<CString> {
    // Source: https://github.com/io12/userland-execve-rust/blob/main/src/main.rs
    env::vars_os()
        .map(|(key, val)| {
            [key, OsString::from("="), val]
                .into_iter()
                .collect::<OsString>()
        })
        .map(os_string_to_c_string)
        .collect()
}

fn os_string_to_c_string(string: OsString) -> CString {
    // Source: https://github.com/io12/userland-execve-rust/blob/main/src/main.rs
    let mut vector = string.into_vec();
    vector.push(0);
    CString::from_vec_with_nul(vector).unwrap()
}

pub fn parse_args_for_fexecve(binary: &str, args: &str) -> Vec<CString> {
    let mut bin_vec = vec![CString::new(binary).unwrap()];
    let mut args_vec: Vec<CString> = args
        .split_whitespace()
        .map(|x| CString::new(x).unwrap())
        .collect();

    bin_vec.append(&mut args_vec);
    bin_vec
}
