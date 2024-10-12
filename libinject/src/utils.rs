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

pub fn str_to_vec_c_string(string: &str) -> Vec<CString> {
    let string_vec: Vec<CString> = string
        .split_whitespace()
        .map(|x| CString::new(x).unwrap())
        .collect();
    string_vec
}