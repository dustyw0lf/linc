use reqwest;
use std::ffi::CString;
use std::{env, fs};

pub fn get_binary_filesystem(path: &str) -> Vec<u8> {
    return fs::read(path).expect("Faild to open file");
}

pub fn get_binary_http(url: &str) -> Vec<u8> {
    let response = reqwest::blocking::get(url).expect("Failed to download file");
    response.bytes().unwrap().to_vec()
}

pub fn get_env_vars() -> Vec<CString> {
    let mut env_vars: Vec<CString> = Vec::new();
    for (key, value) in env::vars() {
        env_vars.push(CString::new(format!("{}={}", key, value)).unwrap());
    }
    env_vars
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
