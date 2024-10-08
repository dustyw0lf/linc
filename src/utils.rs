use std::env;
use std::ffi::CString;

pub fn parse_args_for_fexecve(binary: &str, args: &str) -> Vec<CString> {
    let mut bin_vec = vec![CString::new(binary).unwrap()];
    let mut args_vec: Vec<CString> = args
        .split_whitespace()
        .map(|x| CString::new(x).unwrap())
        .collect();

    bin_vec.append(&mut args_vec);
    bin_vec
}

pub fn get_env_vars() -> Vec<CString> {
    let mut env_vars: Vec<CString> = Vec::new();
    for (key, value) in env::vars() {
        env_vars.push(CString::new(format!("{}={}", key, value)).unwrap());
    }
    env_vars
}
