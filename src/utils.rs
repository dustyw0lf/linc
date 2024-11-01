use std::env;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;

use crate::error::{Error, Result};

pub fn get_env() -> Result<Vec<CString>> {
    env::vars_os()
        .map(|(mut key, val)| {
            key.push("=");
            key.push(val);
            os_string_to_c_string(key)
        })
        .collect()
}

fn os_string_to_c_string(string: OsString) -> Result<CString> {
    let mut vector = string.into_vec();
    vector.push(0);
    CString::from_vec_with_nul(vector).map_err(Error::FromVecWithNul)
}

pub fn str_to_vec_c_string(string: &str) -> Result<Vec<CString>> {
    string
        .split_whitespace()
        .map(|x| CString::new(x).map_err(Error::Nul))
        .collect()
}
