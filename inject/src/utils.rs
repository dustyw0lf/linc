use std::fs;

pub fn get_binary_filesystem(path: &str) -> Vec<u8> {
    fs::read(path).expect("Faild to open file")
}

pub fn get_binary_http(url: &str) -> Vec<u8> {
    let response = reqwest::blocking::get(url).expect("Failed to download file");
    response.bytes().unwrap().to_vec()
}
