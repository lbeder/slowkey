use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use super::chacha20poly1305::{ChaCha20Poly1305, Nonce};

#[derive(Serialize, Deserialize)]
pub struct OutputData {
    pub data: Vec<u8>,
}

pub struct Output {
    pub path: PathBuf,
    cipher: ChaCha20Poly1305,
}

#[derive(PartialEq, Debug, Clone)]
pub struct OutputOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
}

impl Output {
    pub fn new(opts: &OutputOptions) -> Self {
        if opts.path.exists() {
            panic!("Output file \"{}\" already exists", opts.path.to_str().unwrap());
        }

        Self {
            path: opts.path.clone(),
            cipher: ChaCha20Poly1305::new(&opts.key),
        }
    }

    pub fn get(opts: &OutputOptions) -> OutputData {
        let cipher = ChaCha20Poly1305::new(&opts.key);

        if !opts.path.exists() {
            panic!("Output file \"{}\" does not exist", opts.path.to_str().unwrap());
        }

        if !opts.path.is_file() {
            panic!("Output file \"{}\" is not a file", opts.path.to_str().unwrap());
        }

        let mut encrypted_data = Vec::new();
        File::open(&opts.path)
            .unwrap()
            .read_to_end(&mut encrypted_data)
            .unwrap();

        cipher.decrypt(&hex::decode(encrypted_data).unwrap())
    }

    pub fn save(&self, data: &[u8]) {
        let encrypted_data = self.cipher.encrypt(Nonce::Random, &OutputData { data: data.to_vec() });

        let mut file = File::create_new(&self.path).unwrap();

        file.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        file.flush().unwrap();
    }
}
