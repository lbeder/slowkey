use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

use crate::{
    slowkey::SlowKeyOptions,
    utils::chacha20poly1305::{ChaCha20Poly1305, Nonce},
};

use super::version::Version;

#[derive(PartialEq, Debug, Clone)]
pub struct OutputOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
    pub slowkey: SlowKeyOptions,
}

#[derive(PartialEq, Debug, Clone)]
pub struct OpenOutputOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct OutputData {
    pub version: Version,
    pub data: SlowKeyData,
}

#[derive(Serialize, Deserialize)]
pub struct SlowKeyData {
    pub iteration: usize,
    pub data: Vec<u8>,
    pub slowkey: SlowKeyOptions,
}

pub struct Output {
    pub path: PathBuf,
    cipher: ChaCha20Poly1305,
    slowkey: SlowKeyOptions,
}

impl Output {
    pub fn new(opts: &OutputOptions) -> Self {
        if opts.path.exists() {
            panic!("Output file \"{}\" already exists", opts.path.to_str().unwrap());
        }

        Self {
            path: opts.path.clone(),
            cipher: ChaCha20Poly1305::new(&opts.key),
            slowkey: opts.slowkey.clone(),
        }
    }

    pub fn get(opts: &OpenOutputOptions) -> OutputData {
        if !opts.path.exists() {
            panic!("Output file \"{}\" does not exist", opts.path.to_str().unwrap());
        }

        if !opts.path.is_file() {
            panic!("Output file \"{}\" is not a file", opts.path.to_str().unwrap());
        }

        let file = File::open(&opts.path).unwrap();
        let mut reader = BufReader::new(file);

        // Read the first byte (version)
        let mut version_byte = [0u8; 1];
        reader.read_exact(&mut version_byte).unwrap();
        let version = Version::from(version_byte[0]);

        // Return the struct based on the version
        match version {
            Version::V1 => {
                let mut encrypted_data = Vec::new();
                reader.read_to_end(&mut encrypted_data).unwrap();

                let cipher = ChaCha20Poly1305::new(&opts.key);
                let data = cipher.decrypt(&hex::decode(encrypted_data).unwrap());

                OutputData {
                    version: Version::V1,
                    data,
                }
            },
        }
    }

    pub fn save(&self, iteration: usize, data: &[u8]) {
        let file = File::create(&self.path).unwrap();
        let mut writer = BufWriter::new(file);

        let output = OutputData {
            version: Version::V1,
            data: SlowKeyData {
                iteration,
                data: data.to_vec(),
                slowkey: self.slowkey.clone(),
            },
        };

        // Write the version as u8 first
        let version_byte: u8 = output.version.clone().into();
        writer.write_all(&[version_byte]).unwrap();

        let encrypted_data = self.cipher.encrypt(Nonce::Random, &output.data);

        writer.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        writer.flush().unwrap();
    }
}
