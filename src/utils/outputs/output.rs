use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

use crate::{
    slowkey::{SlowKey, SlowKeyOptions},
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

impl OutputData {
    pub fn verify(&self, salt: &[u8], password: &[u8]) -> bool {
        // Use the checkpoint's previous data to derive the current data and return if it matches
        let options = SlowKeyOptions {
            iterations: self.data.iteration,
            length: self.data.slowkey.length,
            scrypt: self.data.slowkey.scrypt,
            argon2id: self.data.slowkey.argon2id,
        };

        let prev_data = match &self.data.prev_data {
            Some(data) => data,
            None => panic!("Unable to verify the output!"),
        };

        let slowkey = SlowKey::new(&options);
        let key = slowkey.derive_key(salt, password, prev_data, self.data.iteration - 1);

        key == self.data.data
    }
}

impl Display for OutputData {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let prev_data = match &self.data.prev_data {
            Some(data) => hex::encode(data),
            None => "".to_string(),
        };

        let output = format!(
            "{}:\n  {}: {}\n  {} (please highlight to see): {}\n  {} (please highlight to see): {}",
            "Output".yellow(),
            "Iterations".green(),
            self.data.iteration,
            "Data".green(),
            format!("0x{}", hex::encode(&self.data.data)).black().on_black(),
            "Previous Iteration's Data".green(),
            format!("0x{}", prev_data).black().on_black()
        );

        write!(f, "{}", output)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SlowKeyData {
    pub iteration: usize,
    pub data: Vec<u8>,
    pub prev_data: Option<Vec<u8>>,
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

    pub fn save(&self, iteration: usize, data: &[u8], prev_data: Option<&[u8]>) {
        let file = File::create(&self.path).unwrap();
        let mut writer = BufWriter::new(file);

        let output = OutputData {
            version: Version::V1,
            data: SlowKeyData {
                iteration,
                data: data.to_vec(),
                prev_data: prev_data.map(|slice| slice.to_vec()),
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
