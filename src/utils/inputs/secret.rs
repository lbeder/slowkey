use super::version::Version;
use crate::log;
use crate::utils::chacha20poly1305::{ChaCha20Poly1305, Nonce};
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

#[derive(PartialEq, Debug, Clone)]
pub struct SecretOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretInnerData {
    pub password: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretData {
    pub version: Version,
    pub data: SecretInnerData,
}

impl SecretData {
    pub fn print(&self) {
        let output = format!(
            "{}:\n  {}: {}\n  {} (please highlight to see): {}\n  {} (please highlight to see): {}",
            "Secrets".yellow(),
            "Version".green(),
            u8::from(self.version.clone()),
            "Salt".green(),
            self.data.salt.as_str().black().on_black(),
            "Password".green(),
            self.data.password.as_str().black().on_black()
        );

        log!("{}\n", output);
    }
}

pub struct Secret {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
}

impl Secret {
    pub fn new(opts: &SecretOptions) -> Self {
        Self {
            path: opts.path.clone(),
            cipher: ChaCha20Poly1305::new(&opts.key),
        }
    }

    pub fn open(&self) -> SecretData {
        if !self.path.exists() {
            panic!("Secrets file \"{}\" does not exist", self.path.to_str().unwrap());
        }

        if !self.path.is_file() {
            panic!("Secrets file \"{}\" is not a file", self.path.to_str().unwrap());
        }

        let file = File::open(&self.path).unwrap();
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

                let data = self.cipher.decrypt(&hex::decode(encrypted_data).unwrap());

                SecretData { version, data }
            },
        }
    }

    pub fn save(&self, data: &SecretData) {
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).unwrap();
            }
        }

        if self.path.exists() {
            panic!("Secrets file \"{}\" already exists", self.path.to_str().unwrap());
        }

        let file = File::create(&self.path).unwrap();
        let mut writer = BufWriter::new(file);

        // Write the version as u8 first
        let version_byte: u8 = data.version.clone().into();
        writer.write_all(&[version_byte]).unwrap();

        let encrypted_data = self.cipher.encrypt(Nonce::Random, &data.data);

        writer.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        writer.flush().unwrap();
    }

    pub fn reencrypt(input_path: &Path, key: Vec<u8>, output_path: &Path, new_key: Vec<u8>) {
        if !input_path.exists() {
            panic!("Input path \"{}\" does not exist", input_path.to_string_lossy());
        }

        if input_path.is_dir() {
            panic!("Input path \"{}\" is a directory", input_path.to_string_lossy());
        }

        if output_path.exists() {
            panic!("Output path \"{}\" already exists", output_path.to_string_lossy());
        }

        let input_secret = Secret::new(&SecretOptions {
            path: input_path.to_path_buf(),
            key,
        });

        let decrypted_data = input_secret.open();

        let output_secret = Secret::new(&SecretOptions {
            path: output_path.to_path_buf(),
            key: new_key,
        });

        output_secret.save(&decrypted_data);
    }
}
