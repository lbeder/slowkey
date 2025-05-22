use crate::utils::chacha20poly1305::{ChaCha20Poly1305, Nonce};
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
pub struct SecretData {
    pub password: String,
    pub salt: String,
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
            panic!("Secret file \"{}\" does not exist", self.path.to_str().unwrap());
        }

        if !self.path.is_file() {
            panic!("Secret file \"{}\" is not a file", self.path.to_str().unwrap());
        }

        let file = File::open(&self.path).unwrap();
        let mut reader = BufReader::new(file);

        let mut encrypted_data = Vec::new();
        reader.read_to_end(&mut encrypted_data).unwrap();

        // Decrypt the entire file content
        let decrypted_data = self.cipher.decrypt_raw(&encrypted_data);

        // Deserialize the decrypted data
        serde_json::from_slice(&decrypted_data).unwrap()
    }

    pub fn save(&self, data: &SecretData) {
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).unwrap();
            }
        }

        if self.path.exists() {
            panic!("Secret file \"{}\" already exists", self.path.to_str().unwrap());
        }

        let file = File::create(&self.path).unwrap();
        let mut writer = BufWriter::new(file);

        // Serialize the data to JSON
        let json_data = serde_json::to_string_pretty(&data).unwrap();

        // Encrypt the entire JSON data
        let encrypted_data = self.cipher.encrypt_raw(Nonce::Random, json_data.as_bytes());

        // Write the encrypted data to the file
        writer.write_all(&encrypted_data).unwrap();
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
