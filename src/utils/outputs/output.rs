use super::{fingerprint::Fingerprint, version::Version};
use crate::{
    slowkey::{SlowKey, SlowKeyOptions},
    utils::chacha20poly1305::{ChaCha20Poly1305, Nonce},
    DisplayOptions,
};
use base64::{engine::general_purpose, Engine as _};
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

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
        let opts = &self.data.slowkey;

        // Use the checkpoint's previous data to derive the current data and return if it matches
        let options = SlowKeyOptions {
            iterations: opts.iterations,
            length: opts.length,
            scrypt: opts.scrypt,
            argon2id: opts.argon2id,
            balloon_hash: opts.balloon_hash,
        };

        let slowkey = SlowKey::new(&options);
        let key = slowkey.derive_key(
            salt,
            password,
            &self.data.prev_data.clone().unwrap_or_default(),
            opts.iterations - 1,
        );

        key == self.data.data
    }

    pub fn print(&self, display: DisplayOptions) {
        let prev_data = match &self.data.prev_data {
            Some(data) => hex::encode(data),
            None => "".to_string(),
        };

        let mut output = format!(
            "{}:\n  {}: {}:\n  {} (please highlight to see): {}\n  {} (please highlight to see): {}",
            "Output".yellow(),
            "Version".green(),
            u8::from(self.version.clone()),
            "Data".green(),
            format!("0x{}", hex::encode(&self.data.data)).black().on_black(),
            "Previous Iteration's Data".green(),
            format!("0x{}", prev_data).black().on_black()
        );

        if display.base64 {
            output = format!(
                "{}\n  {} (please highlight to see): {}\n  {} (please highlight to see): {}",
                output,
                "Data (base64)".green(),
                general_purpose::STANDARD.encode(&self.data.data).black().on_black(),
                "Previous Iteration's Data (base64)".green(),
                general_purpose::STANDARD.encode(&prev_data).black().on_black()
            );
        }

        if display.base58 {
            output = format!(
                "{}\n  {} (please highlight to see): {}\n  {} (please highlight to see): {}",
                output,
                "Data (base58)".green(),
                bs58::encode(&self.data.data).into_string().black().on_black(),
                "Previous Iteration's Data (base58)".green(),
                bs58::encode(&prev_data).into_string().black().on_black()
            );
        }

        println!("{}\n", output);

        if display.options {
            self.data.slowkey.print();
        }

        self.data.fingerprint.print();
    }
}

#[derive(Serialize, Deserialize)]
pub struct SlowKeyData {
    pub data: Vec<u8>,
    pub prev_data: Option<Vec<u8>>,
    pub fingerprint: Fingerprint,
    pub slowkey: SlowKeyOptions,
}

pub struct Output {
    pub path: PathBuf,
    cipher: ChaCha20Poly1305,
    slowkey: SlowKeyOptions,
}

impl Output {
    pub fn new(opts: &OutputOptions) -> Self {
        Self {
            path: opts.path.clone(),
            cipher: ChaCha20Poly1305::new(&opts.key),
            slowkey: opts.slowkey.clone(),
        }
    }

    pub fn open(opts: &OpenOutputOptions) -> OutputData {
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
            Version::V2 => {
                let mut encrypted_data = Vec::new();
                reader.read_to_end(&mut encrypted_data).unwrap();

                let cipher = ChaCha20Poly1305::new(&opts.key);
                let data = cipher.decrypt(&hex::decode(encrypted_data).unwrap());

                OutputData { version, data }
            },
        }
    }

    pub fn save(&self, data: &[u8], prev_data: Option<&[u8]>, fingerprint: &Fingerprint) {
        let file = File::create(&self.path).unwrap();
        let mut writer = BufWriter::new(file);

        let output = OutputData {
            version: Version::V2,
            data: SlowKeyData {
                data: data.to_vec(),
                prev_data: prev_data.map(|slice| slice.to_vec()),
                fingerprint: fingerprint.clone(),
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

        let output_file = File::open(input_path).unwrap();
        let mut reader = BufReader::new(output_file);

        // Read the first byte (version)
        let mut version_byte = [0u8; 1];
        reader.read_exact(&mut version_byte).unwrap();

        // Read the rest of the data
        let mut encrypted_data = Vec::new();
        reader.read_to_end(&mut encrypted_data).unwrap();

        // Decrypt tje data
        let cipher = ChaCha20Poly1305::new(&key);
        let data: SlowKeyData = cipher.decrypt(&hex::decode(encrypted_data).unwrap());

        // Reencrypt the data
        let new_cipher = ChaCha20Poly1305::new(&new_key);
        let reencrypted_data = new_cipher.encrypt(Nonce::Random, &data);

        let output_file = File::create(output_path).unwrap();
        let mut writer = BufWriter::new(output_file);

        // Write the first byte (version)
        writer.write_all(&version_byte).unwrap();

        // Write the rest of the data
        writer.write_all(hex::encode(reencrypted_data).as_bytes()).unwrap();
        writer.flush().unwrap();
    }
}
