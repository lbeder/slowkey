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
    pub key: Option<Vec<u8>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct OpenSecretOptions {
    pub path: PathBuf,
    pub key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretData {
    pub encrypted: bool,
    #[serde(
        serialize_with = "serialize_bytes_as_hex",
        deserialize_with = "deserialize_hex_to_bytes"
    )]
    pub password: Vec<u8>,
    #[serde(
        serialize_with = "serialize_bytes_as_hex",
        deserialize_with = "deserialize_hex_to_bytes"
    )]
    pub salt: Vec<u8>,
}

fn serialize_bytes_as_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}

fn deserialize_hex_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let hex_str = if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        &s
    };
    hex::decode(hex_str).map_err(serde::de::Error::custom)
}

pub struct Secret {
    path: PathBuf,
    cipher: Option<ChaCha20Poly1305>,
}

impl Secret {
    pub fn new(opts: &SecretOptions) -> Self {
        Self {
            path: opts.path.clone(),
            cipher: opts.key.as_ref().map(|key| ChaCha20Poly1305::new(key)),
        }
    }

    #[allow(dead_code)]
    pub fn open(opts: &OpenSecretOptions) -> SecretData {
        if !opts.path.exists() {
            panic!("Secret file \"{}\" does not exist", opts.path.to_str().unwrap());
        }

        if !opts.path.is_file() {
            panic!("Secret file \"{}\" is not a file", opts.path.to_str().unwrap());
        }

        let file = File::open(&opts.path).unwrap();
        let mut reader = BufReader::new(file);

        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();

        let mut secret_data: SecretData = serde_json::from_slice(&data).unwrap();

        if secret_data.encrypted {
            if let Some(key) = &opts.key {
                let cipher = ChaCha20Poly1305::new(key);
                secret_data.password = cipher.decrypt(&hex::decode(&secret_data.password).unwrap());
                secret_data.salt = cipher.decrypt(&hex::decode(&secret_data.salt).unwrap());
            } else {
                panic!("Encryption key is required when encrypted is true");
            }
        }

        secret_data
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

        let mut data_to_save = data.clone();

        if data.encrypted {
            if let Some(cipher) = &self.cipher {
                let encrypted_password = hex::encode(cipher.encrypt(Nonce::Random, &data.password));
                let encrypted_salt = hex::encode(cipher.encrypt(Nonce::Random, &data.salt));
                data_to_save.password = encrypted_password.into_bytes();
                data_to_save.salt = encrypted_salt.into_bytes();
            } else {
                panic!("Encryption key is required when encrypted is true");
            }
        }

        let json_data = serde_json::to_string_pretty(&data_to_save).unwrap();
        writer.write_all(json_data.as_bytes()).unwrap();
        writer.flush().unwrap();
    }

    #[allow(dead_code)]
    pub fn reencrypt(input_path: &Path, key: Option<Vec<u8>>, output_path: &Path, new_key: Option<Vec<u8>>) {
        if !input_path.exists() {
            panic!("Input path \"{}\" does not exist", input_path.to_string_lossy());
        }

        if input_path.is_dir() {
            panic!("Input path \"{}\" is a directory", input_path.to_string_lossy());
        }

        if output_path.exists() {
            panic!("Output path \"{}\" already exists", output_path.to_string_lossy());
        }

        let secret_file = File::open(input_path).unwrap();
        let mut reader = BufReader::new(secret_file);

        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();

        let mut secret_data: SecretData = serde_json::from_slice(&data).unwrap();

        if secret_data.encrypted {
            if let Some(key) = key {
                let cipher = ChaCha20Poly1305::new(&key);
                secret_data.password = cipher.decrypt(&hex::decode(&secret_data.password).unwrap());
                secret_data.salt = cipher.decrypt(&hex::decode(&secret_data.salt).unwrap());

                if let Some(new_key) = new_key {
                    let new_cipher = ChaCha20Poly1305::new(&new_key);
                    let encrypted_password = hex::encode(new_cipher.encrypt(Nonce::Random, &secret_data.password));
                    let encrypted_salt = hex::encode(new_cipher.encrypt(Nonce::Random, &secret_data.salt));
                    secret_data.password = encrypted_password.into_bytes();
                    secret_data.salt = encrypted_salt.into_bytes();
                }
            } else {
                panic!("Encryption key is required when encrypted is true");
            }
        }

        let output_file = File::create(output_path).unwrap();
        let mut writer = BufWriter::new(output_file);

        let json_data = serde_json::to_string_pretty(&secret_data).unwrap();
        writer.write_all(json_data.as_bytes()).unwrap();
        writer.flush().unwrap();
    }
}
