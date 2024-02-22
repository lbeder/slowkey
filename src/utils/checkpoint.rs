use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};

use crate::slowkey::SlowKeyOptions;

#[derive(PartialEq, Debug, Clone)]
pub struct CheckpointOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
    pub slowkey: SlowKeyOptions,
}

#[derive(PartialEq, Debug, Clone)]
pub struct OpenCheckpointOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct CheckpointData {
    pub iteration: u32,
    pub data: Vec<u8>,
    pub slowkey: SlowKeyOptions,
}

pub struct Checkpoint {
    path: PathBuf,
    key: Vec<u8>,
    data: CheckpointData,
}

impl Checkpoint {
    pub const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12; // 96 bits

    pub fn new(opts: &CheckpointOptions) -> Self {
        if opts.key.len() != Self::KEY_SIZE {
            panic!("key must be {} long", Self::KEY_SIZE);
        }

        if opts.path.is_dir() {
            panic!("Checkpoints file \"{}\" is a directory", opts.path.to_str().unwrap());
        }

        if opts.path.exists() {
            panic!("Checkpoints file \"{}\" already exists", opts.path.to_str().unwrap());
        }

        Self {
            path: opts.path.clone(),
            key: opts.key.clone(),
            data: CheckpointData {
                iteration: 0,
                data: Vec::new(),
                slowkey: opts.slowkey.clone(),
            },
        }
    }

    pub fn open(opts: &OpenCheckpointOptions) -> Self {
        if opts.key.len() != Self::KEY_SIZE {
            panic!("key must be {} long", Self::KEY_SIZE);
        }

        if opts.path.is_dir() {
            panic!("Checkpoints file \"{}\" is a directory", opts.path.to_str().unwrap());
        }

        if !opts.path.exists() {
            panic!("Checkpoints file \"{}\" does not exist", opts.path.to_str().unwrap());
        }

        let mut encrypted_data = Vec::new();
        File::open(&opts.path)
            .unwrap()
            .read_to_end(&mut encrypted_data)
            .unwrap();

        let data = Self::decrypt(&hex::decode(encrypted_data).unwrap(), &opts.key);

        Self {
            path: opts.path.clone(),
            key: opts.key.clone(),
            data,
        }
    }

    pub fn checkpoint(&self) -> &CheckpointData {
        &self.data
    }

    pub fn create_checkpoint(&mut self, iteration: u32, data: &[u8]) {
        let encrypted_data = Self::encrypt(iteration, data, &self.data.slowkey, &self.key);

        let final_path = Path::new(&self.path);
        let mut file = tempfile::NamedTempFile::new_in(final_path.parent().unwrap()).unwrap();

        file.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        file.persist(final_path).unwrap();

        self.data.iteration = iteration;
        self.data.data = data.to_vec();
    }

    fn encrypt(iteration: u32, data: &[u8], slowkey: &SlowKeyOptions, key: &[u8]) -> Vec<u8> {
        let json = serde_json::to_string(&CheckpointData {
            iteration,
            data: data.to_vec(),
            slowkey: slowkey.clone(),
        })
        .unwrap();

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let encrypted_data = cipher.encrypt(&nonce, json.as_bytes()).unwrap();

        // Return the random nonce and the encrypted data
        [nonce.as_slice(), encrypted_data.as_slice()].concat()
    }

    fn decrypt(encrypted_data: &[u8], key: &[u8]) -> CheckpointData {
        // Split the nonce and the encrypted data
        let (raw_nonce, json) = encrypted_data.split_at(Self::NONCE_SIZE);

        let cipher = ChaCha20Poly1305::new(key.into());

        serde_json::from_slice(&cipher.decrypt(Nonce::from_slice(raw_nonce), json.as_ref()).unwrap()).unwrap()
    }
}
