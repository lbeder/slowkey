use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use glob::{glob_with, MatchOptions};
use serde::{Deserialize, Serialize};

use crate::slowkey::SlowKeyOptions;

#[derive(PartialEq, Debug, Clone)]
pub struct CheckpointOptions {
    pub iterations: usize,
    pub dir: PathBuf,
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
    pub iteration: usize,
    pub data: Vec<u8>,
    pub slowkey: SlowKeyOptions,
}

pub struct Checkpoint {
    dir: PathBuf,
    key: Vec<u8>,
    data: CheckpointData,
    padding: usize,
}

impl Checkpoint {
    const CHECKPOINT_PREFIX: &'static str = "checkpoint";
    const CHECKPOINTS_PATTERN: &'static str = "checkpoint.[0-9]*";

    pub const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12; // 96 bits

    pub fn new(opts: &CheckpointOptions) -> Self {
        if opts.key.len() != Self::KEY_SIZE {
            panic!("key must be {} long", Self::KEY_SIZE);
        }

        if !opts.dir.exists() {
            panic!(
                "Checkpoints directory \"{}\" does not exist",
                opts.dir.to_str().unwrap()
            );
        }

        if !opts.dir.is_dir() {
            panic!(
                "Checkpoints directory \"{}\" is not a directory",
                opts.dir.to_str().unwrap()
            );
        }

        if !Vec::from_iter(
            glob_with(
                opts.dir.join(Self::CHECKPOINTS_PATTERN).to_str().unwrap(),
                MatchOptions {
                    case_sensitive: false,
                    require_literal_separator: false,
                    require_literal_leading_dot: false,
                },
            )
            .unwrap(),
        )
        .is_empty()
        {
            panic!(
                "Checkpoints directory \"{}\" is not empty and contains existing checkpoint files",
                opts.dir.to_str().unwrap()
            );
        }

        Self {
            dir: opts.dir.clone(),
            key: opts.key.clone(),
            data: CheckpointData {
                iteration: 0,
                data: Vec::new(),
                slowkey: opts.slowkey.clone(),
            },
            padding: (opts.iterations as f64).log10().round() as usize + 1,
        }
    }

    pub fn get(opts: &OpenCheckpointOptions) -> CheckpointData {
        if opts.key.len() != Self::KEY_SIZE {
            panic!("key must be {} long", Self::KEY_SIZE);
        }

        if opts.path.is_dir() {
            panic!("Checkpoint file \"{}\" is a directory", opts.path.to_str().unwrap());
        }

        if !opts.path.exists() {
            panic!("Checkpoint file \"{}\" does not exist", opts.path.to_str().unwrap());
        }

        let mut encrypted_data = Vec::new();
        File::open(&opts.path)
            .unwrap()
            .read_to_end(&mut encrypted_data)
            .unwrap();

        Self::decrypt(&hex::decode(encrypted_data).unwrap(), &opts.key)
    }

    pub fn create_checkpoint(&mut self, iteration: usize, data: &[u8]) {
        let encrypted_data = Self::encrypt(iteration, data, &self.data.slowkey, &self.key);

        let padding = self.padding;
        let final_path = Path::new(&self.dir)
            .join(Self::CHECKPOINT_PREFIX)
            .with_extension(format!("{:0padding$}", iteration + 1));
        let mut file = tempfile::NamedTempFile::new_in(final_path.parent().unwrap()).unwrap();

        file.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        file.persist(final_path).unwrap();

        self.data.iteration = iteration;
        self.data.data = data.to_vec();
    }

    fn encrypt(iteration: usize, data: &[u8], slowkey: &SlowKeyOptions, key: &[u8]) -> Vec<u8> {
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
