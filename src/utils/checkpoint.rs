use crate::slowkey::SlowKeyOptions;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use glob::{glob_with, MatchOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{remove_file, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(PartialEq, Debug, Clone)]
pub struct CheckpointOptions {
    pub iterations: usize,
    pub dir: PathBuf,
    pub key: Vec<u8>,
    pub max_checkpoints_to_keep: usize,
    pub slowkey: SlowKeyOptions,
}

impl CheckpointOptions {
    pub const DEFAULT_MAX_CHECKPOINTS_TO_KEEP: usize = 1;
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
    checkpoint_extension_padding: usize,
    checkpoint_paths: VecDeque<PathBuf>,
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

        if opts.max_checkpoints_to_keep == 0 {
            panic!("Invalid max checkpoints to keep value");
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
            checkpoint_extension_padding: (opts.iterations as f64).log10().round() as usize + 1,
            checkpoint_paths: VecDeque::with_capacity(opts.max_checkpoints_to_keep),
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

    pub fn create_checkpoint(&mut self, salt: &[u8], iteration: usize, data: &[u8]) {
        let encrypted_data = Self::encrypt(iteration, data, &self.data.slowkey, &self.key);

        let hash = Self::hash_checkpoint(salt, iteration, data);
        let padding = self.checkpoint_extension_padding;
        let checkpoint_path = Path::new(&self.dir)
            .join(Self::CHECKPOINT_PREFIX)
            .with_extension(format!("{:0padding$}.{}", iteration + 1, hex::encode(hash)));
        let mut file = tempfile::NamedTempFile::new_in(checkpoint_path.parent().unwrap()).unwrap();

        file.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        file.persist(&checkpoint_path).unwrap();

        self.process_checkpoints(&checkpoint_path);

        self.data.iteration = iteration;
        self.data.data = data.to_vec();
    }

    pub fn hash_checkpoint(salt: &[u8], iteration: usize, data: &[u8]) -> Vec<u8> {
        let mut salted_data = data.to_vec();
        salted_data.extend_from_slice(salt);
        salted_data.extend_from_slice(&iteration.to_be_bytes());

        let mut sha256 = Sha256::new();
        sha256.update(salted_data);
        sha256.finalize().to_vec()
    }

    fn process_checkpoints(&mut self, last_checkpoint_path: &Path) {
        // Ensure that the checkpoints queue does not exceed the fixed capacity
        if self.checkpoint_paths.len() == self.checkpoint_paths.capacity() {
            if let Some(path) = self.checkpoint_paths.pop_front() {
                remove_file(path).unwrap();
            }
        }

        self.checkpoint_paths.push_back(last_checkpoint_path.to_path_buf());
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
