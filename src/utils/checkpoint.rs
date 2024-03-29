use crate::slowkey::SlowKeyOptions;

use glob::{glob_with, MatchOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{remove_file, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::chacha20poly1305::{ChaCha20Poly1305, Nonce};

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
    data: CheckpointData,
    checkpoint_extension_padding: usize,
    checkpoint_paths: VecDeque<PathBuf>,
    cipher: ChaCha20Poly1305,
}

impl Checkpoint {
    const CHECKPOINT_PREFIX: &'static str = "checkpoint";
    const CHECKPOINTS_PATTERN: &'static str = "checkpoint.[0-9]*";

    pub fn new(opts: &CheckpointOptions) -> Self {
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
            data: CheckpointData {
                iteration: 0,
                data: Vec::new(),
                slowkey: opts.slowkey.clone(),
            },
            checkpoint_extension_padding: (opts.iterations as f64).log10().round() as usize + 1,
            checkpoint_paths: VecDeque::with_capacity(opts.max_checkpoints_to_keep),
            cipher: ChaCha20Poly1305::new(&opts.key),
        }
    }

    pub fn get(opts: &OpenCheckpointOptions) -> CheckpointData {
        let cipher = ChaCha20Poly1305::new(&opts.key);

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

        cipher.decrypt(&hex::decode(encrypted_data).unwrap())
    }

    pub fn create_checkpoint(&mut self, salt: &[u8], iteration: usize, data: &[u8]) {
        let encrypted_data = self.cipher.encrypt(
            Nonce::Random,
            &CheckpointData {
                iteration,
                data: data.to_vec(),
                slowkey: self.data.slowkey.clone(),
            },
        );

        let hash = Self::hash_checkpoint(salt, iteration, data);
        let padding = self.checkpoint_extension_padding;
        let checkpoint_path = Path::new(&self.dir)
            .join(Self::CHECKPOINT_PREFIX)
            .with_extension(format!("{:0padding$}.{}", iteration + 1, hex::encode(hash)));

        self.store_checkpoint(&checkpoint_path, &encrypted_data);

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

    fn store_checkpoint(&mut self, checkpoint_path: &Path, data: &[u8]) {
        let mut file = tempfile::NamedTempFile::new_in(checkpoint_path.parent().unwrap()).unwrap();

        file.write_all(hex::encode(data).as_bytes()).unwrap();
        file.persist(checkpoint_path).unwrap();

        // Ensure that the checkpoints queue does not exceed the fixed capacity
        if self.checkpoint_paths.len() == self.checkpoint_paths.capacity() {
            if let Some(path) = self.checkpoint_paths.pop_front() {
                remove_file(path).unwrap();
            }
        }

        self.checkpoint_paths.push_back(checkpoint_path.to_path_buf());
    }
}
