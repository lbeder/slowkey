use super::version::Version;
use crate::log;
use crate::{
    slowkey::{SlowKey, SlowKeyOptions},
    utils::{
        algorithms::{
            argon2id::{Argon2id, Argon2idOptions},
            balloon_hash::{BalloonHash, BalloonHashOptions},
            scrypt::ScryptOptions,
        },
        chacha20poly1305::{ChaCha20Poly1305, Nonce},
    },
    DisplayOptions,
};

use base64::{engine::general_purpose, Engine as _};
use crossterm::style::Stylize;
use glob::{glob_with, MatchOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{remove_file, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

#[derive(PartialEq, Clone)]
pub struct CheckpointOptions {
    pub iterations: usize,
    pub dir: PathBuf,
    pub key: Vec<u8>,
    pub max_checkpoints_to_keep: usize,
    pub slowkey: SlowKeyOptions,
}

impl CheckpointOptions {
    pub const DEFAULT_CHECKPOINT_INTERVAL: usize = 1;
    pub const DEFAULT_MAX_CHECKPOINTS_TO_KEEP: usize = 1;
}

#[derive(PartialEq, Debug, Clone)]
pub struct OpenCheckpointOptions {
    pub path: PathBuf,
    pub key: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSlowKeyOptions {
    pub length: usize,
    pub scrypt: ScryptOptions,
    pub argon2id: Argon2idOptions,
    pub balloon_hash: BalloonHashOptions,
}

impl From<SlowKeyOptions> for CheckpointSlowKeyOptions {
    fn from(options: SlowKeyOptions) -> Self {
        CheckpointSlowKeyOptions {
            length: options.length,
            scrypt: options.scrypt,
            argon2id: options.argon2id,
            balloon_hash: options.balloon_hash,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SlowKeyData {
    pub iteration: usize,
    pub data: Vec<u8>,
    pub prev_data: Option<Vec<u8>>,
    pub slowkey: CheckpointSlowKeyOptions,
}

#[derive(Serialize, Deserialize)]
pub struct CheckpointData {
    pub version: Version,
    pub data: SlowKeyData,
}

impl CheckpointData {
    pub fn verify(&self, salt: &[u8], password: &[u8]) -> bool {
        let opts = &self.data.slowkey;

        // Use the checkpoint's previous data to derive the current data and return if it matches
        let options = SlowKeyOptions {
            iterations: self.data.iteration + 1,
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
            self.data.iteration,
        );

        key == self.data.data
    }

    pub fn print(&self, display: DisplayOptions) {
        let prev_data = match &self.data.prev_data {
            Some(data) => hex::encode(data),
            None => "".to_string(),
        };

        let mut output = format!(
            "{}:\n  {}: {}:\n  {}: {}:\n  {} (please highlight to see): {}\n  {} (please highlight to see): {}",
            "Checkpoint".yellow(),
            "Version".green(),
            u8::from(self.version.clone()),
            "Iteration".green(),
            (self.data.iteration + 1).to_string().cyan(),
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

        if display.options {
            let opts = &self.data.slowkey;

            output = format!(
                "{}\n\n{}:\n  {}: {}\n  {}: (log_n: {}, r: {}, p: {})\n  {}: (version: {}, m_cost: {}, t_cost: {})\n  {}: (hash: {}, s_cost: {}, t_cost: {})",
                output,
                "SlowKey Parameters".yellow(),
                "Length".green(),
                &opts.length.to_string().cyan(),
                "Scrypt".green(),
                &opts.scrypt.log_n().to_string().cyan(),
                &opts.scrypt.r().to_string().cyan(),
                &opts.scrypt.p().to_string().cyan(),
                "Argon2id".green(),
                Argon2id::VERSION.to_string().cyan(),
                &opts.argon2id.m_cost().to_string().cyan(),
                &opts.argon2id.t_cost().to_string().cyan(),
                "Balloon Hash".green(),
                BalloonHash::HASH.cyan(),
                &opts.balloon_hash.s_cost().to_string().cyan(),
                &opts.balloon_hash.t_cost().to_string().cyan()
            );
        }

        log!("{}\n", output);
    }
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
            panic!("Checkpoints directory \"{}\" does not exist", opts.dir.display());
        }

        if !opts.dir.is_dir() {
            panic!("Checkpoints directory \"{}\" is not a directory", opts.dir.display());
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
                opts.dir.display()
            );
        }

        Self {
            dir: opts.dir.clone(),
            data: CheckpointData {
                version: Version::V2,
                data: SlowKeyData {
                    iteration: 0,
                    data: Vec::new(),
                    prev_data: None,
                    slowkey: opts.slowkey.clone().into(),
                },
            },
            checkpoint_extension_padding: (opts.iterations as f64).log10().round() as usize + 1,
            checkpoint_paths: VecDeque::with_capacity(opts.max_checkpoints_to_keep),
            cipher: ChaCha20Poly1305::new(&opts.key),
        }
    }

    pub fn create(&mut self, iteration: usize, data: &[u8], prev_data: Option<&[u8]>) {
        let hash = Self::hash(iteration, data, prev_data);
        let padding = self.checkpoint_extension_padding;
        let checkpoint_path = Path::new(&self.dir)
            .join(Self::CHECKPOINT_PREFIX)
            .with_extension(format!("{:0padding$}.{}", iteration + 1, hex::encode(hash)));

        let checkpoint = CheckpointData {
            version: Version::V2,
            data: SlowKeyData {
                iteration,
                data: data.to_vec(),
                prev_data: prev_data.map(|slice| slice.to_vec()),
                slowkey: self.data.data.slowkey.clone(),
            },
        };

        self.save(&checkpoint_path, &checkpoint);

        self.data = CheckpointData {
            version: Version::V2,
            data: checkpoint.data,
        }
    }

    pub fn hash(iteration: usize, data: &[u8], prev_data: Option<&[u8]>) -> Vec<u8> {
        let mut hash_data = data.to_vec();
        hash_data.extend_from_slice(&iteration.to_be_bytes());

        if let Some(prev_data) = prev_data {
            hash_data.extend_from_slice(prev_data);
        }

        let mut sha256 = Sha256::new();
        sha256.update(hash_data);
        sha256.finalize().to_vec()
    }

    pub fn open(opts: &OpenCheckpointOptions) -> CheckpointData {
        if opts.path.is_dir() {
            panic!("Checkpoint file \"{}\" is a directory", opts.path.display());
        }

        if !opts.path.exists() {
            panic!("Checkpoint file \"{}\" does not exist", opts.path.display());
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

                CheckpointData { version, data }
            },
        }
    }

    fn save(&mut self, checkpoint_path: &Path, checkpoint: &CheckpointData) {
        let file = File::create(checkpoint_path).unwrap();
        let mut writer = BufWriter::new(file);

        // Write the version as u8 first
        let version_byte: u8 = checkpoint.version.clone().into();
        writer.write_all(&[version_byte]).unwrap();

        let encrypted_data = self.cipher.encrypt(Nonce::Random, &checkpoint.data);

        writer.write_all(hex::encode(encrypted_data).as_bytes()).unwrap();
        writer.flush().unwrap();

        // Ensure that the checkpoints queue does not exceed the fixed capacity
        if self.checkpoint_paths.len() == self.checkpoint_paths.capacity() {
            if let Some(path) = self.checkpoint_paths.pop_front() {
                remove_file(path).unwrap();
            }
        }

        self.checkpoint_paths.push_back(checkpoint_path.to_path_buf());
    }

    pub fn reencrypt(input_path: &Path, key: Vec<u8>, output_path: &Path, new_key: Vec<u8>) {
        if !input_path.exists() {
            panic!("Input path \"{}\" does not exist", input_path.display());
        }

        if input_path.is_dir() {
            panic!("Input path \"{}\" is a directory", input_path.display());
        }

        if output_path.exists() {
            panic!("Output path \"{}\" already exists", output_path.display());
        }

        let checkpoint_file = File::open(input_path).unwrap();
        let mut reader = BufReader::new(checkpoint_file);

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
