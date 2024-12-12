mod utils;

extern crate chacha20poly1305;
extern crate hex;
extern crate indicatif;
extern crate libsodium_sys;
extern crate serde;
extern crate serde_json;

mod slowkey;

use crate::{
    slowkey::{SlowKey, SlowKeyOptions},
    utils::sodium_init::initialize,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use crossterm::style::Stylize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use humantime::format_duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use mimalloc::MiMalloc;
use sha2::{Digest, Sha512};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    env,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};
use utils::{
    algorithms::{argon2id::Argon2idOptions, balloon_hash::BalloonHashOptions, scrypt::ScryptOptions},
    chacha20poly1305::ChaCha20Poly1305,
    checkpoints::{
        checkpoint::{
            Checkpoint, CheckpointData, CheckpointOptions, CheckpointSlowKeyOptions, OpenCheckpointOptions, SlowKeyData,
        },
        version::Version,
    },
    color_hash::color_hash,
    file_lock::FileLock,
    outputs::{
        fingerprint::Fingerprint,
        output::{OpenOutputOptions, Output, OutputOptions},
    },
};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(author, about, long_about = None, arg_required_else_help = true, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Derive a key using using Scrypt, Argon2, Balloon Hash, SHA2, and SHA3")]
    Derive {
        #[arg(
            short,
            long,
            help = format!("Number of iterations (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_ITERATIONS, SlowKeyOptions::MAX_ITERATIONS)
        )]
        iterations: usize,

        #[arg(
            short,
            long,
            default_value = SlowKeyOptions::DEFAULT_KEY_SIZE.to_string(),
            help = format!("Length of the derived result (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_KEY_SIZE, SlowKeyOptions::MAX_KEY_SIZE)
        )]
        length: usize,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_N.to_string(),
            help = format!("Scrypt CPU/memory cost parameter (must be lesser than {})", ScryptOptions::MAX_N)
        )]
        scrypt_n: u64,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_R.to_string(),
            help = format!("Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than {} and lesser than or equal to {})", ScryptOptions::MIN_R, ScryptOptions::MAX_R)
        )]
        scrypt_r: u32,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_P.to_string(),
            help = format!("Scrypt parallelization parameter (must be greater than {} and lesser than {})", ScryptOptions::MIN_P, ScryptOptions::MAX_P)
        )]
        scrypt_p: u32,

        #[arg(
            long,
            default_value = Argon2idOptions::DEFAULT_M_COST.to_string(),
            help = format!("Argon2 number of 1 KiB memory block (must be greater than {} and lesser than {})", Argon2idOptions::MIN_M_COST, Argon2idOptions::MAX_M_COST))]
        argon2_m_cost: u32,

        #[arg(
            long,
            default_value = Argon2idOptions::DEFAULT_T_COST.to_string(),
            help = format!("Argon2 number of iterations (must be greater than {} and lesser than {})", Argon2idOptions::MIN_T_COST, Argon2idOptions::MAX_T_COST))]
        argon2_t_cost: u32,

        #[arg(
            long,
            default_value = BalloonHashOptions::DEFAULT_S_COST.to_string(),
            help = format!("Balloon Hash space (memory) cost number of 1 KiB memory block (must be greater than {} and lesser than {})", BalloonHashOptions::MIN_S_COST, BalloonHashOptions::MAX_S_COST))]
        balloon_s_cost: u32,

        #[arg(
            long,
            default_value = BalloonHashOptions::DEFAULT_T_COST.to_string(),
            help = format!("Balloon Hash number of iterations (must be greater than {} and lesser than {})", BalloonHashOptions::MIN_T_COST, BalloonHashOptions::MAX_T_COST))]
        balloon_t_cost: u32,

        #[arg(long, help = "Optional path for storing the encrypted output")]
        output: Option<PathBuf>,

        #[arg(
            long,
            help = "Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named \"checkpoint.i\", indicating the iteration number at which the checkpoint was created"
        )]
        checkpoint_dir: Option<PathBuf>,

        #[arg(
            long,
            default_value = CheckpointOptions::DEFAULT_CHECKPOINT_INTERVAL.to_string(),
            requires = "checkpoint_dir",
            help = "Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save"
        )]
        checkpoint_interval: usize,

        #[arg(
            long,
            default_value = CheckpointOptions::DEFAULT_MAX_CHECKPOINTS_TO_KEEP.to_string(),
            requires = "checkpoint_dir",
            help = format!("Specifies the number of most recent checkpoints to keep, while automatically deleting older ones")
        )]
        max_checkpoints_to_keep: usize,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base64 (in addition to hex)"
        )]
        base64: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base58 (in addition to hex)"
        )]
        base58: bool,

        #[arg(long, default_value = "10", help = "Iteration time sampling moving window size")]
        iteration_moving_window: u32,
    },

    #[command(
        about = "Continue derivation process from an existing checkpoint",
        arg_required_else_help = true
    )]
    RestoreFromCheckpoint {
        #[arg(
            short,
            long,
            help = format!("Number of iterations (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_ITERATIONS, SlowKeyOptions::MAX_ITERATIONS)
        )]
        iterations: usize,

        #[arg(long, help = "Optional path for storing the encrypted output")]
        output: Option<PathBuf>,

        #[arg(
            long,
            help = "Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named \"checkpoint.i\", indicating the iteration number at which the checkpoint was created"
        )]
        checkpoint_dir: Option<PathBuf>,

        #[arg(
            long,
            default_value = CheckpointOptions::DEFAULT_CHECKPOINT_INTERVAL.to_string(),
            requires = "checkpoint_dir",
            help = "Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save"
        )]
        checkpoint_interval: usize,

        #[arg(
            long,
            default_value = CheckpointOptions::DEFAULT_MAX_CHECKPOINTS_TO_KEEP.to_string(),
            requires = "checkpoint_dir",
            help = format!("Specifies the number of most recent checkpoints to keep, while automatically deleting older ones")
        )]
        max_checkpoints_to_keep: usize,

        #[arg(
            long,
            help = "Path to an existing checkpoint from which to resume the derivation process"
        )]
        checkpoint: Option<PathBuf>,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Input checkpoint data interactively (instead of providing the path to an existing checkpoint)"
        )]
        interactive: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base64 (in addition to hex)"
        )]
        base64: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base58 (in addition to hex)"
        )]
        base58: bool,

        #[arg(long, default_value = "10", help = "Iteration time sampling moving window size")]
        iteration_moving_window: u32,
    },

    #[command(about = "Decrypt and print a checkpoint", arg_required_else_help = true)]
    ShowCheckpoint {
        #[arg(long, help = "Path to an existing checkpoint")]
        checkpoint: PathBuf,

        #[arg(long, help = "Verify that the password and salt match the checkpoint")]
        verify: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base64 (in addition to hex)"
        )]
        base64: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base58 (in addition to hex)"
        )]
        base58: bool,
    },

    #[command(about = "Decrypt and print an output file", arg_required_else_help = true)]
    ShowOutput {
        #[arg(long, help = "Path to an existing output")]
        output: PathBuf,

        #[arg(long, help = "Verify that the password and salt match the output")]
        verify: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base64 (in addition to hex)"
        )]
        base64: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Show the result in Base58 (in addition to hex)"
        )]
        base58: bool,
    },

    #[command(about = "Run benchmarks")]
    Bench {},
}

const BENCHMARKS_DIRECTORY: &str = "benchmarks";
const HEX_PREFIX: &str = "0x";
const MIN_SECRET_LENGTH_TO_REVEAL: usize = 8;

#[derive(PartialEq, Debug, Clone, Default)]
pub struct DisplayOptions {
    pub base64: bool,
    pub base58: bool,
    pub options: bool,
}

fn get_salt() -> Vec<u8> {
    let input_salt = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your salt")
        .with_confirmation("Enter your salt again", "Error: salts don't match")
        .allow_empty_password(true)
        .interact()
        .unwrap();

    let mut hex = false;
    let mut salt = if input_salt.starts_with(HEX_PREFIX) {
        hex = true;
        hex::decode(input_salt.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input_salt.as_bytes().to_vec()
    };

    show_hint(&input_salt, "Salt", hex);

    let salt_len = salt.len();
    match salt_len {
        0 => {
            println!(
                "\nSalt is empty; a default {}-byte zero-filled salt will be used.",
                SlowKey::SALT_SIZE
            );

            let confirmation = Confirm::new()
                .with_prompt("Do you want to continue?")
                .wait_for_newline(true)
                .interact()
                .unwrap();

            if confirmation {
                salt = SlowKey::DEFAULT_SALT.to_vec();
            } else {
                panic!("Aborting");
            }
        },
        _ => match salt_len.cmp(&SlowKey::SALT_SIZE) {
            Ordering::Less => {
                println!(
                    "\nSalt's length {} is shorter than {} and will be SHA512 hashed and then truncated into {} bytes.",
                    salt_len,
                    SlowKey::SALT_SIZE,
                    SlowKey::SALT_SIZE
                );

                let confirmation = Confirm::new()
                    .with_prompt("Do you want to continue?")
                    .wait_for_newline(true)
                    .interact()
                    .unwrap();

                if confirmation {
                    let mut sha512 = Sha512::new();
                    sha512.update(&salt);
                    salt = sha512.finalize().to_vec();

                    salt.truncate(SlowKey::SALT_SIZE);
                } else {
                    panic!("Aborting");
                }
            },
            Ordering::Greater => {
                println!(
                    "\nSalt's length {} is longer than {} and will be SHA512 hashed and then truncated into {} bytes.",
                    salt_len,
                    SlowKey::SALT_SIZE,
                    SlowKey::SALT_SIZE
                );

                let confirmation = Confirm::new()
                    .with_prompt("Do you want to continue?")
                    .wait_for_newline(true)
                    .interact()
                    .unwrap();

                if confirmation {
                    let mut sha512 = Sha512::new();
                    sha512.update(&salt);
                    salt = sha512.finalize().to_vec();

                    salt.truncate(SlowKey::SALT_SIZE);
                } else {
                    panic!("Aborting");
                }
            },
            Ordering::Equal => {},
        },
    }

    println!();

    salt
}

fn get_password() -> Vec<u8> {
    let input_password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your password")
        .with_confirmation("Enter your password again", "Error: passwords don't match")
        .interact()
        .unwrap();

    let mut hex = false;
    let password = if input_password.starts_with(HEX_PREFIX) {
        hex = true;
        hex::decode(input_password.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input_password.as_bytes().to_vec()
    };

    show_hint(&input_password, "Password", hex);

    println!();

    password
}

fn get_output_key() -> Vec<u8> {
    let input = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your checkpoint/output encryption key")
        .with_confirmation(
            "Enter your checkpoint/output encryption key again",
            "Error: keys don't match",
        )
        .interact()
        .unwrap();

    let mut hex = false;
    let mut key = if input.starts_with(HEX_PREFIX) {
        hex = true;
        hex::decode(input.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input.as_bytes().to_vec()
    };

    show_hint(&input, "Output encryption key", hex);

    let key_len = key.len();
    match key_len.cmp(&ChaCha20Poly1305::KEY_SIZE) {
        Ordering::Less => {
            println!(
                "\nOutput encryption key's length {} is shorter than {} and will be SHA512 hashed and then truncated into {} bytes.",
                key_len,
                ChaCha20Poly1305::KEY_SIZE,
                ChaCha20Poly1305::KEY_SIZE
            );

            let confirmation = Confirm::new()
                .with_prompt("Do you want to continue?")
                .wait_for_newline(true)
                .interact()
                .unwrap();

            if confirmation {
                let mut sha512 = Sha512::new();
                sha512.update(&key);
                key = sha512.finalize().to_vec();

                key.truncate(ChaCha20Poly1305::KEY_SIZE);
            } else {
                panic!("Aborting");
            }
        },
        Ordering::Greater => {
            println!(
                "\nOutput encryption key's length {} is longer than {} and will be SHA512 hashed and then truncated into {} bytes.",
                key_len,
                ChaCha20Poly1305::KEY_SIZE,
                ChaCha20Poly1305::KEY_SIZE
            );

            let confirmation = Confirm::new()
                .with_prompt("Do you want to continue?")
                .wait_for_newline(true)
                .interact()
                .unwrap();

            if confirmation {
                let mut sha512 = Sha512::new();
                sha512.update(&key);
                key = sha512.finalize().to_vec();

                key.truncate(ChaCha20Poly1305::KEY_SIZE);
            } else {
                panic!("Aborting");
            }
        },
        Ordering::Equal => {},
    }

    println!();

    key
}

fn get_checkpoint_data() -> CheckpointData {
    println!("Please enter the checkpoint data manually:\n");

    let version: u8 = Input::new()
        .with_prompt("Version")
        .default(Version::V2 as u8)
        .interact_text()
        .unwrap();
    let version = Version::from(version);

    let iteration: usize = Input::new().with_prompt("Iteration").interact_text().unwrap();
    if iteration < SlowKeyOptions::MIN_ITERATIONS {
        panic!(
            "Iteration {} is shorter than the min value of {}",
            iteration,
            SlowKeyOptions::MIN_ITERATIONS,
        );
    } else if iteration > SlowKeyOptions::MAX_ITERATIONS {
        panic!(
            "Iteration {} is greater than the max value of {}",
            iteration,
            SlowKeyOptions::MAX_ITERATIONS,
        );
    }

    let data: String = Input::new().with_prompt("Data").interact_text().unwrap();
    let data = if data.starts_with(HEX_PREFIX) {
        hex::decode(data.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        data.as_bytes().to_vec()
    };

    if data.is_empty() {
        panic!("Invalid data");
    }

    let prev_data = if iteration > 1 {
        let prev_data: String = Input::new()
            .with_prompt("Previous data")
            .allow_empty(true)
            .interact_text()
            .unwrap();
        let prev_data = if prev_data.starts_with(HEX_PREFIX) {
            hex::decode(prev_data.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
        } else {
            prev_data.as_bytes().to_vec()
        };

        if prev_data.len() != data.len() {
            panic!("Invalid previous data's length");
        }

        Some(prev_data)
    } else {
        None
    };

    println!();

    let length: usize = Input::new()
        .with_prompt("Length")
        .default(SlowKeyOptions::DEFAULT_KEY_SIZE)
        .interact_text()
        .unwrap();
    if length < SlowKeyOptions::MIN_KEY_SIZE {
        panic!(
            "Length {} is shorter than the min value of {}",
            length,
            SlowKeyOptions::MIN_KEY_SIZE
        );
    } else if length > SlowKeyOptions::MAX_KEY_SIZE {
        panic!(
            ":ength {} is greater than the max value of {}",
            length,
            SlowKeyOptions::MAX_KEY_SIZE
        );
    }

    println!();

    let scrypt_n: u64 = Input::new()
        .with_prompt("Scrypt n")
        .default(ScryptOptions::DEFAULT_N)
        .interact_text()
        .unwrap();
    let scrypt_r: u32 = Input::new()
        .with_prompt("Scrypt r")
        .default(ScryptOptions::DEFAULT_R)
        .interact_text()
        .unwrap();
    let scrypt_p: u32 = Input::new()
        .with_prompt("Scrypt p")
        .default(ScryptOptions::DEFAULT_P)
        .interact_text()
        .unwrap();
    let scrypt = ScryptOptions::new(scrypt_n, scrypt_r, scrypt_p);

    println!();

    let argon2id_m_cost: u32 = Input::new()
        .with_prompt("Argon2id m_cost")
        .default(Argon2idOptions::DEFAULT_M_COST)
        .interact_text()
        .unwrap();
    let argon2id_t_cost: u32 = Input::new()
        .with_prompt("Argon2id t_cost")
        .default(Argon2idOptions::DEFAULT_T_COST)
        .interact_text()
        .unwrap();
    let argon2id = Argon2idOptions::new(argon2id_m_cost, argon2id_t_cost);

    println!();

    let balloon_s_cost: u32 = Input::new()
        .with_prompt("Balloon Hash s_cost")
        .default(BalloonHashOptions::DEFAULT_S_COST)
        .interact_text()
        .unwrap();
    let balloon_t_cost: u32 = Input::new()
        .with_prompt("Balloon Hash t_cost")
        .default(BalloonHashOptions::DEFAULT_T_COST)
        .interact_text()
        .unwrap();
    let balloon_hash = BalloonHashOptions::new(balloon_s_cost, balloon_t_cost);

    println!();

    CheckpointData {
        version,
        data: SlowKeyData {
            iteration: iteration - 1,
            data,
            prev_data,
            slowkey: CheckpointSlowKeyOptions {
                length,
                scrypt,
                argon2id,
                balloon_hash,
            },
        },
    }
}

fn show_hint(data: &str, description: &str, hex: bool) {
    let len = data.len();

    if len < MIN_SECRET_LENGTH_TO_REVEAL {
        println!(
            "\n{}: {} is too short, therefore hints won't be shown",
            "Warning".dark_yellow(),
            description,
        );
    } else {
        let prefix_len = if hex { 3 } else { 1 };

        println!("\n{} is: {}...{}", description, &data[..prefix_len], &data[len - 1..]);
    }
}

struct DeriveOptions {
    options: SlowKeyOptions,
    checkpoint_data: Option<CheckpointData>,
    output_key: Option<Vec<u8>>,
    checkpoint_dir: Option<PathBuf>,
    checkpoint_interval: usize,
    max_checkpoints_to_keep: usize,
    output: Option<PathBuf>,
    base64: bool,
    base58: bool,
    iteration_moving_window: u32,
}

fn derive(derive_options: DeriveOptions) {
    let options = derive_options.options;
    let mut output_key = derive_options.output_key;
    let mut checkpoint: Option<Checkpoint> = None;

    let mut _output_lock: Option<FileLock> = None;
    let mut out: Option<Output> = None;
    if let Some(path) = derive_options.output {
        if path.exists() {
            panic!("Output file \"{}\" already exists", path.to_string_lossy());
        }

        _output_lock = match FileLock::try_lock(&path) {
            Ok(lock) => Some(lock),
            Err(_) => panic!("Unable to lock {}", path.to_string_lossy()),
        };

        if output_key.is_none() {
            output_key = Some(get_output_key());
        }

        out = Some(Output::new(&OutputOptions {
            path,
            key: output_key.clone().unwrap(),
            slowkey: options.clone(),
        }))
    }

    if let Some(checkpoint_data) = &derive_options.checkpoint_data {
        checkpoint_data.print(DisplayOptions::default());
    }

    options.print();

    let salt = get_salt();
    let password = get_password();

    let mut offset: usize = 0;
    let mut offset_data = Vec::new();
    let mut prev_data = Vec::new();

    if let Some(checkpoint_data) = &derive_options.checkpoint_data {
        println!("Verifying the checkpoint...\n");

        if !checkpoint_data.verify(&salt, &password) {
            panic!("The password, salt, or internal data is incorrect!");
        }

        println!("The password, salt and internal data are correct\n");

        offset = checkpoint_data.data.iteration + 1;
        offset_data.clone_from(&checkpoint_data.data.data);

        // Since we are starting from this checkpoint, set the rolling previous data to its data
        prev_data = checkpoint_data.data.data.clone();
    }

    // Print the colored hash fingerprint of the parameters
    let fingerprint = Fingerprint::from_data(&options, &salt, &password);
    fingerprint.print();

    if let Some(dir) = derive_options.checkpoint_dir {
        if output_key.is_none() {
            output_key = Some(get_output_key());
        }

        checkpoint = Some(Checkpoint::new(&CheckpointOptions {
            iterations: options.iterations,
            dir: dir.to_owned(),
            key: output_key.clone().unwrap(),
            max_checkpoints_to_keep: derive_options.max_checkpoints_to_keep,
            slowkey: options.clone(),
        }));

        println!(
            "Checkpoint will be created every {} iterations and saved to the \"{}\" checkpoints directory\n",
            derive_options.checkpoint_interval.to_string().cyan(),
            &dir.to_string_lossy().cyan()
        );
    }

    let mb = MultiProgress::new();

    // Create the main progress bar. Please note that we are using a custom message, instead of percents, since
    // we want a higher resolution that the default one
    let pb = mb
        .add(ProgressBar::new(options.iterations as u64))
        .with_style(ProgressStyle::with_template("{bar:80.cyan/blue} {pos:>8}/{len:8} {msg}%    ({eta})").unwrap());

    pb.set_position(offset as u64);
    pb.reset_eta();
    pb.enable_steady_tick(Duration::from_secs(1));

    // Set the percent using a custom message
    pb.set_message(format!("{}", (offset * 100) as f64 / options.iterations as f64));

    // Create a progress bar to track iteration times and checkpoints
    let ipb = mb
        .add(ProgressBar::new(options.iterations as u64))
        .with_style(ProgressStyle::with_template("{msg}").unwrap());

    let start_time = SystemTime::now();
    let running_time = Instant::now();
    let mut iteration_time = Instant::now();
    let mut samples: VecDeque<u128> = VecDeque::new();

    let slowkey = SlowKey::new(&options);

    let mut checkpoint_info = String::new();

    let prev_data_mutex = Arc::new(Mutex::new(prev_data));
    let prev_data_thread = Arc::clone(&prev_data_mutex);

    let handle = thread::spawn(move || {
        let key = slowkey.derive_key_with_callback(
            &salt,
            &password,
            &offset_data,
            offset,
            |current_iteration, current_data| {
                // Track iteration times
                let last_iteration_time = iteration_time.elapsed().as_millis();
                iteration_time = Instant::now();

                samples.push_back(last_iteration_time);

                // If we have more than the required samples, remove the oldest one
                if samples.len() > derive_options.iteration_moving_window as usize {
                    samples.pop_front();
                }

                // Calculate the moving average
                let moving_average = samples.iter().sum::<u128>() as f64 / samples.len() as f64;

                let iteration_info = format!(
                    "\nIteration time moving average ({}): {}, last iteration time: {}",
                    derive_options.iteration_moving_window.to_string().cyan(),
                    format_duration(Duration::from_millis(moving_average as u64))
                        .to_string()
                        .cyan(),
                    format_duration(Duration::from_millis(last_iteration_time as u64))
                        .to_string()
                        .cyan(),
                );

                let mut prev_data = prev_data_thread.lock().unwrap();

                // Create a checkpoint if we've reached the checkpoint interval
                if derive_options.checkpoint_interval != 0
                    && (current_iteration + 1) % derive_options.checkpoint_interval == 0
                {
                    let prev_data: Option<&[u8]> = if current_iteration == 0 { None } else { Some(&prev_data) };

                    if let Some(checkpoint) = &mut checkpoint {
                        checkpoint.create_checkpoint(current_iteration, current_data, prev_data);

                        let hash = Checkpoint::hash_checkpoint(current_iteration, current_data, prev_data);

                        checkpoint_info = format!(
                            "\nCreated checkpoint #{} with data hash {}",
                            (current_iteration + 1).to_string().cyan(),
                            format!("0x{}", hex::encode(hash)).cyan()
                        );
                    }
                }

                // Store the current  data in order to store it in the checkpoint for future verification of the
                // parameters
                if current_iteration < options.iterations - 1 {
                    prev_data.clone_from(current_data);
                }

                pb.inc(1);

                // Set the percent using a custom message
                pb.set_message(format!(
                    "{}",
                    ((current_iteration + 1) * 100) as f64 / options.iterations as f64
                ));

                ipb.set_message(format!("{}{}", iteration_info, checkpoint_info));
            },
        );

        pb.finish();
        ipb.finish();

        key
    });

    mb.clear().unwrap();

    let key = handle.join().unwrap();

    println!(
        "\n\nKey is (please highlight to see): {}",
        format!("0x{}", hex::encode(&key)).black().on_black()
    );

    if derive_options.base64 {
        println!(
            "Key (base64) is (please highlight to see): {}",
            general_purpose::STANDARD.encode(&key).black().on_black()
        );
    }

    if derive_options.base58 {
        println!(
            "Key (base58) is (please highlight to see): {}",
            bs58::encode(&key).into_string().black().on_black()
        );
    }

    println!();

    if let Some(out) = out {
        let prev_data_guard = prev_data_mutex.lock().unwrap();
        let prev_data_option: Option<&[u8]> = if prev_data_guard.is_empty() {
            None
        } else {
            Some(&prev_data_guard[..])
        };

        out.save(&key, prev_data_option, &fingerprint);

        println!("Saved encrypted output to \"{}\"\n", &out.path.to_str().unwrap().cyan(),);
    }

    println!(
        "Start time: {}",
        DateTime::<Local>::from(start_time)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .cyan()
    );
    println!(
        "End time: {}",
        DateTime::<Local>::from(SystemTime::now())
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .cyan()
    );
    println!(
        "Total running time: {}",
        format_duration(Duration::from_secs(running_time.elapsed().as_secs()))
            .to_string()
            .cyan()
    );
    println!(
        "Average iteration time: {}",
        format_duration(Duration::from_millis(
            (running_time.elapsed().as_millis() as f64 / options.iterations as f64).round() as u64
        ))
        .to_string()
        .cyan()
    );
}

fn print_input_instructions() {
    println!(
        "Please input all data either in raw or hex format starting with the {} prefix\n",
        HEX_PREFIX
    );
}

fn main() {
    better_panic::install();
    color_backtrace::install();

    // Initialize libsodium
    initialize();

    println!("SlowKey v{VERSION}\n");

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Derive {
            iterations,
            length,
            output,
            scrypt_n,
            scrypt_r,
            scrypt_p,
            argon2_m_cost,
            argon2_t_cost,
            balloon_s_cost,
            balloon_t_cost,
            checkpoint_dir,
            checkpoint_interval,
            max_checkpoints_to_keep,
            base64,
            base58,
            iteration_moving_window,
        }) => {
            print_input_instructions();

            derive(DeriveOptions {
                options: SlowKeyOptions::new(
                    iterations,
                    length,
                    &ScryptOptions::new(scrypt_n, scrypt_r, scrypt_p),
                    &Argon2idOptions::new(argon2_m_cost, argon2_t_cost),
                    &BalloonHashOptions::new(balloon_s_cost, balloon_t_cost),
                ),
                checkpoint_data: None,
                output_key: None,
                checkpoint_dir,
                checkpoint_interval,
                max_checkpoints_to_keep,
                output,
                base64,
                base58,
                iteration_moving_window,
            });
        },

        Some(Commands::RestoreFromCheckpoint {
            iterations,
            output,
            checkpoint_dir,
            checkpoint_interval,
            max_checkpoints_to_keep,
            checkpoint,
            interactive,
            base64,
            base58,
            iteration_moving_window,
        }) => {
            print_input_instructions();

            let mut output_key: Option<Vec<u8>> = None;

            let checkpoint_data = match checkpoint {
                Some(path) => {
                    let key = get_output_key();
                    output_key = Some(key.clone());

                    Checkpoint::get_checkpoint(&OpenCheckpointOptions { key: key.clone(), path })
                },
                None => match interactive {
                    true => get_checkpoint_data(),
                    false => panic!("Missing checkpoint path"),
                },
            };

            if iterations <= checkpoint_data.data.iteration {
                panic!(
                    "Invalid iterations number {} for checkpoint {}",
                    iterations, checkpoint_data.data.iteration
                );
            }

            let opts = &checkpoint_data.data.slowkey;
            let options = SlowKeyOptions {
                iterations,
                length: opts.length,
                scrypt: opts.scrypt,
                argon2id: opts.argon2id,
                balloon_hash: opts.balloon_hash,
            };

            derive(DeriveOptions {
                options,
                checkpoint_data: Some(checkpoint_data),
                output_key,
                checkpoint_dir,
                checkpoint_interval,
                max_checkpoints_to_keep,
                output,
                base64,
                base58,
                iteration_moving_window,
            });
        },

        Some(Commands::ShowCheckpoint {
            checkpoint,
            verify,
            base64,
            base58,
        }) => {
            print_input_instructions();

            let output_key = get_output_key();
            let checkpoint_data = Checkpoint::get_checkpoint(&OpenCheckpointOptions {
                key: output_key,
                path: checkpoint,
            });

            checkpoint_data.print(DisplayOptions {
                base64,
                base58,
                options: true,
            });

            if verify {
                let salt = get_salt();
                let password = get_password();

                println!("Verifying the checkpoint...\n");

                if !checkpoint_data.verify(&salt, &password) {
                    panic!("The password, salt, or internal data is incorrect!");
                }

                println!("The password, salt and internal data are correct\n");
            }
        },

        Some(Commands::ShowOutput {
            output,
            verify,
            base64,
            base58,
        }) => {
            print_input_instructions();

            let output_key = get_output_key();
            let output_data = Output::get(&OpenOutputOptions {
                key: output_key,
                path: output,
            });

            output_data.print(DisplayOptions {
                base64,
                base58,
                options: true,
            });

            if verify {
                let salt = get_salt();
                let password = get_password();

                println!("Verifying the output...\n");

                if !output_data.verify(&salt, &password) {
                    panic!("The password, salt, or internal data is incorrect!");
                }

                println!("The password, salt and internal data are correct\n");
            }
        },

        Some(Commands::Bench {}) => {
            let output_path = env::current_dir().unwrap().join(BENCHMARKS_DIRECTORY);

            SlowKey::benchmark(&output_path);

            println!("Saved benchmark reports to: \"{}\"", output_path.to_string_lossy());
        },
        None => {},
    }
}
