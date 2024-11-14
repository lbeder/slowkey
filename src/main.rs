mod utils;

extern crate chacha20poly1305;
extern crate hex;
extern crate indicatif;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

mod slowkey;

use crate::{
    slowkey::{SlowKey, SlowKeyOptions, TEST_VECTORS},
    utils::scrypt::ScryptOptions,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use crossterm::style::Stylize;
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use humantime::format_duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use mimalloc::MiMalloc;
use sha2::{Digest, Sha512};
use std::{
    cmp::Ordering,
    env,
    path::PathBuf,
    str::from_utf8,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};
use utils::{
    argon2id::Argon2idOptions,
    chacha20poly1305::ChaCha20Poly1305,
    checkpoints::checkpoint::{Checkpoint, CheckpointData, CheckpointOptions, OpenCheckpointOptions},
    outputs::output::{OpenOutputOptions, Output, OutputOptions},
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
    #[command(about = "Derive a key using using Scrypt, Argon2, SHA2, and SHA3")]
    Derive {
        #[arg(
            short,
            long,
            default_value = SlowKeyOptions::default().iterations.to_string(),
            help = format!("Number of iterations (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_ITERATIONS, SlowKeyOptions::MAX_ITERATIONS)
        )]
        iterations: usize,

        #[arg(
            short,
            long,
            default_value = SlowKeyOptions::default().length.to_string(),
            help = format!("Length of the derived result (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_KEY_SIZE, SlowKeyOptions::MAX_KEY_SIZE)
        )]
        length: usize,

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

        #[arg(long, help = "Optional path for storing the encrypted output")]
        output: Option<PathBuf>,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().scrypt.log_n.to_string(),
            help = format!("Scrypt CPU/memory cost parameter (must be lesser than {})", ScryptOptions::MAX_LOG_N)
        )]
        scrypt_log_n: u8,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().scrypt.r.to_string(),
            help = format!("Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than {} and lesser than or equal to {})", ScryptOptions::MIN_R, ScryptOptions::MAX_R)
        )]
        scrypt_r: u32,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().scrypt.p.to_string(),
            help = format!("Scrypt parallelization parameter (must be greater than {} and lesser than {})", ScryptOptions::MIN_P, ScryptOptions::MAX_P)
        )]
        scrypt_p: u32,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().argon2id.m_cost.to_string(),
            help = format!("Argon2 number of 1 KiB memory block (must be greater than {} and lesser than {})", Argon2idOptions::MIN_M_COST, Argon2idOptions::MAX_M_COST))]
        argon2_m_cost: u32,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().argon2id.t_cost.to_string(),
            help = format!("Argon2 number of iterations (must be greater than {} and lesser than {})", Argon2idOptions::MIN_T_COST, Argon2idOptions::MAX_T_COST))]
        argon2_t_cost: u32,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().argon2id.p_cost.to_string(),
            help = format!("Argon2 Degree of parallelism (must be greater than {} and lesser than {})", Argon2idOptions::MIN_P_COST, Argon2idOptions::MAX_P_COST))]
        argon2_p_cost: u32,

        #[arg(
            long,
            requires = "checkpoint_interval",
            help = "Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named \"checkpoint.i\", indicating the iteration number at which the checkpoint was created"
        )]
        checkpoint_dir: Option<PathBuf>,

        #[arg(
            long,
            requires = "checkpoint_path",
            help = "Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save"
        )]
        checkpoint_interval: Option<usize>,

        #[arg(
            long,
            requires = "checkpoint_path",
            default_value = CheckpointOptions::DEFAULT_MAX_CHECKPOINTS_TO_KEEP.to_string(),
            help = format!("Specifies the number of most recent checkpoints to keep, while automatically deleting older ones")
        )]
        max_checkpoints_to_keep: usize,

        #[arg(
            long,
            requires = "checkpoint_path",
            help = "Path to an existing checkpoint from which to resume the derivation process"
        )]
        restore_from_checkpoint: Option<PathBuf>,
    },

    #[command(about = "Decrypt and print a checkpoint")]
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

    #[command(about = "Decrypt and print an output file")]
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

    #[command(about = "Print test vectors")]
    Test {},
}

const HEX_PREFIX: &str = "0x";

#[derive(PartialEq, Debug, Clone, Default)]
pub struct DisplayOptions {
    pub base64: bool,
    pub base58: bool,
    pub options: bool,
}

fn get_salt() -> Vec<u8> {
    let input = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your salt")
        .with_confirmation("Enter your salt again", "Error: salts don't match")
        .allow_empty_password(true)
        .interact()
        .unwrap();

    let mut salt = if input.starts_with(HEX_PREFIX) {
        hex::decode(input.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input.as_bytes().to_vec()
    };

    let salt_len = salt.len();
    match salt_len {
        0 => {
            println!();

            let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Salt is empty; a default {}-byte zero-filled salt will be used. Do you want to continue?",
                    SlowKey::SALT_SIZE
                ))
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
                println!();

                let confirmation = Confirm::new()
                    .with_prompt(format!(
                        "Salt's length {} is shorter than {} and will be SHA512 hashed and then truncated to {} bytes. Do you want to continue?",
                        salt_len,
                        SlowKey::SALT_SIZE, SlowKey::SALT_SIZE
                    ))
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
                println!();

                let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Salt's length {} is longer than {} and will be SHA512 hashed and then truncated to {} bytes. Do you want to continue?",
                    salt_len,
                    SlowKey::SALT_SIZE, SlowKey::SALT_SIZE
                ))
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
    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your password")
        .with_confirmation("Enter your password again", "Error: passwords don't match")
        .interact()
        .unwrap();

    println!();

    if password.starts_with(HEX_PREFIX) {
        hex::decode(password.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        password.as_bytes().to_vec()
    }
}

fn get_output_key() -> Vec<u8> {
    let key = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your checkpoint/output encryption key")
        .with_confirmation(
            "Enter your checkpoint/output encryption key again",
            "Error: keys don't match",
        )
        .interact()
        .unwrap();

    let mut key = if key.starts_with(HEX_PREFIX) {
        hex::decode(key.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        key.as_bytes().to_vec()
    };

    let key_len = key.len();
    match key_len.cmp(&ChaCha20Poly1305::KEY_SIZE) {
        Ordering::Less => {
            println!();

            let confirmation = Confirm::new()
            .with_prompt(format!(
                "Output encryption key's length {} is shorter than {} and will be SHA512 hashed and then truncated to {} bytes. Do you want to continue?",
                key_len,
                ChaCha20Poly1305::KEY_SIZE, ChaCha20Poly1305::KEY_SIZE
            ))
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
            println!();

            let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Output encryption key's length {} is longer than {} and will be SHA512 hashed and then truncated to {} bytes. Do you want to continue?",
                    key_len,
                    ChaCha20Poly1305::KEY_SIZE, ChaCha20Poly1305::KEY_SIZE
                ))
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

fn main() {
    better_panic::install();
    color_backtrace::install();

    println!("SlowKey v{VERSION}\n");

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Derive {
            iterations,
            length,
            base64,
            base58,
            output,
            scrypt_log_n,
            scrypt_r,
            scrypt_p,
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            checkpoint_interval,
            checkpoint_dir,
            restore_from_checkpoint,
            max_checkpoints_to_keep,
        }) => {
            println!(
                "Please input all data either in raw or hex format starting with the {} prefix\n",
                HEX_PREFIX
            );

            let slowkey_opts: SlowKeyOptions;

            let mut output_key: Option<Vec<u8>> = None;
            let mut checkpoint: Option<Checkpoint> = None;
            let mut restore_from_checkpoint_data: Option<CheckpointData> = None;

            let mut offset: usize = 0;
            let mut offset_data = Vec::new();

            if let Some(path) = restore_from_checkpoint {
                if output_key.is_none() {
                    output_key = Some(get_output_key());
                }

                let checkpoint_data = Checkpoint::get_checkpoint(&OpenCheckpointOptions {
                    key: output_key.clone().unwrap(),
                    path: path.clone(),
                });

                if iterations <= checkpoint_data.data.iteration {
                    panic!(
                        "Invalid iterations number {} for checkpoint {}",
                        iterations, checkpoint_data.data.iteration
                    );
                }

                checkpoint_data.print(DisplayOptions::default());

                slowkey_opts = SlowKeyOptions {
                    iterations,
                    length: checkpoint_data.data.slowkey.length,
                    scrypt: checkpoint_data.data.slowkey.scrypt,
                    argon2id: checkpoint_data.data.slowkey.argon2id,
                };

                offset = checkpoint_data.data.iteration + 1;
                offset_data.clone_from(&checkpoint_data.data.data);

                restore_from_checkpoint_data = Some(checkpoint_data)
            } else {
                slowkey_opts = SlowKeyOptions::new(
                    iterations,
                    length,
                    &ScryptOptions::new(scrypt_log_n, scrypt_r, scrypt_p),
                    &Argon2idOptions::new(argon2_m_cost, argon2_t_cost, argon2_p_cost),
                );
            }

            let mut out: Option<Output> = None;
            if let Some(path) = output {
                if output_key.is_none() {
                    output_key = Some(get_output_key());
                }

                out = Some(Output::new(&OutputOptions {
                    path,
                    key: output_key.clone().unwrap(),
                    slowkey: slowkey_opts.clone(),
                }))
            }

            let mut checkpointing_interval: usize = 0;

            if let Some(dir) = checkpoint_dir {
                checkpointing_interval = checkpoint_interval.unwrap();

                if output_key.is_none() {
                    output_key = Some(get_output_key());
                }

                checkpoint = Some(Checkpoint::new(&CheckpointOptions {
                    iterations: slowkey_opts.iterations,
                    dir: dir.to_owned(),
                    key: output_key.clone().unwrap(),
                    max_checkpoints_to_keep,
                    slowkey: slowkey_opts.clone(),
                }));

                println!(
                    "Checkpoint will be created every {} iterations and saved to the \"{}\" checkpoints directory\n",
                    checkpointing_interval.to_string().cyan(),
                    &dir.to_string_lossy().cyan()
                );
            }

            slowkey_opts.print();

            let salt = get_salt();
            let password = get_password();

            let mut prev_data = Vec::new();

            if let Some(checkpoint_data) = restore_from_checkpoint_data {
                println!("Verifying the checkpoint...\n");

                if checkpoint_data.data.iteration > 0 {
                    if !checkpoint_data.verify(&salt, &password) {
                        panic!("The password, salt, or internal data is incorrect!");
                    }

                    println!("The password, salt and internal data are correct\n");
                } else {
                    println!("{}: Unable to verify the first checkpoint\n", "Warning".dark_yellow());
                }

                // Since we are starting from this checkpoint, set the rolling previous data to its data
                prev_data = checkpoint_data.data.data;
            }

            let mb = MultiProgress::new();

            let pb = mb
                .add(ProgressBar::new(slowkey_opts.iterations as u64))
                .with_style(
                    ProgressStyle::with_template("{bar:80.cyan/blue} {pos:>7}/{len:7} {percent}%    ({eta})").unwrap(),
                )
                .with_position(offset as u64);

            pb.enable_steady_tick(Duration::from_secs(1));

            let mut cpb: Option<ProgressBar> = None;

            if checkpoint.is_some() && checkpointing_interval != 0 {
                cpb = Some(
                    mb.add(ProgressBar::new(
                        (slowkey_opts.iterations / checkpointing_interval) as u64,
                    ))
                    .with_style(ProgressStyle::with_template("{msg}").unwrap())
                    .with_position((offset / checkpointing_interval) as u64),
                );

                if let Some(ref mut cpb) = &mut cpb {
                    cpb.enable_steady_tick(Duration::from_secs(1));
                }
            }

            let start_time = SystemTime::now();
            let running_time = Instant::now();
            let slowkey = SlowKey::new(&slowkey_opts);

            let prev_data_mutex = Arc::new(Mutex::new(prev_data));
            let prev_data_thread = Arc::clone(&prev_data_mutex);

            let handle = thread::spawn(move || {
                let key = slowkey.derive_key_with_callback(
                    &salt,
                    &password,
                    &offset_data,
                    offset,
                    |current_iteration, current_data| {
                        let mut prev_data = prev_data_thread.lock().unwrap();

                        // Create a checkpoint if we've reached the checkpoint interval
                        if checkpointing_interval != 0 && (current_iteration + 1) % checkpointing_interval == 0 {
                            let prev_data: Option<&[u8]> = if current_iteration == 0 { None } else { Some(&prev_data) };

                            if let Some(checkpoint) = &mut checkpoint {
                                checkpoint.create_checkpoint(&salt, current_iteration, current_data, prev_data);
                            }

                            if let Some(ref mut cpb) = &mut cpb {
                                let hash =
                                    Checkpoint::hash_checkpoint(&salt, current_iteration, current_data, prev_data);

                                cpb.set_message(format!(
                                    "\nCreated checkpoint #{} with data hash (salted) {}",
                                    (current_iteration + 1).to_string().cyan(),
                                    format!("0x{}", hex::encode(hash)).cyan()
                                ));
                            }
                        }

                        // Store the current data in order to store it in the checkpoint for future verification of the
                        // parameters
                        if current_iteration < iterations - 1 {
                            prev_data.clone_from(current_data);
                        }

                        pb.inc(1);
                    },
                );

                pb.finish();

                if let Some(ref mut cpb) = &mut cpb {
                    cpb.finish();
                }

                key
            });

            mb.clear().unwrap();

            let key = handle.join().unwrap();

            println!(
                "\n\nKey is (please highlight to see): {}",
                format!("0x{}", hex::encode(&key)).black().on_black()
            );

            if base64 {
                println!(
                    "Key (base64) is (please highlight to see): {}",
                    general_purpose::STANDARD.encode(&key).black().on_black()
                );
            }

            if base58 {
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

                out.save(iterations, &key, prev_data_option);

                println!("Saved encrypted output to \"{}\"\n", &out.path.to_str().unwrap().cyan(),);
            }

            println!(
                "Start time: {}",
                DateTime::<Utc>::from(start_time)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
                    .cyan()
            );
            println!(
                "End time: {}",
                DateTime::<Utc>::from(SystemTime::now())
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
                    .cyan()
            );
            println!(
                "Total running time: {}\n",
                format_duration(Duration::new(running_time.elapsed().as_secs(), 0))
                    .to_string()
                    .cyan()
            );
        },

        Some(Commands::ShowCheckpoint {
            checkpoint,
            verify,
            base64,
            base58,
        }) => {
            println!(
                "Please input all data either in raw or hex format starting with the {} prefix\n",
                HEX_PREFIX
            );

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

                if checkpoint_data.data.iteration > 0 {
                    if !checkpoint_data.verify(&salt, &password) {
                        panic!("The password, salt, or internal data is incorrect!");
                    }

                    println!("The password, salt and internal data are correct\n");
                } else {
                    println!("{}: Unable to verify the first checkpoint\n", "Warning".dark_yellow());
                }
            }
        },

        Some(Commands::ShowOutput {
            output,
            verify,
            base64,
            base58,
        }) => {
            println!(
                "Please input all data either in raw or hex format starting with the {} prefix\n",
                HEX_PREFIX
            );

            let output_key = get_output_key();

            let output_data = Output::get(&OpenOutputOptions {
                key: output_key,
                path: output,
            });

            output_data.print(DisplayOptions {
                base64,
                base58,
                options: false,
            });

            if verify {
                let salt = get_salt();
                let password = get_password();

                println!("Verifying the output...\n");

                if output_data.data.iteration > 0 {
                    if !output_data.verify(&salt, &password) {
                        panic!("The password, salt, or internal data is incorrect!");
                    }

                    println!("The password, salt and internal data are correct\n");
                } else {
                    println!(
                        "{}: Unable to verify the output of the first iteration checkpoint\n",
                        "Warning".dark_yellow()
                    );
                }
            }
        },

        Some(Commands::Test {}) => {
            for test_vector in TEST_VECTORS.iter() {
                println!(
                    "{}: \"{}\"\n{}: \"{}\"\n",
                    "Salt".yellow(),
                    from_utf8(&test_vector.salt).unwrap().cyan(),
                    "Password".yellow(),
                    from_utf8(&test_vector.password).unwrap().cyan(),
                );

                test_vector.opts.print();

                let slowkey = SlowKey::new(&test_vector.opts);
                let key = slowkey.derive_key(
                    &test_vector.salt,
                    &test_vector.password,
                    &test_vector.offset_data,
                    test_vector.offset,
                );

                println!("Derived key: {}\n", format!("0x{}", hex::encode(&key)).cyan());
            }
        },
        None => {},
    }
}
