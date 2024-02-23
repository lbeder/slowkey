mod utils;

extern crate chacha20poly1305;
extern crate hex;
extern crate indicatif;
extern crate libsodium_sys;
extern crate serde;
extern crate serde_json;
extern crate tempfile;

#[macro_use]
extern crate lazy_static;

mod slowkey;

use crate::{
    slowkey::{SlowKey, SlowKeyOptions, TEST_VECTORS},
    utils::{
        argon2id::Argon2id,
        checkpoint::{Checkpoint, CheckpointOptions, OpenCheckpointOptions},
        scrypt::ScryptOptions,
        sodium_init::initialize,
    },
};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use crossterm::style::Stylize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use humantime::format_duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use mimalloc::MiMalloc;
use sha2::{Digest, Sha256, Sha512};
use std::{
    cmp::Ordering,
    env,
    path::PathBuf,
    str::from_utf8,
    thread,
    time::{Duration, Instant},
};
use utils::argon2id::Argon2idOptions;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true, disable_help_subcommand = true)]
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
            help = "Output the result in Base64 (in addition to hex)"
        )]
        base64: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Output the result in Base58 (in addition to hex)"
        )]
        base58: bool,

        #[arg(
            long,
            default_value = SlowKeyOptions::default().scrypt.n.to_string(),
            help = format!("Scrypt CPU/memory cost parameter (must be lesser than {})", ScryptOptions::MAX_N)
        )]
        scrypt_n: u64,

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
            requires = "checkpoint_interval",
            help = "Optional directory for storing checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named \"checkpoint.i\", indicating the iteration number at which the checkpoint was created"
        )]
        checkpoint_dir: Option<PathBuf>,

        #[arg(
            long,
            requires = "checkpoint_path",
            default_value = "0",
            help = "Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save. This argument is only required if --checkpoint-interval is provided"
        )]
        checkpoint_interval: usize,

        #[arg(
            long,
            requires = "checkpoint_path",
            help = "Path to an existing checkpoint from which to resume the derivation process"
        )]
        restore_from_checkpoint: Option<PathBuf>,

        #[arg(
            long,
            requires = "checkpoint_path",
            default_value = CheckpointOptions::DEFAULT_MAX_CHECKPOINTS_TO_KEEP.to_string(),
            help = format!("Specifies the number of most recent checkpoints to keep, while automatically deleting older ones")
        )]
        max_checkpoints_to_keep: usize,
    },

    #[command(about = "Print test vectors")]
    Test {},
}

const HEX_PREFIX: &str = "0x";

fn get_salt() -> Vec<u8> {
    let input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your salt")
        .interact()
        .unwrap();

    let mut salt = if input.starts_with(HEX_PREFIX) {
        hex::decode(input.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input.as_bytes().to_vec()
    };

    let salt_len = salt.len();
    match salt_len.cmp(&SlowKey::SALT_SIZE) {
        Ordering::Less => {
            println!();

            let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Salt is shorter than {} and will padded with 0s. Do you want to continue?",
                    SlowKey::SALT_SIZE
                ))
                .wait_for_newline(true)
                .interact()
                .unwrap();

            if confirmation {
                salt.resize(SlowKey::SALT_SIZE, 0)
            } else {
                panic!("Aborting");
            }

            println!();
        },
        Ordering::Greater => {
            println!();

            let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Salt is longer than {} and will first SHA512 hashed and then truncated to {} bytes. Do you want to continue?",
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

            println!();
        },
        Ordering::Equal => {},
    }

    salt
}

fn get_password() -> Vec<u8> {
    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your password")
        .with_confirmation("Enter your password again", "Error: passwords don't match")
        .interact()
        .unwrap();

    if password.starts_with(HEX_PREFIX) {
        hex::decode(password.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        password.as_bytes().to_vec()
    }
}

fn get_checkpoint_key() -> Vec<u8> {
    let key = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your checkpoint encryption key")
        .with_confirmation("Enter your checkpoint encryption key again", "Error: keys don't match")
        .interact()
        .unwrap();

    let mut key = if key.starts_with(HEX_PREFIX) {
        hex::decode(key.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        key.as_bytes().to_vec()
    };

    let key_len = key.len();
    match key_len.cmp(&Checkpoint::KEY_SIZE) {
        Ordering::Less => {
            println!();

            let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Checkpoint encryption key is shorter than {} and will padded with 0s. Do you want to continue?",
                    Checkpoint::KEY_SIZE
                ))
                .wait_for_newline(true)
                .interact()
                .unwrap();

            if confirmation {
                key.resize(Checkpoint::KEY_SIZE, 0)
            } else {
                panic!("Aborting");
            }

            println!();
        },
        Ordering::Greater => {
            println!();

            let confirmation = Confirm::new()
                .with_prompt(format!(
                    "Checkpoint encryption key is longer than {} and will first SHA512 hashed and then truncated to {} bytes. Do you want to continue?",
                    SlowKey::SALT_SIZE, SlowKey::SALT_SIZE
                ))
                .wait_for_newline(true)
                .interact()
                .unwrap();

            if confirmation {
                let mut sha512 = Sha512::new();
                sha512.update(&key);
                key = sha512.finalize().to_vec();

                key.truncate(Checkpoint::KEY_SIZE);
            } else {
                panic!("Aborting");
            }

            println!();
        },
        Ordering::Equal => {},
    }

    key
}

fn main() {
    better_panic::install();
    color_backtrace::install();

    // Initialize libsodium
    initialize();

    println!("SlowKey v{VERSION}");
    println!();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Derive {
            iterations,
            length,
            base64,
            base58,
            scrypt_n,
            scrypt_r,
            scrypt_p,
            argon2_m_cost,
            argon2_t_cost,
            checkpoint_interval,
            checkpoint_dir,
            restore_from_checkpoint,
            max_checkpoints_to_keep,
        }) => {
            println!(
                "Please input all data either in raw or hex format starting with the {} prefix",
                HEX_PREFIX
            );
            println!();

            let slowkey_opts: SlowKeyOptions;

            let mut output_encryption_key: Option<Vec<u8>> = None;
            let mut checkpoint: Option<Checkpoint> = None;

            let mut offset: usize = 0;
            let mut offset_data = Vec::new();

            if let Some(path) = restore_from_checkpoint {
                if output_encryption_key.is_none() {
                    output_encryption_key = Some(get_checkpoint_key());
                }

                let data = Checkpoint::get(&OpenCheckpointOptions {
                    key: output_encryption_key.clone().unwrap(),
                    path: path.clone(),
                });

                slowkey_opts = data.slowkey.clone();

                offset = data.iteration + 1;
                offset_data = data.data.clone();

                println!(
                    "Using SlowKey parameters extracted from the checkpoint. Resuming from iteration {} with intermediary offset data {} (please highlight to see). ",
                    offset.to_string().cyan(),
                    hex::encode(&offset_data).black().on_black()
                );
                println!();
            } else {
                slowkey_opts = SlowKeyOptions::new(
                    iterations,
                    length,
                    &ScryptOptions::new(scrypt_n, scrypt_r, scrypt_p),
                    &Argon2idOptions::new(argon2_m_cost, argon2_t_cost),
                );
            }

            if let Some(dir) = checkpoint_dir {
                if checkpoint_interval == 0 {
                    panic!("Invalid checkpoint interval")
                }

                if output_encryption_key.as_ref().is_none() {
                    output_encryption_key = Some(get_checkpoint_key());
                }

                checkpoint = Some(Checkpoint::new(&CheckpointOptions {
                    iterations,
                    dir: dir.to_owned(),
                    key: output_encryption_key.clone().unwrap(),
                    max_checkpoints_to_keep,
                    slowkey: slowkey_opts.clone(),
                }));

                println!(
                    "Checkpoint will be created every {} iterations and saved to the \"{}\" checkpoints directory",
                    checkpoint_interval.to_string().cyan(),
                    &dir.to_string_lossy().cyan()
                );
                println!();
            }

            let salt = get_salt();
            let password = get_password();

            println!();

            println!(
                "{}: iterations: {}, length: {}, {}: (n: {}, r: {}, p: {}), {}: (version: {}, m_cost: {}, t_cost: {})",
                "SlowKey".yellow(),
                &slowkey_opts.iterations.to_string().cyan(),
                &slowkey_opts.length.to_string().cyan(),
                "Scrypt".green(),
                &slowkey_opts.scrypt.n.to_string().cyan(),
                &slowkey_opts.scrypt.r.to_string().cyan(),
                &slowkey_opts.scrypt.p.to_string().cyan(),
                "Argon2id".green(),
                Argon2id::VERSION.to_string().cyan(),
                &slowkey_opts.argon2id.m_cost.to_string().cyan(),
                &slowkey_opts.argon2id.t_cost.to_string().cyan(),
            );

            println!();

            let mb = MultiProgress::new();

            let pb = mb
                .add(ProgressBar::new(iterations as u64))
                .with_style(
                    ProgressStyle::with_template("{bar:80.cyan/blue} {pos:>7}/{len:7} {percent}%    ({eta})").unwrap(),
                )
                .with_position(offset as u64);

            pb.enable_steady_tick(Duration::from_secs(1));

            let mut cpb: Option<ProgressBar> = None;

            if checkpoint.is_some() && checkpoint_interval != 0 {
                cpb = Some(
                    mb.add(ProgressBar::new((iterations / checkpoint_interval) as u64))
                        .with_style(ProgressStyle::with_template("{msg}").unwrap())
                        .with_position((offset / checkpoint_interval) as u64),
                );

                if let Some(ref mut cpb) = &mut cpb {
                    cpb.enable_steady_tick(Duration::from_secs(1));
                }
            }

            let start_time = Instant::now();
            let slowkey = SlowKey::new(&slowkey_opts);

            let handle = thread::spawn(move || {
                let key = slowkey.derive_key_with_callback(
                    &salt,
                    &password,
                    &offset_data,
                    offset,
                    |current_iteration, current_data| {
                        // Create a checkpoint if we've reached the checkpoint interval
                        if checkpoint_interval != 0 && (current_iteration + 1) % checkpoint_interval == 0 {
                            if let Some(checkpoint) = &mut checkpoint {
                                checkpoint.create_checkpoint(current_iteration, current_data);
                            }

                            if let Some(ref mut cpb) = &mut cpb {
                                let mut sha256 = Sha256::new();
                                sha256.update(current_data);
                                let hash = hex::encode(sha256.finalize());

                                cpb.set_message(format!(
                                    "\nCreated checkpoint #{} with data hash {}\n",
                                    (current_iteration + 1).to_string().cyan(),
                                    hash.cyan()
                                ));
                            }
                        }

                        pb.inc(1);
                    },
                );

                pb.finish();
                pb.reset_eta();

                if let Some(ref mut cpb) = &mut cpb {
                    cpb.finish();
                }

                key
            });

            mb.clear().unwrap();

            let key = handle.join().unwrap();

            println!(
                "Finished in {}",
                format_duration(Duration::new(start_time.elapsed().as_secs(), 0))
                    .to_string()
                    .cyan()
            );
            println!();

            println!(
                "Key (hex) is (please highlight to see): {}",
                hex::encode(&key).black().on_black()
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
        },

        Some(Commands::Test {}) => {
            for test_vector in TEST_VECTORS.iter() {
                let scrypt = &test_vector.opts.scrypt;
                let argon2id = &test_vector.opts.argon2id;

                println!(
                    "{}: iterations: {}, length: {}, {}: (n: {}, r: {}, p: {}), {}: (version: {}, m_cost: {}, t_cost: {}), salt: \"{}\", password: \"{}\"",
                    "SlowKey".yellow(),
                    test_vector.opts.iterations.to_string().cyan(),
                    test_vector.opts.length.to_string().cyan(),
                    "Scrypt".green(),
                    scrypt.n.to_string().cyan(),
                    scrypt.r.to_string().cyan(),
                    scrypt.p.to_string().cyan(),
                    "Argon2id".green(),
                    Argon2id::VERSION.to_string().cyan(),
                    argon2id.m_cost.to_string().cyan(),
                    argon2id.t_cost.to_string().cyan(),
                    from_utf8(&test_vector.salt).unwrap().cyan(),
                    from_utf8(&test_vector.password).unwrap().cyan(),
                );

                let slowkey = SlowKey::new(&test_vector.opts);
                let key = slowkey.derive_key(
                    &test_vector.salt,
                    &test_vector.password,
                    &test_vector.offset_data,
                    test_vector.offset,
                );

                println!("Derived key: {}", hex::encode(&key).cyan());

                println!();
            }
        },
        None => {},
    }
}
