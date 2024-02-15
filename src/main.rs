extern crate hex;
extern crate libsodium_sys;
extern crate pbr;

mod utils;

#[macro_use]
extern crate lazy_static;

use libsodium_sys::sodium_init;
use mimalloc::MiMalloc;
use utils::argon2id::Argon2idOptions;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod slowkey;

use crate::{
    slowkey::{SlowKey, SlowKeyOptions, TEST_VECTORS},
    utils::{argon2id::Argon2id, scrypt::ScryptOptions},
};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    style::Stylize,
};
use humantime::format_duration;
use pbr::ProgressBar;
use std::{
    env,
    io::{self, Result, Write},
    process::exit,
    str::from_utf8,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

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
        #[arg(short, long, default_value = SlowKeyOptions::default().iterations.to_string(), help = format!("Number of iterations (must be greater than {} and lesser than or equal to {})",  SlowKeyOptions::MIN_ITERATIONS, SlowKeyOptions::MAX_ITERATIONS))]
        iterations: u32,

        #[arg(short, long, default_value = SlowKeyOptions::default().length.to_string(), help = format!("Length of the derived result (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_KEY_LENGTH, SlowKeyOptions::MAX_KEY_LENGTH))]
        length: usize,

        #[arg(long, default_value = SlowKeyOptions::default().scrypt.n.to_string(), help = format!("Scrypt CPU/memory cost parameter (must be lesser than {})", ScryptOptions::MAX_N))]
        scrypt_n: u64,

        #[arg(long, default_value = SlowKeyOptions::default().scrypt.r.to_string(), help = format!("Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than {} and lesser than or equal to {})", ScryptOptions::MIN_R, ScryptOptions::MAX_R))]
        scrypt_r: u32,

        #[arg(long, default_value = SlowKeyOptions::default().scrypt.p.to_string(), help = format!("Scrypt parallelization parameter (must be greater than {} and lesser than {})", ScryptOptions::MIN_P, ScryptOptions::MAX_P))]
        scrypt_p: u32,

        #[arg(long, default_value = SlowKeyOptions::default().argon2id.m_cost.to_string(), help = format!("Argon2 number of 1 KiB memory block (must be greater than {} and lesser than {})", Argon2idOptions::MIN_M_COST, Argon2idOptions::MAX_M_COST))]
        argon2_m_cost: u32,

        #[arg(long, default_value = SlowKeyOptions::default().argon2id.t_cost.to_string(), help = format!("Argon2 number of iterations (must be greater than {} and lesser than {})", Argon2idOptions::MIN_T_COST, Argon2idOptions::MAX_T_COST))]
        argon2_t_cost: u32,

        #[arg(
            long,
            default_value = "0",
            help = "Start the derivation from this offset. In order to use it, you also have to specify the intermediary offset data in hex format"
        )]
        offset: u32,

        #[arg(long, help = "Start the derivation with this intermediary data in hex format")]
        offset_data: Option<String>,

        #[arg(long, action = clap::ArgAction::SetTrue, help = "Output the result in Base64 (in addition to hex)")]
        base64: bool,

        #[arg(long, action = clap::ArgAction::SetTrue, help = "Output the result in Base58 (in addition to hex)")]
        base58: bool,
    },

    #[command(about = "Print test vectors")]
    Test {},
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    while let Event::Key(KeyEvent { code, .. }) = event::read()? {
        match code {
            KeyCode::Enter => {
                break;
            },
            KeyCode::Char(c) => {
                line.push(c);
            },
            _ => {},
        }
    }

    Ok(line)
}

const HEX_PREFIX: &str = "0x";

fn get_salt() -> Vec<u8> {
    print!(
        "Enter your salt (must be {} characters/bytes long in either raw or hex format starting with 0x): ",
        SlowKey::SALT_LENGTH
    );

    io::stdout().flush().unwrap();

    let input = read_line().unwrap();
    let salt = if input.starts_with(HEX_PREFIX) {
        hex::decode(input.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input.as_bytes().to_vec()
    };

    if salt.len() != SlowKey::SALT_LENGTH {
        panic!("salt must be {} characters/bytes long", SlowKey::SALT_LENGTH);
    }

    salt
}

fn get_password() -> Vec<u8> {
    let pass =
        rpassword::prompt_password("Enter your password (in either raw or hex format starting with 0x): ").unwrap();
    let pass2 = rpassword::prompt_password("Enter your password again: ").unwrap();

    if pass != pass2 {
        println!();
        println!("Passwords don't match!");

        exit(-1);
    }

    if pass.starts_with(HEX_PREFIX) {
        hex::decode(pass.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        pass.as_bytes().to_vec()
    }
}

fn main() {
    better_panic::install();
    color_backtrace::install();

    // Initialize libsodium
    unsafe {
        let res = sodium_init();
        if res != 0 {
            panic!("sodium_init failed with: {res}");
        }
    }

    println!("SlowKey v{VERSION}");
    println!();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Derive {
            iterations,
            length,
            scrypt_n,
            scrypt_r,
            scrypt_p,
            argon2_m_cost,
            argon2_t_cost,
            offset,
            offset_data,
            base64,
            base58,
        }) => {
            let opts = SlowKeyOptions::new(
                *iterations,
                *length,
                &ScryptOptions::new(*scrypt_n, *scrypt_r, *scrypt_p),
                &Argon2idOptions::new(*argon2_m_cost, *argon2_t_cost),
            );

            println!(
                "{}: iterations: {}, length: {}, {}: (n: {}, r: {}, p: {}), {}: (version: {}, m_cost: {}, t_cost: {})",
                "SlowKey".yellow(),
                iterations.to_string().cyan(),
                length.to_string().cyan(),
                "Scrypt".green(),
                scrypt_n.to_string().cyan(),
                scrypt_r.to_string().cyan(),
                scrypt_p.to_string().cyan(),
                "Argon2id".green(),
                Argon2id::VERSION.to_string().cyan(),
                argon2_m_cost.to_string().cyan(),
                argon2_t_cost.to_string().cyan(),
            );
            println!();

            // Register a termination handler to output intermediary results
            let last_iteration_ref = Arc::new(Mutex::new(0));
            let last_result_ref = Arc::new(Mutex::new(String::new()));

            let last_iteration = last_iteration_ref.clone();
            let last_result = last_result_ref.clone();

            ctrlc::set_handler(move || {
                let offset = *last_iteration.lock().unwrap();
                let offset_data = last_result.lock().unwrap();
                if offset_data.is_empty() {
                    exit(-1);
                }

                println!();
                println!();
                println!(
                    "Terminated. To resume, please specify --offset {} and --offset-data (please highlight to see) {}",
                    offset + 1,
                    offset_data.clone().black().on_black()
                );

                exit(-1);
            })
            .expect("Error setting termination handler");

            let mut offset_raw_data = Vec::new();

            if *offset != 0 {
                offset_raw_data = match offset_data {
                    Some(data) => {
                        println!("Resuming from iteration {offset} with intermediary offset data {data}");
                        println!();

                        hex::decode(data).unwrap()
                    },

                    None => {
                        panic!("Missing intermediary offset data");
                    },
                }
            }

            let salt = get_salt();
            let password = get_password();

            println!();

            let mut pb = ProgressBar::new(u64::from(*iterations - *offset));
            pb.show_speed = false;
            pb.message("Processing: ");
            pb.tick();

            let start_time = Instant::now();

            let slowkey = SlowKey::new(&opts);

            let last_iteration2 = last_iteration_ref;
            let last_result2 = last_result_ref;
            let key = slowkey.derive_key_with_callback(&salt, &password, &offset_raw_data, *offset, |i, res| {
                *last_iteration2.lock().unwrap() = i;
                *last_result2.lock().unwrap() = hex::encode(res);

                pb.inc();
            });

            println!();
            println!();
            println!(
                "Key (hex) is (please highlight to see): {}",
                hex::encode(&key).black().on_black()
            );

            if *base64 {
                println!(
                    "Key (base64) is (please highlight to see): {}",
                    general_purpose::STANDARD.encode(&key).black().on_black()
                );
            }

            if *base58 {
                println!(
                    "Key (base58) is (please highlight to see): {}",
                    bs58::encode(&key).into_string().black().on_black()
                );
            }

            pb.finish_println(&format!(
                "Finished in {}\n",
                format_duration(Duration::new(start_time.elapsed().as_secs(), 0))
                    .to_string()
                    .cyan()
            ));
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
