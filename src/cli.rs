use crate::utils::{
    algorithms::{argon2id::Argon2idOptions, balloon_hash::BalloonHashOptions, scrypt::ScryptOptions},
    chacha20poly1305::ChaCha20Poly1305,
    checkpoints::{
        checkpoint::{CheckpointData, CheckpointSlowKeyOptions, SlowKeyData},
        version::Version,
    },
    inputs::{
        secret::{Secret, SecretData, SecretInnerData, SecretOptions},
        version::Version as SecretVersion,
    },
};
use crossterm::style::Stylize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use rand::Rng;
use sha2::{Digest, Sha512};
use std::{cmp::Ordering, fs, path::PathBuf};

use crate::slowkey::{SlowKey, SlowKeyOptions};

pub const HEX_PREFIX: &str = "0x";
const MIN_SECRET_LENGTH_TO_REVEAL: usize = 8;
const RANDOM_PASSWORD_SIZE: usize = 32;

pub fn get_salt() -> String {
    let input_salt = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your salt")
        .with_confirmation("Enter your salt again", "Error: salts don't match")
        .allow_empty_password(true)
        .interact()
        .unwrap();

    let mut hex = false;
    let salt_bytes = if input_salt.starts_with(HEX_PREFIX) {
        hex = true;
        hex::decode(input_salt.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input_salt.as_bytes().to_vec()
    };

    show_hint(&input_salt, "Salt", hex);

    let salt_len = salt_bytes.len();
    let salt = match salt_len {
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
                format!("0x{}", hex::encode(SlowKey::DEFAULT_SALT))
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
                    sha512.update(&salt_bytes);
                    let mut salt_bytes = sha512.finalize().to_vec();

                    salt_bytes.truncate(SlowKey::SALT_SIZE);

                    // Return as hex since it was modified
                    format!("0x{}", hex::encode(salt_bytes))
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
                    sha512.update(&salt_bytes);
                    let mut salt_bytes = sha512.finalize().to_vec();

                    salt_bytes.truncate(SlowKey::SALT_SIZE);

                    // Return as hex since it was modified
                    format!("0x{}", hex::encode(salt_bytes))
                } else {
                    panic!("Aborting");
                }
            },
            Ordering::Equal => input_salt,
        },
    };

    println!();

    salt
}

pub fn get_password() -> String {
    let input_password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your password")
        .with_confirmation("Enter your password again", "Error: passwords don't match")
        .interact()
        .unwrap();

    let hex = input_password.starts_with(HEX_PREFIX);

    show_hint(&input_password, "Password", hex);

    println!();

    input_password
}

pub fn get_entropy() -> Vec<u8> {
    let input_entropy = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your extra entropy")
        .interact()
        .unwrap();

    let mut hex = false;
    let entropy = if input_entropy.starts_with(HEX_PREFIX) {
        hex = true;
        hex::decode(input_entropy.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input_entropy.as_bytes().to_vec()
    };

    show_hint(&input_entropy, "Entropy", hex);

    println!();

    entropy
}

pub fn get_encryption_key(name: &str) -> Vec<u8> {
    let input = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Enter your {} encryption key", name))
        .with_confirmation(
            format!("Enter your {} encryption key again", name),
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

    show_hint(&input, &format!("{} encryption key", name), hex);

    let key_len = key.len();
    let capitalized = name.chars().next().unwrap().to_uppercase().collect::<String>() + &name[1..];
    match key_len.cmp(&ChaCha20Poly1305::KEY_SIZE) {
        Ordering::Less => {
            println!(
                "\n{} encryption key's length {} is shorter than {} and will be SHA512 hashed and then truncated into {} bytes.",
                capitalized,
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
                "\n{} encryption key's length {} is longer than {} and will be SHA512 hashed and then truncated into {} bytes.",
                capitalized,
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

pub fn get_checkpoint_data() -> CheckpointData {
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
        .default(SlowKeyOptions::DEFAULT_OUTPUT_SIZE)
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
            "Length {} is greater than the max value of {}",
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
            "\n{}: {} is too short, therefore password hint won't be shown",
            "Warning".dark_yellow(),
            description,
        );
    } else {
        let prefix_len = if hex { 3 } else { 1 };

        println!("\n{} is: {}...{}", description, &data[..prefix_len], &data[len - 1..]);
    }
}

pub fn generate_random_secret() -> (String, String) {
    let entropy = get_entropy();

    // Generate truly random data using the system's secure random number generator
    let mut rng = rand::thread_rng();
    let random_data: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

    // Append the user-provided entropy to the randomly generated data
    let mut combined_data = random_data;
    combined_data.extend_from_slice(&entropy);

    // Hash the combined data
    let mut hasher = Sha512::new();
    hasher.update(&combined_data);
    let final_hash = hasher.finalize();

    // Use the first 32 bytes for password and next 16 bytes for salt
    let password = final_hash[0..RANDOM_PASSWORD_SIZE].to_vec();
    let salt = final_hash[RANDOM_PASSWORD_SIZE..RANDOM_PASSWORD_SIZE + SlowKey::SALT_SIZE].to_vec();

    // Return as hex strings with 0x prefix since they're randomly generated
    (
        format!("0x{}", hex::encode(&salt)),
        format!("0x{}", hex::encode(&password)),
    )
}

pub fn generate_secrets(count: usize, output_dir: PathBuf, prefix: String, random: bool) {
    if count == 0 {
        panic!("Count cannot be 0");
    }

    if output_dir.exists() {
        panic!("Output directory \"{}\" already exists", output_dir.to_string_lossy());
    }

    // Create the output directory
    fs::create_dir_all(&output_dir).unwrap();

    // Ask for an encryption key
    println!("Please provide an encryption key for the secret files:\n");

    let encryption_key = get_encryption_key("secrets");

    for i in 1..=count {
        let (salt, password) = if random {
            println!("Please provide some extra entropy for secret number {i} (this will be mixed into the random number generator):\n");

            generate_random_secret()
        } else {
            println!("Please provide the salt and the password for secret number {i}:\n");

            (get_salt(), get_password())
        };

        let filename = format!(
            "{}{:0width$}.dat",
            prefix,
            i,
            width = (count as f64).log10().ceil() as usize
        );
        let filepath = output_dir.join(filename);

        let secret = Secret::new(&SecretOptions {
            path: filepath.clone(),
            key: encryption_key.clone(),
        });

        let secret_data = SecretData {
            version: SecretVersion::V1,
            data: SecretInnerData {
                password: password.clone(),
                salt: salt.clone(),
            },
        };

        secret.save(&secret_data);

        // Display the secret differently based on whether it has 0x prefix
        println!(
            "Salt for secret number {i} is (please highlight to see): {}",
            salt.black().on_black()
        );

        println!(
            "Password for secret number {i} is (please highlight to see): {}",
            password.black().on_black()
        );

        println!("Stored encrypted secret number {i} at: {}\n", filepath.display());
    }
}

pub fn print_input_instructions() {
    println!(
        "Please input all data either in raw or hex format starting with the {} prefix\n",
        HEX_PREFIX
    );
}
