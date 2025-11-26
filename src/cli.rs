use crate::log;
use crate::slowkey::{SlowKey, SlowKeyOptions};
use crate::utils::{
    algorithms::{argon2id::Argon2idOptions, balloon_hash::BalloonHashOptions, scrypt::ScryptOptions},
    chacha20poly1305::ChaCha20Poly1305,
    checkpoints::{
        checkpoint::{Checkpoint, CheckpointData, CheckpointSlowKeyOptions, OpenCheckpointOptions, SlowKeyData},
        version::Version,
    },
    file_lock::FileLock,
    inputs::{
        secret::{Secret, SecretData, SecretInnerData, SecretOptions},
        version::Version as SecretVersion,
    },
    outputs::{
        fingerprint::Fingerprint,
        output::{OpenOutputOptions, Output},
    },
};
use crate::warning;

const DAISY_OUTPUT_PREFIX: &str = "output_";

use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Local};
use crossterm::style::Stylize;
use dialoguer::{theme::ColorfulTheme, Input, Password};
use humantime::format_duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::Rng;
use sha2::{Digest, Sha512};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Instant, SystemTime},
};

pub const HEX_PREFIX: &str = "0x";
const MIN_SECRET_LENGTH_TO_REVEAL: usize = 8;
const RANDOM_PASSWORD_SIZE: usize = 32;

fn normalize_and_harden_key(key: Vec<u8>, key_description: Option<&str>, key_name: Option<&str>) -> Vec<u8> {
    // First normalize the key to 32 bytes
    let normalized_key = normalize_key_to_size(key, key_description);

    // Then harden it using SlowKey
    let name = key_name.unwrap_or("key");
    log!("\nHardening the {name} using SlowKey\n");

    SlowKey::new(&ENCRYPTION_KEY_HARDENING_OPTIONS).derive_key(&SlowKey::DEFAULT_SALT, &normalized_key, &[], 0)
}

fn normalize_key_to_size(key: Vec<u8>, key_description: Option<&str>) -> Vec<u8> {
    let key_len = key.len();
    let description = key_description.unwrap_or("Key");

    match key_len.cmp(&ChaCha20Poly1305::KEY_SIZE) {
        Ordering::Less => {
            warning!(
                "{}'s length {} is shorter than {}; hashing with SHA512 and truncating to {} bytes",
                description,
                key_len,
                ChaCha20Poly1305::KEY_SIZE,
                ChaCha20Poly1305::KEY_SIZE
            );

            let mut sha512 = Sha512::new();
            sha512.update(&key);
            let mut normalized = sha512.finalize().to_vec();
            normalized.truncate(ChaCha20Poly1305::KEY_SIZE);
            normalized
        },
        Ordering::Greater => {
            warning!(
                "{}'s length {} is longer than {}; hashing with SHA512 and truncating to {} bytes",
                description,
                key_len,
                ChaCha20Poly1305::KEY_SIZE,
                ChaCha20Poly1305::KEY_SIZE
            );

            let mut sha512 = Sha512::new();
            sha512.update(&key);
            let mut normalized = sha512.finalize().to_vec();
            normalized.truncate(ChaCha20Poly1305::KEY_SIZE);
            normalized
        },
        Ordering::Equal => key,
    }
}

// Fixed SlowKey parameters for encryption key hardening. Intentionally hard-coded so future default changes do not
// affect this behavior.
const ENCRYPTION_KEY_HARDENING_OPTIONS: SlowKeyOptions = SlowKeyOptions {
    iterations: 1,
    length: ChaCha20Poly1305::KEY_SIZE,
    scrypt: ScryptOptions::HARDENING_DEFAULT,
    argon2id: Argon2idOptions::HARDENING_DEFAULT,
    balloon_hash: BalloonHashOptions::HARDENING_DEFAULT,
};

pub fn get_salt_normalized(normalize: bool) -> String {
    let input_salt = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your salt")
        .with_confirmation("Enter your salt again", "Error: salts don't match")
        .allow_empty_password(true)
        .interact()
        .unwrap();

    show_hint(&input_salt, "salt");

    if !normalize {
        log!();

        return input_salt;
    }

    let salt_bytes = input_to_bytes(&input_salt);

    let salt_len = salt_bytes.len();
    let salt = match salt_len {
        0 => {
            warning!(
                "Salt is empty; using default zero-filled salt of {} bytes",
                SlowKey::SALT_SIZE
            );
            format!("0x{}", hex::encode(SlowKey::DEFAULT_SALT))
        },
        _ => match salt_len.cmp(&SlowKey::SALT_SIZE) {
            Ordering::Less => {
                warning!(
                    "Salt's length {} is shorter than {}; hashing with SHA512 and truncating to {} bytes",
                    salt_len,
                    SlowKey::SALT_SIZE,
                    SlowKey::SALT_SIZE
                );

                let mut sha512 = Sha512::new();
                sha512.update(&salt_bytes);
                let mut salt_bytes = sha512.finalize().to_vec();

                salt_bytes.truncate(SlowKey::SALT_SIZE);

                // Return as hex since it was modified
                format!("0x{}", hex::encode(salt_bytes))
            },
            Ordering::Greater => {
                warning!(
                    "Salt's length {} is longer than {}; hashing with SHA512 and truncating to {} bytes",
                    salt_len,
                    SlowKey::SALT_SIZE,
                    SlowKey::SALT_SIZE
                );

                let mut sha512 = Sha512::new();
                sha512.update(&salt_bytes);
                let mut salt_bytes = sha512.finalize().to_vec();

                salt_bytes.truncate(SlowKey::SALT_SIZE);

                // Return as hex since it was modified
                format!("0x{}", hex::encode(salt_bytes))
            },
            Ordering::Equal => input_salt,
        },
    };

    log!();

    salt
}

pub fn get_salt() -> String {
    get_salt_normalized(true)
}

pub fn get_password() -> String {
    let input_password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your password")
        .with_confirmation("Enter your password again", "Error: passwords don't match")
        .interact()
        .unwrap();

    show_hint(&input_password, "password");

    log!();

    input_password
}

pub fn get_entropy() -> Vec<u8> {
    let input_entropy = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter your extra entropy")
        .interact()
        .unwrap();

    log!(
        "\nEntropy (please highlight to see): {}\nLength: {}\n",
        format!("\"{}\"", &input_entropy).black().on_black(),
        &input_entropy.len()
    );

    input_to_bytes(&input_entropy)
}

pub fn get_encryption_key_with_confirm(name: &str, confirm: bool) -> Vec<u8> {
    let theme = ColorfulTheme::default();
    let mut prompt = Password::with_theme(&theme).with_prompt(format!("Enter your {} encryption key", name));

    if confirm {
        prompt = prompt.with_confirmation(
            format!("Enter your {} encryption key again", name),
            "Error: keys don't match",
        );
    }

    let input = prompt.interact().unwrap();

    let key = input_to_bytes(&input);

    show_hint(&input, &format!("{} encryption key", name));

    let capitalized = name.chars().next().unwrap().to_uppercase().collect::<String>() + &name[1..];
    normalize_and_harden_key(
        key,
        Some(&format!("{} encryption key", capitalized)),
        Some(&format!("{name} encryption key")),
    )
}

pub fn get_encryption_key(name: &str) -> Vec<u8> {
    get_encryption_key_with_confirm(name, true)
}

pub fn get_checkpoint_data() -> CheckpointData {
    log!("Please enter the checkpoint data manually:\n");

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
    let data = input_to_bytes(&data);

    if data.is_empty() {
        panic!("Invalid data");
    }

    let prev_data = if iteration > 1 {
        let prev_data: String = Input::new()
            .with_prompt("Previous data")
            .allow_empty(true)
            .interact_text()
            .unwrap();
        let prev_data = input_to_bytes(&prev_data);

        if prev_data.len() != data.len() {
            panic!("Invalid previous data's length");
        }

        Some(prev_data)
    } else {
        None
    };

    log!();

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

    log!();

    let scrypt_log_n: u8 = Input::new()
        .with_prompt("Scrypt log_n")
        .default(ScryptOptions::DEFAULT_LOG_N)
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
    let scrypt = ScryptOptions::new(scrypt_log_n, scrypt_r, scrypt_p);

    log!();

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

    log!();

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

    log!();

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

/// Convert hex or raw input to bytes
/// If the input starts with HEX_PREFIX, it's decoded as hex, otherwise treated as raw bytes
pub fn input_to_bytes(input: &str) -> Vec<u8> {
    if input.starts_with(HEX_PREFIX) {
        hex::decode(input.strip_prefix(HEX_PREFIX).unwrap()).unwrap()
    } else {
        input.as_bytes().to_vec()
    }
}

fn show_hint(data: &str, description: &str) {
    let len = data.len();

    let capitalized = description.chars().next().unwrap().to_uppercase().collect::<String>() + &description[1..];

    if len < MIN_SECRET_LENGTH_TO_REVEAL {
        warning!("{} is too short, therefore password hint won't be shown", capitalized);
    } else {
        let is_hex = data.starts_with(HEX_PREFIX);
        let prefix_len = if is_hex { 2 } else { 0 };

        log!(
            "\n{} hint is: {}...{} (length: {})",
            capitalized,
            format!("\"{}", &data[..prefix_len + 1]),
            format!("{}\"", &data[len - 1..]),
            len
        );
    }
}

pub fn generate_random_secret() -> (String, String) {
    let entropy = get_entropy();

    // Generate truly random data using the system's secure random number generator
    let mut rng = rand::thread_rng();
    let mut random_data: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();

    // Append the user-provided entropy to the randomly generated data
    random_data.extend_from_slice(&entropy);

    // Hash the combined data
    let mut hasher = Sha512::new();
    hasher.update(&random_data);
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

    if !output_dir.exists() {
        panic!("Output directory \"{}\" doesn't exist", output_dir.display());
    }

    // Ask for an encryption key
    log!("Please provide an encryption key for the secrets files:\n");

    let encryption_key = get_encryption_key("secrets");

    for i in 1..=count {
        let filename = format!(
            "{}{:0width$}.dat",
            prefix,
            i,
            width = (count as f64).log10().ceil() as usize
        );
        let filepath = output_dir.join(filename);

        if filepath.exists() {
            panic!("Output file \"{}\" already exists", filepath.display());
        }

        let (salt, password) = if random {
            log!("Please provide some extra entropy for secrets number {i} (this will be mixed into the random number generator):\n");

            generate_random_secret()
        } else {
            log!("Please provide the salt and the password for secrets number {i}:\n");

            (get_salt_normalized(false), get_password())
        };

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
        log!(
            "Salt for secrets file number {i} is (please highlight to see): {}",
            format!("\"{}\"", salt).black().on_black()
        );

        log!(
            "Password for secrets file number {i} is (please highlight to see): {}",
            format!("\"{}\"", password).black().on_black()
        );

        log!("Stored encrypted secrets file number {i} at: {}\n", filepath.display());
    }
}

pub fn print_input_instructions() {
    log!(
        "Please input all data either in raw or hex format starting with the {} prefix\n",
        HEX_PREFIX
    );
}

// Handlers options for other commands
pub struct CheckpointShowOptions {
    pub input: PathBuf,
    pub verify: bool,
    pub secrets: Option<PathBuf>,
    pub base64: bool,
    pub base58: bool,
}

pub fn handle_checkpoint_show(opts: CheckpointShowOptions) {
    print_input_instructions();

    let file_key = get_encryption_key_with_confirm("checkpoint", false);
    let checkpoint_data = Checkpoint::open(&OpenCheckpointOptions {
        key: file_key,
        path: opts.input,
    });

    checkpoint_data.print(crate::DisplayOptions {
        base64: opts.base64,
        base58: opts.base58,
        options: true,
    });

    if opts.verify {
        let (salt_str, password_str) = if let Some(secrets_path) = &opts.secrets {
            log!(
                "Loading password and salt from a secrets file: {}\n",
                secrets_path.display()
            );

            let secret_key = get_encryption_key_with_confirm("secrets", false);
            let secret = Secret::new(&SecretOptions {
                path: secrets_path.clone(),
                key: secret_key,
            });

            let secret_data = secret.open();
            (secret_data.data.salt, secret_data.data.password)
        } else {
            (get_salt(), get_password())
        };

        // Convert to bytes
        let salt = input_to_bytes(&salt_str);
        let password = input_to_bytes(&password_str);

        log!("Verifying the checkpoint...\n");

        if !checkpoint_data.verify(&salt, &password) {
            panic!("The password, salt, or internal data is incorrect!");
        }

        log!("The password, salt and internal data are correct\n");
    }
}

pub struct CheckpointRestoreOptions {
    pub iterations: usize,
    pub output: Option<PathBuf>,
    pub checkpoint_dir: Option<PathBuf>,
    pub checkpoint_interval: usize,
    pub max_checkpoints_to_keep: usize,
    pub input: Option<PathBuf>,
    pub interactive: bool,
    pub base64: bool,
    pub base58: bool,
    pub iteration_moving_window: u32,
    pub sanity: bool,
    pub secrets: Option<PathBuf>,
}

pub fn handle_checkpoint_restore(opts: CheckpointRestoreOptions) {
    print_input_instructions();

    let mut checkpoint_key: Option<Vec<u8>> = None;

    let checkpoint_data = match opts.input {
        Some(path) => {
            let key = get_encryption_key_with_confirm("checkpoint", false);
            checkpoint_key = Some(key.clone());

            Checkpoint::open(&OpenCheckpointOptions { key: key.clone(), path })
        },
        None => match opts.interactive {
            true => get_checkpoint_data(),
            false => panic!("Missing checkpoint path"),
        },
    };

    if opts.iterations <= checkpoint_data.data.iteration {
        panic!(
            "Invalid iterations number {} for checkpoint {}",
            opts.iterations, checkpoint_data.data.iteration
        );
    }

    let ck_opts = &checkpoint_data.data.slowkey;
    let options = SlowKeyOptions {
        iterations: opts.iterations,
        length: ck_opts.length,
        scrypt: ck_opts.scrypt,
        argon2id: ck_opts.argon2id,
        balloon_hash: ck_opts.balloon_hash,
    };

    derive(DeriveOptions {
        options,
        checkpoint_data: Some(checkpoint_data),
        output_key: None,
        checkpoint_key,
        checkpoint_dir: opts.checkpoint_dir,
        checkpoint_interval: opts.checkpoint_interval,
        max_checkpoints_to_keep: opts.max_checkpoints_to_keep,
        output: opts.output,
        base64: opts.base64,
        base58: opts.base58,
        iteration_moving_window: opts.iteration_moving_window,
        sanity: opts.sanity,
        secrets_path: opts.secrets,
    });
}

pub struct CheckpointReencryptOptions {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub fn handle_checkpoint_reencrypt(opts: CheckpointReencryptOptions) {
    print_input_instructions();

    let key = get_encryption_key_with_confirm("checkpoint", false);

    log!("Please provide the new file encryption key:\n");

    let new_key = get_encryption_key("checkpoint");

    Checkpoint::reencrypt(&opts.input, key, &opts.output, new_key);

    log!("Saved new checkpoint at \"{}\"", opts.output.display());
}

pub struct OutputShowOptions {
    pub input: PathBuf,
    pub verify: bool,
    pub secrets: Option<PathBuf>,
    pub base64: bool,
    pub base58: bool,
}

pub fn handle_output_show(opts: OutputShowOptions) {
    print_input_instructions();

    let file_key = get_encryption_key_with_confirm("output", false);
    let output_data = Output::open(&OpenOutputOptions {
        key: file_key,
        path: opts.input,
    });

    output_data.print(crate::DisplayOptions {
        base64: opts.base64,
        base58: opts.base58,
        options: true,
    });

    if opts.verify {
        let (salt_str, password_str) = if let Some(secrets_path) = &opts.secrets {
            log!(
                "Loading password and salt from a secrets file: {}\n",
                secrets_path.display()
            );

            let secret_key = get_encryption_key_with_confirm("secrets", false);
            let secret = Secret::new(&SecretOptions {
                path: secrets_path.clone(),
                key: secret_key,
            });

            let secret_data = secret.open();
            (secret_data.data.salt, secret_data.data.password)
        } else {
            (get_salt(), get_password())
        };

        let salt = input_to_bytes(&salt_str);
        let password = input_to_bytes(&password_str);

        log!("Verifying the output...\n");

        if !output_data.verify(&salt, &password) {
            panic!("The password, salt, or internal data is incorrect!");
        }

        log!("The password, salt and internal data are correct\n");
    }
}

pub struct OutputReencryptOptions {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub fn handle_output_reencrypt(opts: OutputReencryptOptions) {
    print_input_instructions();

    let key = get_encryption_key_with_confirm("output", false);

    log!("Please provide the new file encryption key:\n");

    let new_key = get_encryption_key("output");

    Output::reencrypt(&opts.input, key, &opts.output, new_key);

    log!("Saved new output at \"{}\"", opts.output.display());
}

pub struct SecretsGenerateOptions {
    pub count: usize,
    pub output_dir: PathBuf,
    pub prefix: String,
    pub random: bool,
}

pub fn handle_secrets_generate(opts: SecretsGenerateOptions) {
    generate_secrets(opts.count, opts.output_dir, opts.prefix, opts.random);
}

pub struct SecretsShowOptions {
    pub input: PathBuf,
    pub with_output: Option<PathBuf>,
}

pub fn handle_secrets_show(opts: SecretsShowOptions) {
    print_input_instructions();

    let key = if let Some(output_path) = opts.with_output {
        log!("Loading decryption key from output file: {}\n", output_path.display());

        log!("Please provide the encryption key for the output file:\n");

        let output_key = get_encryption_key_with_confirm("output", false);

        let output_data = Output::open(&OpenOutputOptions {
            key: output_key,
            path: output_path,
        });

        log!("Loaded derived key from output file");

        // Use the output's derived key as the decryption key
        // Normalize and harden it since it will be used as a decryption key
        normalize_and_harden_key(
            output_data.data.data,
            Some("Output derived key"),
            Some("output derived key"),
        )
    } else {
        log!("Please provide the encryption key for the secrets file:\n");

        get_encryption_key_with_confirm("secrets", false)
    };

    let secret = Secret::new(&SecretOptions {
        path: opts.input.clone(),
        key,
    });

    let secret_data = secret.open();

    secret_data.print();
}

pub struct SecretsReencryptOptions {
    pub input: PathBuf,
    pub output: PathBuf,
    pub with_output: Option<PathBuf>,
}

pub fn handle_secrets_reencrypt(opts: SecretsReencryptOptions) {
    print_input_instructions();

    log!("Please provide the current encryption key for the secrets file:\n");

    let key = get_encryption_key_with_confirm("secrets", false);

    let new_key = if let Some(output_path) = opts.with_output {
        log!("Loading encryption key from output file: {}\n", output_path.display());

        log!("Please provide the encryption key for the output file:\n");

        let output_key = get_encryption_key_with_confirm("output", false);

        let output_data = Output::open(&OpenOutputOptions {
            key: output_key,
            path: output_path,
        });

        log!("Loaded derived key from output file");

        // Use the output's derived key as the new encryption key
        // Normalize and harden it since it will be used as an encryption key
        normalize_and_harden_key(
            output_data.data.data,
            Some("Output derived key"),
            Some("output derived key"),
        )
    } else {
        log!("Please provide the new encryption key for the secrets file:\n");

        get_encryption_key("secrets")
    };

    Secret::reencrypt(&opts.input, key, &opts.output, new_key);

    log!("Saved reencrypted secrets file at \"{}\"", opts.output.display());
}

pub struct DeriveOptions {
    pub options: SlowKeyOptions,
    pub checkpoint_data: Option<CheckpointData>,
    pub output_key: Option<Vec<u8>>,
    pub checkpoint_key: Option<Vec<u8>>,
    pub checkpoint_dir: Option<PathBuf>,
    pub checkpoint_interval: usize,
    pub max_checkpoints_to_keep: usize,
    pub output: Option<PathBuf>,
    pub base64: bool,
    pub base58: bool,
    pub iteration_moving_window: u32,
    pub sanity: bool,
    pub secrets_path: Option<PathBuf>,
}

pub fn handle_derive(options: DeriveOptions) {
    print_input_instructions();

    derive(options);
}

pub fn derive(derive_options: DeriveOptions) {
    let options = derive_options.options;
    let mut output_key = derive_options.output_key;
    let mut checkpoint_key = derive_options.checkpoint_key;
    let mut checkpoint: Option<Checkpoint> = None;

    let mut _output_lock: Option<FileLock> = None;
    let mut out: Option<Output> = None;
    if let Some(output_path) = derive_options.output {
        if output_path.exists() {
            panic!("Output file \"{}\" already exists", output_path.display());
        }

        // Check if the output directory exists
        if let Some(parent) = output_path.parent() {
            if !parent.exists() {
                panic!("Output directory \"{}\" does not exist", parent.display());
            }
        } else {
            panic!(
                "Could not determine the parent directory for output file \"{}\"",
                output_path.display()
            );
        }

        _output_lock = match FileLock::try_lock(&output_path) {
            Ok(lock) => Some(lock),
            Err(_) => panic!("Unable to lock {}", output_path.display()),
        };

        if output_key.is_none() {
            output_key = Some(get_encryption_key("output"));
        }

        out = Some(Output::new(&crate::utils::outputs::output::OutputOptions {
            path: output_path,
            key: output_key.clone().unwrap(),
            slowkey: options.clone(),
        }))
    }

    if let Some(checkpoint_data) = &derive_options.checkpoint_data {
        checkpoint_data.print(crate::DisplayOptions::default());
    }

    options.print();

    let (salt_str, password_str) = if let Some(secrets_path) = &derive_options.secrets_path {
        log!(
            "Loading password and salt from a secrets file: {}\n",
            secrets_path.display()
        );

        let secret_key = get_encryption_key_with_confirm("secrets", false);
        let secret = Secret::new(&SecretOptions {
            path: secrets_path.clone(),
            key: secret_key,
        });

        let secret_data = secret.open();

        log!("Loaded password and salt from secrets file\n");

        (secret_data.data.salt, secret_data.data.password)
    } else {
        (get_salt(), get_password())
    };

    // Convert salt string to bytes
    let salt = input_to_bytes(&salt_str);

    // Convert password string to bytes
    let password = input_to_bytes(&password_str);

    let mut offset: usize = 0;
    let mut offset_data = Vec::new();
    let mut prev_data = Vec::new();

    if let Some(checkpoint_data) = &derive_options.checkpoint_data {
        log!("Verifying the checkpoint...\n");

        if !checkpoint_data.verify(&salt, &password) {
            panic!("The password, salt, or internal data is incorrect!");
        }

        log!("The password, salt and internal data are correct\n");

        offset = checkpoint_data.data.iteration + 1;
        offset_data.clone_from(&checkpoint_data.data.data);

        // Since we are starting from this checkpoint, set the rolling previous data to its data
        prev_data = checkpoint_data.data.data.clone();
    }

    // Print the colored hash fingerprint of the parameters
    let fingerprint = Fingerprint::from_data(&options, &salt, &password);
    fingerprint.print();

    if let Some(dir) = derive_options.checkpoint_dir {
        if checkpoint_key.is_none() {
            checkpoint_key = Some(get_encryption_key("checkpoint"));
        }

        checkpoint = Some(Checkpoint::new(
            &crate::utils::checkpoints::checkpoint::CheckpointOptions {
                iterations: options.iterations,
                dir: dir.to_owned(),
                key: checkpoint_key.clone().unwrap(),
                max_checkpoints_to_keep: derive_options.max_checkpoints_to_keep,
                slowkey: options.clone(),
            },
        ));

        log!(
            "Checkpoint will be created every {} iterations and saved to the \"{}\" checkpoints directory\n",
            derive_options.checkpoint_interval.to_string().cyan(),
            &dir.display().to_string().cyan()
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
    pb.enable_steady_tick(std::time::Duration::from_secs(1));

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
            derive_options.sanity,
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
                    format_duration(std::time::Duration::from_millis(moving_average as u64))
                        .to_string()
                        .cyan(),
                    format_duration(std::time::Duration::from_millis(last_iteration_time as u64))
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
                        checkpoint.create(current_iteration, current_data, prev_data);

                        let hash = Checkpoint::hash(current_iteration, current_data, prev_data);

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

    let key = handle.join().unwrap();

    log!(
        "\n\nOutput is (please highlight to see): {}",
        format!("0x{}", hex::encode(&key)).black().on_black()
    );

    if derive_options.base64 {
        log!(
            "\nOutput (base64) is (please highlight to see): {}",
            general_purpose::STANDARD.encode(&key).black().on_black()
        );
    }

    if derive_options.base58 {
        log!(
            "\nOutput (base58) is (please highlight to see): {}",
            bs58::encode(&key).into_string().black().on_black()
        );
    }

    log!();

    if let Some(out) = out {
        let prev_data_guard = prev_data_mutex.lock().unwrap();
        let prev_data_option: Option<&[u8]> = if prev_data_guard.is_empty() {
            None
        } else {
            Some(&prev_data_guard[..])
        };

        out.save(&key, prev_data_option, &fingerprint);

        log!("Saved encrypted output to \"{}\"\n", &out.path.to_str().unwrap().cyan(),);
    }

    log!(
        "Start time: {}",
        DateTime::<Local>::from(start_time)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .cyan()
    );
    log!(
        "End time: {}",
        DateTime::<Local>::from(SystemTime::now())
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .cyan()
    );
    log!(
        "Total running time: {}",
        format_duration(std::time::Duration::from_secs(running_time.elapsed().as_secs()))
            .to_string()
            .cyan()
    );
    log!(
        "Average iteration time: {}",
        format_duration(std::time::Duration::from_millis(
            (running_time.elapsed().as_millis() as f64 / options.iterations as f64).round() as u64
        ))
        .to_string()
        .cyan()
    );
}

pub struct DaisyDeriveOptions {
    pub options: SlowKeyOptions,
    pub output: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub base64: bool,
    pub base58: bool,
    pub iteration_moving_window: u32,
    pub sanity: bool,
    pub fast_forward: bool,
    pub secrets_paths: Vec<PathBuf>,
}

pub fn handle_daisy_derive(opts: DaisyDeriveOptions) {
    print_input_instructions();

    if opts.secrets_paths.is_empty() {
        panic!("At least one secrets file must be provided");
    }

    // Fast-forward mode requires output_dir
    if opts.fast_forward && opts.output_dir.is_none() {
        panic!("Fast-forward mode requires --output-dir to be specified");
    }

    log!(
        "Daisy-chaining derivation through {} secrets file(s)\n",
        opts.secrets_paths.len()
    );

    if opts.fast_forward {
        log!("Fast-forward mode enabled: will skip derivation for secrets files with existing outputs\n");
    }

    // Ask for the initial encryption key for the first secrets file
    log!("Please provide the encryption key for the first secrets file:\n");
    let mut current_key = get_encryption_key_with_confirm("secrets", false);

    // Ask for the output encryption key if output or output_dir is specified
    let output_key = if opts.output.is_some() || opts.output_dir.is_some() {
        Some(get_encryption_key("output"))
    } else {
        None
    };

    let mut final_key = Vec::new();
    let mut last_salt = Vec::new();
    let mut last_password = Vec::new();
    let overall_start_time = SystemTime::now();

    // Process each secrets file in sequence
    for (i, secrets_path) in opts.secrets_paths.iter().enumerate() {
        log!(
            "Processing secrets file {} of {}: {}\n",
            i + 1,
            opts.secrets_paths.len(),
            secrets_path.display()
        );

        let running_time = Instant::now();

        // Decrypt the secrets file to get salt/password (needed for next iteration's key and final output fingerprint)
        log!(
            "Decrypting secrets file {} of {}: {}\n",
            i + 1,
            opts.secrets_paths.len(),
            secrets_path.display()
        );
        let secret = Secret::new(&SecretOptions {
            path: secrets_path.clone(),
            key: current_key.clone(),
        });

        let secret_data = secret.open();
        let (salt_str, password_str) = (secret_data.data.salt, secret_data.data.password);

        log!("Loaded password and salt from secrets file\n");

        // Fast-forward: check if output exists and try to decrypt it
        let fast_forward_result: Option<(Vec<u8>, Fingerprint)> = if opts.fast_forward {
            if let Some(ref output_dir) = opts.output_dir {
                // Get the filename from the secrets path and prefix it with DAISY_OUTPUT_PREFIX
                let secrets_filename = secrets_path
                    .file_name()
                    .unwrap_or_else(|| {
                        panic!(
                            "Could not determine filename for secrets file: {}",
                            secrets_path.display()
                        )
                    })
                    .to_string_lossy();
                let output_filename = format!("{}{}", DAISY_OUTPUT_PREFIX, secrets_filename);
                let output_path = output_dir.join(output_filename);

                if output_path.exists() {
                    log!("Found existing output file: {}\n", output_path.display());
                    log!("Attempting to decrypt output file using provided key...\n");

                    let output_data = Output::open(&OpenOutputOptions {
                        key: output_key.clone().unwrap(),
                        path: output_path.clone(),
                    });

                    log!("Successfully decrypted output file - fast-forwarding past derivation\n");
                    Some((output_data.data.data, output_data.data.fingerprint))
                } else {
                    log!("No existing output file found - will perform derivation\n");
                    // Perform derivation below
                    None
                }
            } else {
                // Perform derivation below
                None
            }
        } else {
            // Perform derivation below
            None
        };

        // Convert salt string to bytes
        let salt = input_to_bytes(&salt_str);

        // Convert password string to bytes
        let password = input_to_bytes(&password_str);

        // Save the last salt and password for output file fingerprint
        last_salt = salt.clone();
        last_password = password.clone();

        // If fast-forward didn't find a file, perform the derivation
        let was_fast_forwarded = fast_forward_result.is_some();
        let (key, fingerprint) = if let Some((k, f)) = fast_forward_result {
            (k, f)
        } else {
            // Derive using the secrets file
            let options = opts.options.clone();
            options.print();

            // Print the colored hash fingerprint of the parameters
            let fingerprint = Fingerprint::from_data(&options, &salt, &password);
            fingerprint.print();

            let mb = MultiProgress::new();

            // Create the main progress bar
            let pb = mb.add(ProgressBar::new(options.iterations as u64)).with_style(
                ProgressStyle::with_template("{bar:80.cyan/blue} {pos:>8}/{len:8} {msg}%    ({eta})").unwrap(),
            );

            pb.reset_eta();
            pb.enable_steady_tick(std::time::Duration::from_secs(1));

            pb.set_message("0");

            // Create a progress bar to track iteration times
            let ipb = mb
                .add(ProgressBar::new(options.iterations as u64))
                .with_style(ProgressStyle::with_template("{msg}").unwrap());

            let mut iteration_time = Instant::now();
            let mut samples: VecDeque<u128> = VecDeque::new();

            let slowkey = SlowKey::new(&options);

            let key = slowkey.derive_key_with_callback(
                &salt,
                &password,
                &[],
                0,
                opts.sanity,
                |current_iteration, _current_data| {
                    // Track iteration times
                    let last_iteration_time = iteration_time.elapsed().as_millis();
                    iteration_time = Instant::now();

                    samples.push_back(last_iteration_time);

                    // If we have more than the required samples, remove the oldest one
                    if samples.len() > opts.iteration_moving_window as usize {
                        samples.pop_front();
                    }

                    // Calculate the moving average
                    let moving_average = samples.iter().sum::<u128>() as f64 / samples.len() as f64;

                    let iteration_info = format!(
                        "\nIteration time moving average ({}): {}, last iteration time: {}",
                        opts.iteration_moving_window.to_string().cyan(),
                        format_duration(std::time::Duration::from_millis(moving_average as u64))
                            .to_string()
                            .cyan(),
                        format_duration(std::time::Duration::from_millis(last_iteration_time as u64))
                            .to_string()
                            .cyan(),
                    );

                    pb.inc(1);

                    // Set the percent using a custom message
                    pb.set_message(format!(
                        "{}",
                        ((current_iteration + 1) * 100) as f64 / options.iterations as f64
                    ));

                    ipb.set_message(iteration_info);
                },
            );

            pb.finish();
            ipb.finish();

            (key, fingerprint)
        };

        log!(
            "Derived key for secrets file {} is (please highlight to see): {}",
            i + 1,
            format!("0x{}", hex::encode(&key)).black().on_black()
        );

        log!(
            "\nSecrets file {} processing time: {}\n",
            i + 1,
            format_duration(std::time::Duration::from_secs(running_time.elapsed().as_secs()))
                .to_string()
                .cyan()
        );

        // Save the derived key to output_dir if specified (skip if fast-forwarded and file already exists)
        if let Some(ref output_dir) = opts.output_dir {
            if !output_dir.exists() {
                panic!("Output directory \"{}\" does not exist", output_dir.display());
            }

            // Get the filename from the secrets path and prefix it with DAISY_OUTPUT_PREFIX
            let secrets_filename = secrets_path
                .file_name()
                .unwrap_or_else(|| {
                    panic!(
                        "Could not determine filename for secrets file: {}",
                        secrets_path.display()
                    )
                })
                .to_string_lossy();
            let output_filename = format!("{}{}", DAISY_OUTPUT_PREFIX, secrets_filename);
            let output_path = output_dir.join(output_filename);

            // Skip saving if file already exists (fast-forward case)
            if output_path.exists() {
                if was_fast_forwarded {
                    log!(
                        "Output file already exists (fast-forwarded) - skipping save: \"{}\"",
                        output_path.display().to_string().cyan()
                    );
                } else {
                    panic!("Output file \"{}\" already exists", output_path.display());
                }
            } else {
                let _output_lock = match FileLock::try_lock(&output_path) {
                    Ok(lock) => lock,
                    Err(_) => panic!("Unable to lock {}", output_path.display()),
                };

                let out = Output::new(&crate::utils::outputs::output::OutputOptions {
                    path: output_path.clone(),
                    key: output_key.clone().unwrap(),
                    slowkey: opts.options.clone(),
                });

                out.save(&key, None, &fingerprint);

                log!(
                    "Saved encrypted output for secrets file {} to \"{}\"",
                    i + 1,
                    output_path.display().to_string().cyan()
                );
            }
        }

        // Save the final key
        final_key = key.clone();

        // If this is not the last file, normalize and harden the key for use as decryption key
        if i < opts.secrets_paths.len() - 1 {
            // Normalize and harden the derived key (same process as get_encryption_key_with_confirm)
            // This is necessary because secrets files are encrypted with hardened keys
            current_key = normalize_and_harden_key(key, Some("Derived key"), Some("derived key"));

            log!("Using derived key as decryption key for next secrets file...\n",);
        }
    }

    // Display final result
    log!(
        "\nFinal output is (please highlight to see): {}",
        format!("0x{}", hex::encode(&final_key)).black().on_black()
    );

    if opts.base64 {
        log!(
            "\nFinal output (base64) is (please highlight to see): {}",
            general_purpose::STANDARD.encode(&final_key).black().on_black()
        );
    }

    if opts.base58 {
        log!(
            "\nFinal output (base58) is (please highlight to see): {}",
            bs58::encode(&final_key).into_string().black().on_black()
        );
    }

    log!();

    // Handle output file if specified
    if let Some(output_path) = opts.output {
        if output_path.exists() {
            panic!("Output file \"{}\" already exists", output_path.display());
        }

        // Check if the output directory exists
        if let Some(parent) = output_path.parent() {
            if !parent.exists() {
                panic!("Output directory \"{}\" does not exist", parent.display());
            }
        } else {
            panic!(
                "Could not determine the parent directory for output file \"{}\"",
                output_path.display()
            );
        }

        let _output_lock = match FileLock::try_lock(&output_path) {
            Ok(lock) => lock,
            Err(_) => panic!("Unable to lock {}", output_path.display()),
        };

        let out = Output::new(&crate::utils::outputs::output::OutputOptions {
            path: output_path.clone(),
            key: output_key.clone().unwrap(),
            slowkey: opts.options.clone(),
        });

        // Use the last secrets file's salt and password for the fingerprint
        let fingerprint = Fingerprint::from_data(&opts.options, &last_salt, &last_password);

        out.save(&final_key, None, &fingerprint);

        log!(
            "Saved encrypted output to \"{}\"\n",
            output_path.display().to_string().cyan()
        );
    }

    log!(
        "Start time: {}",
        DateTime::<Local>::from(overall_start_time)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .cyan()
    );
    log!(
        "End time: {}",
        DateTime::<Local>::from(SystemTime::now())
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .cyan()
    );
}
