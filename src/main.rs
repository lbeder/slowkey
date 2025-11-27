mod cli;
mod utils;

extern crate chacha20poly1305;
extern crate hex;
extern crate indicatif;
extern crate libsodium_sys;
extern crate serde;
extern crate serde_json;

mod slowkey;
mod stability;

use crate::cli::DeriveOptions;
use crate::stability::stability_test;
use crate::{
    slowkey::{SlowKey, SlowKeyOptions},
    utils::{
        algorithms::{
            argon2id::{Argon2idImplementation, Argon2idOptions},
            balloon_hash::BalloonHashOptions,
            scrypt::{ScryptImplementation, ScryptOptions},
        },
        checkpoints::checkpoint::CheckpointOptions,
        color_hash::color_hash,
        sodium_init::initialize,
    },
};
use clap::{Parser, Subcommand};
use mimalloc::MiMalloc;
use stability::STABILITY_TEST_ITERATIONS;
use std::{env, path::PathBuf};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(author, about, long_about = None, arg_required_else_help = true, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
            default_value = SlowKeyOptions::DEFAULT_OUTPUT_SIZE.to_string(),
            help = format!("Length of the derived result (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_KEY_SIZE, SlowKeyOptions::MAX_KEY_SIZE)
        )]
        length: usize,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_LOG_N.to_string(),
            help = format!("Scrypt CPU/memory cost parameter (must be lesser than or equal {})", ScryptOptions::MAX_LOG_N)
        )]
        scrypt_log_n: u8,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_R.to_string(),
            help = format!("Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than {} and lesser than or equal to {})", ScryptOptions::MIN_R, ScryptOptions::MAX_R)
        )]
        scrypt_r: u32,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_P.to_string(),
            help = format!("Scrypt parallelization parameter (must be greater than {} and lesser than or equal {})", ScryptOptions::MIN_P, ScryptOptions::MAX_P)
        )]
        scrypt_p: u32,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Use rust-crypto's Scrypt implementation instead of libsodium (default)"
        )]
        scrypt_rc: bool,

        #[arg(
            long,
            default_value = Argon2idOptions::DEFAULT_M_COST.to_string(),
            help = format!("Argon2 number of 1 KiB memory block (must be greater than {} and lesser than or equal {})", Argon2idOptions::MIN_M_COST, Argon2idOptions::MAX_M_COST))]
        argon2_m_cost: u32,

        #[arg(
            long,
            default_value = Argon2idOptions::DEFAULT_T_COST.to_string(),
            help = format!("Argon2 number of iterations (must be greater than {} and lesser than or equal {})", Argon2idOptions::MIN_T_COST, Argon2idOptions::MAX_T_COST))]
        argon2_t_cost: u32,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Use rust-crypto's Argon2id implementation instead of libsodium (default)"
        )]
        argon2_rc: bool,

        #[arg(
            long,
            default_value = BalloonHashOptions::DEFAULT_S_COST.to_string(),
            help = format!("Balloon Hash space (memory) cost number of 1 KiB memory block (must be greater than {} and lesser than or equal {})", BalloonHashOptions::MIN_S_COST, BalloonHashOptions::MAX_S_COST))]
        balloon_s_cost: u32,

        #[arg(
            long,
            default_value = BalloonHashOptions::DEFAULT_T_COST.to_string(),
            help = format!("Balloon Hash number of iterations (must be greater than {} and lesser than or equal {})", BalloonHashOptions::MIN_T_COST, BalloonHashOptions::MAX_T_COST))]
        balloon_t_cost: u32,

        #[arg(long, help = "Optional file path for storing the encrypted output")]
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

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Perform an optional sanity check by computing the algorithm twice and verifying the results"
        )]
        sanity: bool,

        #[arg(long, help = "Optional path to a secrets file containing password and salt")]
        secrets: Option<PathBuf>,
    },

    #[command(subcommand, about = "Checkpoint operations", arg_required_else_help = true)]
    Checkpoint(CheckpointCommands),

    #[command(subcommand, about = "Output operations", arg_required_else_help = true)]
    Output(OutputCommands),

    #[command(subcommand, about = "Secrets operations", arg_required_else_help = true)]
    Secrets(SecretsCommands),

    #[command(about = "Run benchmarks")]
    Bench {
        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Use rust-crypto's Scrypt implementation instead of libsodium (default)"
        )]
        scrypt_rc: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Use rust-crypto's Argon2id implementation instead of libsodium (default)"
        )]
        argon2_rc: bool,
    },

    #[command(about = "Run stability tests", arg_required_else_help = true)]
    StabilityTest {
        #[arg(long, short, help = "Number of tasks")]
        tasks: usize,

        #[arg(
            long,
            short,
            default_value = STABILITY_TEST_ITERATIONS.to_string(),
            help = format!("Number of iterations to perform (must be greater than {} and lesser than or equal {})", 0, STABILITY_TEST_ITERATIONS))]
        iterations: usize,
    },

    #[command(about = "Daisy-chain derivation through multiple secrets files")]
    DaisyDerive {
        #[arg(
            short,
            long,
            help = format!("Number of iterations (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_ITERATIONS, SlowKeyOptions::MAX_ITERATIONS)
        )]
        iterations: usize,

        #[arg(
            short,
            long,
            default_value = SlowKeyOptions::DEFAULT_OUTPUT_SIZE.to_string(),
            help = format!("Length of the derived result (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_KEY_SIZE, SlowKeyOptions::MAX_KEY_SIZE)
        )]
        length: usize,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_LOG_N.to_string(),
            help = format!("Scrypt CPU/memory cost parameter (must be lesser than or equal {})", ScryptOptions::MAX_LOG_N)
        )]
        scrypt_log_n: u8,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_R.to_string(),
            help = format!("Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than {} and lesser than or equal to {})", ScryptOptions::MIN_R, ScryptOptions::MAX_R)
        )]
        scrypt_r: u32,

        #[arg(
            long,
            default_value = ScryptOptions::DEFAULT_P.to_string(),
            help = format!("Scrypt parallelization parameter (must be greater than {} and lesser than or equal {})", ScryptOptions::MIN_P, ScryptOptions::MAX_P)
        )]
        scrypt_p: u32,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Use rust-crypto's Scrypt implementation instead of libsodium (default)"
        )]
        scrypt_rc: bool,

        #[arg(
            long,
            default_value = Argon2idOptions::DEFAULT_M_COST.to_string(),
            help = format!("Argon2 number of 1 KiB memory block (must be greater than {} and lesser than or equal {})", Argon2idOptions::MIN_M_COST, Argon2idOptions::MAX_M_COST))]
        argon2_m_cost: u32,

        #[arg(
            long,
            default_value = Argon2idOptions::DEFAULT_T_COST.to_string(),
            help = format!("Argon2 number of iterations (must be greater than {} and lesser than or equal {})", Argon2idOptions::MIN_T_COST, Argon2idOptions::MAX_T_COST))]
        argon2_t_cost: u32,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Use rust-crypto's Argon2id implementation instead of libsodium (default)"
        )]
        argon2_rc: bool,

        #[arg(
            long,
            default_value = BalloonHashOptions::DEFAULT_S_COST.to_string(),
            help = format!("Balloon Hash space (memory) cost number of 1 KiB memory block (must be greater than {} and lesser than or equal {})", BalloonHashOptions::MIN_S_COST, BalloonHashOptions::MAX_S_COST))]
        balloon_s_cost: u32,

        #[arg(
            long,
            default_value = BalloonHashOptions::DEFAULT_T_COST.to_string(),
            help = format!("Balloon Hash number of iterations (must be greater than {} and lesser than or equal {})", BalloonHashOptions::MIN_T_COST, BalloonHashOptions::MAX_T_COST))]
        balloon_t_cost: u32,

        #[arg(long, help = "Optional file path for storing the encrypted output")]
        output: Option<PathBuf>,

        #[arg(
            long,
            help = "Optional directory for storing encrypted outputs for each secrets file in the chain. Each output file will be named \"output_\" followed by the secrets file name"
        )]
        output_dir: Option<PathBuf>,

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

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Perform an optional sanity check by computing the algorithm twice and verifying the results"
        )]
        sanity: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Fast-forward mode: skip derivation for secrets files that have existing outputs in the output directory. Requires --output-dir to be specified"
        )]
        fast_forward: bool,

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Verify output files during fast-forward mode using the password and salt from the secrets file"
        )]
        verify: bool,

        #[arg(
            long,
            help = "List of secrets files to daisy chain in sequential order (mandatory). Use --secrets <file1> --secrets <file2> ... to specify multiple files",
            required = true
        )]
        secrets: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CheckpointCommands {
    #[command(about = "Print a checkpoint", arg_required_else_help = true)]
    Show {
        #[arg(long, help = "Path to an existing checkpoint")]
        input: PathBuf,

        #[arg(long, help = "Verify that the password and salt match the checkpoint")]
        verify: bool,

        #[arg(long, help = "Optional path to a secrets file containing password and salt")]
        secrets: Option<PathBuf>,

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

    #[command(
        about = "Continue derivation process from an existing checkpoint",
        arg_required_else_help = true
    )]
    Restore {
        #[arg(
            short,
            long,
            help = format!("Number of iterations (must be greater than {} and lesser than or equal to {})", SlowKeyOptions::MIN_ITERATIONS, SlowKeyOptions::MAX_ITERATIONS)
        )]
        iterations: usize,

        #[arg(long, help = "Optional file path for storing the encrypted output")]
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
        input: Option<PathBuf>,

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

        #[arg(
            long,
            action = clap::ArgAction::SetTrue,
            help = "Perform an optional sanity check by computing the algorithm twice and verifying the results"
        )]
        sanity: bool,

        #[arg(long, help = "Optional path to a secrets file containing password and salt")]
        secrets: Option<PathBuf>,
    },

    #[command(about = "Reencrypt a checkpoint", arg_required_else_help = true)]
    Reencrypt {
        #[arg(long, help = "Path to an existing checkpoint")]
        input: PathBuf,

        #[arg(long, help = "Path to the new checkpoint")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum OutputCommands {
    #[command(about = "Print an output file", arg_required_else_help = true)]
    Show {
        #[arg(long, help = "Path to an existing output")]
        input: PathBuf,

        #[arg(long, help = "Verify that the password and salt match the output")]
        verify: bool,

        #[arg(long, help = "Optional path to a secrets file containing password and salt")]
        secrets: Option<PathBuf>,

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

    #[command(about = "Reencrypt an output file", arg_required_else_help = true)]
    Reencrypt {
        #[arg(long, help = "Path to an existing output")]
        input: PathBuf,

        #[arg(long, help = "Path to the new checkpoint")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SecretsCommands {
    #[command(about = "Generate and encrypt multiple secrets", arg_required_else_help = true)]
    Generate {
        #[arg(short, long, help = "Number of secrets to generate")]
        count: usize,

        #[arg(short, long, help = "Output directory for the secrets files")]
        output_dir: PathBuf,

        #[arg(
            short,
            long,
            help = "Prefix for the secrets files (generated files will end with \".dat\")"
        )]
        prefix: String,

        #[arg(short, long, help = "Generate random secrets instead of prompting for each")]
        random: bool,
    },

    #[command(
        about = "Show the contents of an encrypted secrets file",
        arg_required_else_help = true
    )]
    Show {
        #[arg(long, help = "Path to an existing secrets file")]
        input: PathBuf,

        #[arg(
            long,
            help = "Optional path to an output file. If provided, the output's derived key will be used as the decryption key for the secrets file"
        )]
        with_output: Option<PathBuf>,
    },

    #[command(about = "Reencrypt a secrets file with a new key", arg_required_else_help = true)]
    Reencrypt {
        #[arg(long, help = "Path to an existing secrets file")]
        input: PathBuf,

        #[arg(long, help = "Path to the new secrets file")]
        output: PathBuf,

        #[arg(
            long,
            help = "Optional path to an output file. If provided, the output's derived key will be used as the new encryption key for the secrets file"
        )]
        with_output: Option<PathBuf>,
    },
}

const BENCHMARKS_DIRECTORY: &str = "benchmarks";

#[derive(PartialEq, Debug, Clone, Default)]
pub struct DisplayOptions {
    pub base64: bool,
    pub base58: bool,
    pub options: bool,
}

fn main() {
    better_panic::install();
    color_backtrace::install();

    // Initialize libsodium
    initialize();

    log!("SlowKey v{VERSION}\n");

    let cli = Cli::parse();

    match cli.command {
        Commands::Derive {
            iterations,
            length,
            output,
            scrypt_log_n,
            scrypt_r,
            scrypt_p,
            scrypt_rc,
            argon2_m_cost,
            argon2_t_cost,
            argon2_rc,
            balloon_s_cost,
            balloon_t_cost,
            checkpoint_dir,
            checkpoint_interval,
            max_checkpoints_to_keep,
            base64,
            base58,
            iteration_moving_window,
            sanity,
            secrets,
        } => {
            let scrypt_implementation = if scrypt_rc {
                ScryptImplementation::RustCrypto
            } else {
                ScryptImplementation::Libsodium
            };
            let argon2_implementation = if argon2_rc {
                Argon2idImplementation::RustCrypto
            } else {
                Argon2idImplementation::Libsodium
            };
            cli::handle_derive(DeriveOptions {
                options: SlowKeyOptions::new(
                    iterations,
                    length,
                    &ScryptOptions::new_with_implementation(scrypt_log_n, scrypt_r, scrypt_p, scrypt_implementation),
                    &Argon2idOptions::new_with_implementation(argon2_m_cost, argon2_t_cost, argon2_implementation),
                    &BalloonHashOptions::new(balloon_s_cost, balloon_t_cost),
                ),
                checkpoint_data: None,
                output_key: None,
                checkpoint_key: None,
                checkpoint_dir,
                checkpoint_interval,
                max_checkpoints_to_keep,
                output,
                base64,
                base58,
                iteration_moving_window,
                sanity,
                secrets_path: secrets,
            });
        },

        Commands::Checkpoint(cmd) => match cmd {
            CheckpointCommands::Show {
                input,
                verify,
                secrets,
                base64,
                base58,
            } => {
                cli::handle_checkpoint_show(cli::CheckpointShowOptions {
                    input,
                    verify,
                    secrets,
                    base64,
                    base58,
                });
            },

            CheckpointCommands::Restore {
                iterations,
                output,
                checkpoint_dir,
                checkpoint_interval,
                max_checkpoints_to_keep,
                input,
                interactive,
                base64,
                base58,
                iteration_moving_window,
                sanity,
                secrets,
            } => {
                cli::handle_checkpoint_restore(cli::CheckpointRestoreOptions {
                    iterations,
                    output,
                    checkpoint_dir,
                    checkpoint_interval,
                    max_checkpoints_to_keep,
                    input,
                    interactive,
                    base64,
                    base58,
                    iteration_moving_window,
                    sanity,
                    secrets,
                });
            },

            CheckpointCommands::Reencrypt { input, output } => {
                cli::handle_checkpoint_reencrypt(cli::CheckpointReencryptOptions { input, output });
            },
        },

        Commands::Output(cmd) => match cmd {
            OutputCommands::Show {
                input,
                verify,
                secrets,
                base64,
                base58,
            } => {
                cli::handle_output_show(cli::OutputShowOptions {
                    input,
                    verify,
                    secrets,
                    base64,
                    base58,
                });
            },

            OutputCommands::Reencrypt { input, output } => {
                cli::handle_output_reencrypt(cli::OutputReencryptOptions { input, output });
            },
        },

        Commands::Secrets(cmd) => match cmd {
            SecretsCommands::Generate {
                count,
                output_dir,
                prefix,
                random,
            } => {
                cli::handle_secrets_generate(cli::SecretsGenerateOptions {
                    count,
                    output_dir,
                    prefix,
                    random,
                });
            },

            SecretsCommands::Show { input, with_output } => {
                cli::handle_secrets_show(cli::SecretsShowOptions { input, with_output });
            },

            SecretsCommands::Reencrypt {
                input,
                output,
                with_output,
            } => {
                cli::handle_secrets_reencrypt(cli::SecretsReencryptOptions {
                    input,
                    output,
                    with_output,
                });
            },
        },

        Commands::Bench { scrypt_rc, argon2_rc } => {
            let output_path = env::current_dir().unwrap().join(BENCHMARKS_DIRECTORY);

            let scrypt_implementation = if scrypt_rc {
                ScryptImplementation::RustCrypto
            } else {
                ScryptImplementation::Libsodium
            };

            let argon2_implementation = if argon2_rc {
                Argon2idImplementation::RustCrypto
            } else {
                Argon2idImplementation::Libsodium
            };

            SlowKey::benchmark(&output_path, scrypt_implementation, argon2_implementation);

            log!("Saved benchmark reports to: \"{}\"", output_path.display());
        },

        Commands::StabilityTest { tasks, iterations } => {
            stability_test(tasks, iterations);
        },

        Commands::DaisyDerive {
            iterations,
            length,
            scrypt_log_n,
            scrypt_r,
            scrypt_p,
            scrypt_rc,
            argon2_m_cost,
            argon2_t_cost,
            argon2_rc,
            balloon_s_cost,
            balloon_t_cost,
            output,
            output_dir,
            base64,
            base58,
            iteration_moving_window,
            sanity,
            fast_forward,
            verify,
            secrets,
        } => {
            let scrypt_implementation = if scrypt_rc {
                ScryptImplementation::RustCrypto
            } else {
                ScryptImplementation::Libsodium
            };
            let argon2_implementation = if argon2_rc {
                Argon2idImplementation::RustCrypto
            } else {
                Argon2idImplementation::Libsodium
            };
            cli::handle_daisy_derive(cli::DaisyDeriveOptions {
                options: SlowKeyOptions::new(
                    iterations,
                    length,
                    &ScryptOptions::new_with_implementation(scrypt_log_n, scrypt_r, scrypt_p, scrypt_implementation),
                    &Argon2idOptions::new_with_implementation(argon2_m_cost, argon2_t_cost, argon2_implementation),
                    &BalloonHashOptions::new(balloon_s_cost, balloon_t_cost),
                ),
                output,
                output_dir,
                base64,
                base58,
                iteration_moving_window,
                sanity,
                fast_forward,
                verify,
                secrets_paths: secrets,
            });
        },
    }
}
