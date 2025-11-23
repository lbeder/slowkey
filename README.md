# SlowKey: Advanced Key Derivation Tool Using Scrypt, Argon2id, SHA2, and SHA3

[![Build Status](https://github.com/lbeder/slowkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lbeder/slowkey/actions/workflows/ci.yml)

## Table of Contents

- [Introduction](#introduction)
- [SlowKey Key Derivation Scheme](#slowkey-key-derivation-scheme)
  - [Definitions](#definitions)
  - [Input](#input)
  - [Output](#output)
  - [Scheme](#scheme)
- [Usage](#usage)
  - [General](#general)
  - [Deriving](#deriving)
  - [Daisy-Chain Derivation](#daisy-chain-derivation)
  - [Checkpoints](#checkpoints)
    - [Showing a Checkpoint](#showing-a-checkpoint)
    - [Restoring from a Checkpoint](#restoring-from-a-checkpoint)
    - [Reencrypting a Checkpoint](#reencrypting-a-checkpoint)
  - [Outputs](#outputs)
    - [Showing an Output](#showing-an-output)
    - [Reencrypting an Output](#reencrypting-an-output)
  - [Secrets](#secrets)
    - [Generating Secrets](#generating-secrets)
    - [Showing a Secret](#showing-a-secret)
    - [Reencrypting a Secret](#reencrypting-a-secret)
  - [Running Benchmarks](#running-benchmarks)
  - [Running Stability Tests](#running-stability-tests)
- [Build](#build)
  - [Mac OS ARM64](#mac-os-arm64)
  - [Mac OS x64](#mac-os-x64)
  - [Linux x64](#linux-x64)
  - [Linux ARM64](#linux-arm64)
- [Examples](#examples)
  - [Checkpoint Operations](#checkpoint-operations)
  - [Output Commands](#output-commands)
- [Benchmarks](#benchmarks)
- [Stability Tests](#stability-tests)
- [Sanity Mode](#sanity-mode)
- [License](#license)

## Introduction

SlowKey is a cutting-edge [Key Derivation Function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF) tool designed to enhance cryptographic security in various applications, from securing sensitive data to protecting user passwords. At its core, SlowKey leverages the power of five renowned cryptographic algorithms: [Scrypt](https://en.wikipedia.org/wiki/Scrypt), [Argon2](https://en.wikipedia.org/wiki/Argon2), [Balloon Hash](https://en.wikipedia.org/wiki/Balloon_hashing), [SHA2](https://en.wikipedia.org/wiki/SHA-2), and [SHA3](https://en.wikipedia.org/wiki/SHA-3), each selected for its unique strengths in ensuring data integrity and security.

SlowKey incorporates Scrypt, a memory-hard KDF that is specifically engineered to make brute-force attacks prohibitively expensive. By requiring significant amounts of memory and processing power to compute the hash functions, Scrypt ensures that the cost and time to perform large-scale custom hardware attacks are beyond the reach of most attackers, offering robust protection against rainbow table and brute-force attacks.

SlowKey integrates Argon2, an advanced, memory-hard Key Derivation Function (KDF) designed to effectively thwart brute-force and side-channel attacks. As the winner of the Password Hashing Competition, Argon2 is tailored to ensure that the computation of hash functions demands substantial memory and processing resources, making it exceedingly difficult for attackers to mount large-scale custom hardware attacks. This requirement for significant computational effort not only increases the security against brute-force and rainbow table attacks but also provides a customizable framework that can be tuned for specific defense needs, ensuring an adaptable and formidable barrier against unauthorized access attempts.

SlowKey incorporates Balloon Hash, a memory-hard Key Derivation Function (KDF) specifically designed to resist brute-force and large-scale custom hardware attacks. By requiring sequential memory access and significant computational resources, Balloon Hash ensures that attackers face steep costs in time and resources when attempting to compute hash functions at scale. Its emphasis on simplicity and flexibility, combined with its resistance to side-channel attacks, makes it an effective tool for securing passwords and sensitive data against rainbow table, brute-force, and hardware-accelerated attacks. This robust memory-hard approach provides a strong foundation for modern cryptographic security requirements.

Alongside Scrypt, Argon2, and Balloon Hash, SlowKey utilizes SHA2 and SHA3 for their exceptional hash functions, providing an additional layer of security. SHA2, a member of the Secure Hash Algorithm family, offers a high level of resistance against hash collision attacks, making it an excellent choice for secure hashing needs. SHA3, the latest member of the Secure Hash Algorithm family, further strengthens SlowKey's cryptographic capabilities with its resistance to various attack vectors, including those that may affect earlier SHA versions.

A cornerstone of SlowKey's design philosophy is its commitment to resilience through diversity. By integrating Scrypt, SHA2, and SHA3 within its cryptographic framework, SlowKey not only capitalizes on the unique strengths of each algorithm but also ensures a level of security redundancy that is critical in the face of evolving cyber threats. This strategic mixture means that even if one of these algorithms were to be compromised or "broken" due to unforeseen vulnerabilities, the overall security scheme of SlowKey would remain robust and intact, safeguarded by the uncompromised integrity of the remaining algorithms. This approach mirrors the principle of layered security in cybersecurity, where multiple defensive strategies are employed to protect against a single point of failure. Consequently, SlowKey offers an advanced, forward-thinking solution that anticipates and mitigates the potential impact of future cryptographic breakthroughs or advancements in quantum computing that could threaten individual hash functions. Through this multi-algorithm strategy, SlowKey provides a safeguard against the entire spectrum of cryptographic attacks, ensuring long-term security for its users in a landscape where the only constant is change.

The use of ECC memory is recommended where possible as it provides much higher stability and protection against data errors and corruption especially when performing long-term key stretching. Please note however that full system ECC is rarely supported, is much more expensive,  and is usually found in high-end workstations and servers where data reliability is critical. It is also not common in high-end consumer and gaming systems which are actually likely to yield the fastest results (highest CPU and RAM clock speeds).

Regardless, This does not replace the need for verifying that the key stretching performed correctly by running it a second time, preferably on a separate system.

Please note that separate from full system ECC which requires specific CPU, RAM and motherboard compatibility support, there is RAM with on-die (internal) ECC which, while not as robust as full system ECC, does provide additional stability and is a recommended optimization for long-term key stretching.

## SlowKey Key Derivation Scheme

The SlowKey Key Derivation Scheme is defined as follows:

### Definitions

- `Concatenate(data1, data2, data3)`: Function to concatenate `data1`, `data2`, and `data3`.
- `SHA2(data)`: Function to compute SHA2 (SHA512) hash of `data`.
- `SHA3(data)`: Function to compute SHA3 (Keccak512) hash of `data`.
- `Scrypt(data, salt)`: Function to derive a key using Scrypt KDF with `data` and `salt`.
- `Argon2id(data, salt)`: Function to derive a key using Argon2id KDF with `data` and `salt`.
- `BalloonHash(data, salt)`: Function to derive a key using Balloon Hash KDF with `data` and `salt`.

### Input

- `password`: User's password.
- `salt`: Unique salt for hashing. Please note that the salt must be `16` bytes long, therefore shorter/longer salts will be SHA512 hashed and then truncated into `16` bytes.
- `iterations`: Number of iterations the process should be repeated.

### Output

- `result`: Derived key after all iterations.

### Scheme

```pseudo
function deriveKey(password, salt, iterations):
    // Calculate the SHA2 and SHA3 hashes of the result and the inputs
    step1 = SHA2(concatenate(salt, password))
    result = SHA3(concatenate(step1, salt, password))

    for iteration from 1 to iterations:
        // Run all KDF algorithms in parallel
        step2_1 = Scrypt(concatenate(result, salt, password, iteration), salt)
        step2_2 = Argon2id(concatenate(result, salt, password, iteration), salt)
        step2_3 = BalloonHash(concatenate(result, salt, password, iteration), salt)

        // Concatenate all the results and the inputs
        step3 = concatenate(step2_1, step2_2, step2_3, salt, password, iteration)

        // Calculate the SHA2 and SHA3 hashes of the result and the inputs
        step4 = SHA2(concatenate(step3, salt, password, iteration))
        step5 = SHA3(concatenate(step4, salt, password, iteration))

        result = truncate(step5, key_size)

    return result
```

## Usage

For tips on maximizing performance and efficiency—including OS/hardware tuning, recommended CLI parameters for Scrypt, Argon2id, and Balloon Hash, and best practices for long runs—see the [Performance & Efficiency Guide for Running Slowkey](OPTIMIZATION.md).

### General

```sh
Usage: slowkey [COMMAND]

Commands:
  derive          Derive a key using using Scrypt, Argon2, Balloon Hash, SHA2, and SHA3
  daisy-derive    Daisy-chain derivation through multiple secrets files
  checkpoint      Checkpoint operations
  output          Output operations
  secrets         Secrets operations
  bench           Run benchmarks
  stability-test  Run stability tests

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Deriving

```sh
Derive a key using using Scrypt, Argon2, Balloon Hash, SHA2, and SHA3

Usage: slowkey derive [OPTIONS] --iterations <ITERATIONS>

Options:
  -i, --iterations <ITERATIONS>
          Number of iterations (must be greater than 1 and lesser than or equal to 4294967295)
  -l, --length <LENGTH>
          Length of the derived result (must be greater than 9 and lesser than or equal to 64) [default: 32]
      --scrypt-log-n <SCRYPT_LOG_N>
          Scrypt CPU/memory cost parameter (must be lesser than or equal 63) [default: 20]
      --scrypt-r <SCRYPT_R>
          Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and lesser than or equal to 4294967295) [default: 8]
      --scrypt-p <SCRYPT_P>
          Scrypt parallelization parameter (must be greater than 0 and lesser than or equal 4294967295) [default: 1]
      --argon2-m-cost <ARGON2_M_COST>
          Argon2 number of 1 KiB memory block (must be greater than 8 and lesser than or equal 4294967295) [default: 2097152]
      --argon2-t-cost <ARGON2_T_COST>
          Argon2 number of iterations (must be greater than 2 and lesser than or equal 4294967295) [default: 2]
      --balloon-s-cost <BALLOON_S_COST>
          Balloon Hash space (memory) cost number of 1 KiB memory block (must be greater than 1 and lesser than or equal 4294967295) [default: 131072]
      --balloon-t-cost <BALLOON_T_COST>
          Balloon Hash number of iterations (must be greater than 1 and lesser than or equal 4294967295) [default: 1]
      --output <OUTPUT>
          Optional path for storing the encrypted output
      --checkpoint-dir <CHECKPOINT_DIR>
          Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named "checkpoint.i", indicating the iteration number at which the checkpoint was created
      --checkpoint-interval <CHECKPOINT_INTERVAL>
          Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save [default: 1]
      --max-checkpoints-to-keep <MAX_CHECKPOINTS_TO_KEEP>
          Specifies the number of most recent checkpoints to keep, while automatically deleting older ones [default: 1]
      --base64
          Show the result in Base64 (in addition to hex)
      --base58
          Show the result in Base58 (in addition to hex)
      --iteration-moving-window <ITERATION_MOVING_WINDOW>
          Iteration time sampling moving window size [default: 10]
      --sanity
          Perform an optional sanity check by computing the algorithm twice and verifying the results
      --secrets <SECRET>
          Optional path to a secrets file containing password and salt
  -h, --help
          Print help
```

### Daisy-Chain Derivation

The `daisy-derive` command enables daisy-chaining key derivation through multiple encrypted secrets files. This feature allows you to create a chain of derivations where each derived key becomes the decryption key for the next secrets file in the sequence. This is useful for scenarios where you want to create a layered security approach, where each secrets file is protected by the key derived from the previous one.

The workflow is as follows:

1. You provide an initial encryption key to decrypt the first secrets file
2. The tool derives a key using the password and salt from the first secrets file
3. The derived key is used to decrypt the second secrets file
4. The tool derives a new key using the password and salt from the second secrets file
5. This process continues for each subsequent secrets file in the chain
6. The final derived key is the output

Note that when using a derived key as a decryption key for the next secrets file, the key is automatically normalized to 32 bytes (ChaCha20Poly1305::KEY_SIZE) using SHA512 hashing if the derived key length differs from 32 bytes, and then hardened using SlowKey with fixed parameters (same process as used for encrypting secrets files). This ensures that the derived key is properly formatted and hardened before being used to decrypt the next secrets file in the chain.

```sh
Daisy-chain derivation through multiple secrets files

Usage: slowkey daisy-derive [OPTIONS] --secrets <SECRETS>...

Options:
  -i, --iterations <ITERATIONS>
          Number of iterations (must be greater than 1 and lesser than or equal to 4294967295)
  -l, --length <LENGTH>
          Length of the derived result (must be greater than 9 and lesser than or equal to 64) [default: 32]
      --scrypt-log-n <SCRYPT_LOG_N>
          Scrypt CPU/memory cost parameter (must be lesser than or equal 63) [default: 20]
      --scrypt-r <SCRYPT_R>
          Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and lesser than or equal to 4294967295) [default: 8]
      --scrypt-p <SCRYPT_P>
          Scrypt parallelization parameter (must be greater than 0 and lesser than or equal 4294967295) [default: 1]
      --argon2-m-cost <ARGON2_M_COST>
          Argon2 number of 1 KiB memory block (must be greater than 8 and lesser than or equal 4294967295) [default: 2097152]
      --argon2-t-cost <ARGON2_T_COST>
          Argon2 number of iterations (must be greater than 2 and lesser than or equal 4294967295) [default: 2]
      --balloon-s-cost <BALLOON_S_COST>
          Balloon Hash space (memory) cost number of 1 KiB memory block (must be greater than 1 and lesser than or equal 4294967295) [default: 131072]
      --balloon-t-cost <BALLOON_T_COST>
          Balloon Hash number of iterations (must be greater than 1 and lesser than or equal 4294967295) [default: 1]
      --output <OUTPUT>
          Optional path for storing the encrypted output
      --base64
          Show the result in Base64 (in addition to hex)
      --base58
          Show the result in Base58 (in addition to hex)
      --iteration-moving-window <ITERATION_MOVING_WINDOW>
          Iteration time sampling moving window size [default: 10]
      --sanity
          Perform an optional sanity check by computing the algorithm twice and verifying the results
      --secrets <SECRETS>...
          List of secrets files to daisy-chain (mandatory)
  -h, --help
          Print help
```

Example usage:

```sh
slowkey daisy-derive -i 1000 --secrets secret1.dat --secrets secret2.dat --secrets secret3.dat --output final_output.dat
```

The command will:

1. Prompt for the encryption key to decrypt `secret1.dat`
2. Derive a key using the password and salt from `secret1.dat`
3. Normalize and harden the derived key, then use it to decrypt `secret2.dat`
4. Derive a key using the password and salt from `secret2.dat`
5. Normalize and harden the derived key, then use it to decrypt `secret3.dat`
6. Derive the final key using the password and salt from `secret3.dat`
7. Save the final key to `final_output.dat` if specified

Each step shows progress bars and timing information, and the derived key from each step is displayed (in hex format by default, with optional Base64 and Base58 formats).

### Checkpoints

```sh
Checkpoint operations

Usage: slowkey checkpoint <COMMAND>

Commands:
  show       Print a checkpoint
  restore    Continue derivation process from an existing checkpoint
  reencrypt  Reencrypt a checkpoint

Options:
  -h, --help  Print help
```

#### Showing a Checkpoint

```sh
Print a checkpoint

Usage: slowkey checkpoint show [OPTIONS] --path <PATH>

Options:
      --path <PATH>        Path to an existing checkpoint
      --verify             Verify that the password and salt match the checkpoint
      --secrets <SECRETS>  Optional path to a secrets file containing password and salt
      --base64             Show the result in Base64 (in addition to hex)
      --base58             Show the result in Base58 (in addition to hex)
  -h, --help               Print help
```

#### Restoring from a Checkpoint

```sh
Continue derivation process from an existing checkpoint

Usage: slowkey checkpoint restore [OPTIONS] --iterations <ITERATIONS>

Options:
  -i, --iterations <ITERATIONS>
          Number of iterations (must be greater than 1 and lesser than or equal to 4294967295)
      --output <OUTPUT>
          Optional path for storing the encrypted output
      --checkpoint-dir <CHECKPOINT_DIR>
          Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named "checkpoint.i", indicating the iteration number at which the checkpoint was created
      --checkpoint-interval <CHECKPOINT_INTERVAL>
          Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save [default: 1]
      --max-checkpoints-to-keep <MAX_CHECKPOINTS_TO_KEEP>
          Specifies the number of most recent checkpoints to keep, while automatically deleting older ones [default: 1]
      --path <PATH>
          Path to an existing checkpoint from which to resume the derivation process
      --interactive
          Input checkpoint data interactively (instead of providing the path to an existing checkpoint)
      --base64
          Show the result in Base64 (in addition to hex)
      --base58
          Show the result in Base58 (in addition to hex)
      --iteration-moving-window <ITERATION_MOVING_WINDOW>
          Iteration time sampling moving window size [default: 10]
      --sanity
          Perform an optional sanity check by computing the algorithm twice and verifying the results
      --secrets <SECRET>
          Optional path to a secrets file containing password and salt
  -h, --help
          Print help
```

#### Reencrypting a Checkpoint

```sh
Reencrypt a checkpoint

Usage: slowkey checkpoint reencrypt --input <INPUT> --output <OUTPUT>

Options:
      --input <INPUT>    Path to an existing checkpoint
      --output <OUTPUT>  Path to the new checkpoint
  -h, --help             Print help
```

### Outputs

```sh
Output operations

Usage: slowkey output <COMMAND>

Commands:
  show       Print an output file
  reencrypt  Reencrypt an output file

Options:
  -h, --help  Print help
```

#### Showing an Output

```sh
Print an output file

Usage: slowkey output show [OPTIONS] --path <PATH>

Options:
      --path <PATH>        Path to an existing output
      --verify             Verify that the password and salt match the output
      --secrets <SECRETS>  Optional path to a secrets file containing password and salt
      --base64             Show the result in Base64 (in addition to hex)
      --base58             Show the result in Base58 (in addition to hex)
  -h, --help               Print help
```

#### Reencrypting an Output

```sh
Reencrypt an output file

Usage: slowkey output reencrypt --input <INPUT> --output <OUTPUT>

Options:
      --input <INPUT>    Path to an existing output
      --output <OUTPUT>  Path to the new checkpoint
  -h, --help             Print help
```

### Secrets

The secrets functionality provides a more secure way for inputting the salt and password since both are encrypted and stored in files, avoiding the need to input them directly through the console/keyboard. This approach reduces the risk of sensitive data being exposed through command history, shoulder surfing, or other forms of input monitoring. By encrypting and storing these secrets in files, users can maintain better security practices while still being able to use their passwords and salts for key derivation operations.

```sh
Secrets operations

Usage: slowkey secrets <COMMAND>

Commands:
  generate   Generate and encrypt multiple secrets
  show       Show the contents of an encrypted secrets file
  reencrypt  Reencrypt a secrets file with a new key

Options:
  -h, --help  Print help
```

#### Generating Secrets

```sh
Generate and encrypt multiple secrets

Usage: slowkey secrets generate [OPTIONS] --count <COUNT> --output-dir <OUTPUT_DIR> --prefix <PREFIX>

Options:
  -c, --count <COUNT>            Number of secrets to generate
  -o, --output-dir <OUTPUT_DIR>  Output directory for the secrets
  -p, --prefix <PREFIX>          Prefix for the secrets files
  -r, --random                   Generate random secrets instead of prompting for each
  -h, --help                     Print help
```

Note about entropy input: When using the `--random` option, the tool prompts for extra entropy. Some terminals limit the maximum input line length (for example, 4095 characters). After you press Enter, SlowKey echoes the provided entropy and prints its length ("Entropy (please highlight to see): ... Length: N"). Please verify the printed entropy and its length to ensure your input was not truncated by the terminal.

#### Showing a Secret

```sh
Show the contents of an encrypted secrets file

Usage: slowkey secrets show --path <PATH>

Options:
      --path <PATH>  Path to the secrets   file
  -h, --help         Print help
```

#### Reencrypting a Secret

```sh
Reencrypt a secrets file with a new key

Usage: slowkey secrets reencrypt --input <INPUT> --output <OUTPUT>

Options:
      --input <INPUT>    Path to an existing secrets file
      --output <OUTPUT>  Path to the new secrets file
  -h, --help             Print help
```

### Running Benchmarks

```sh
Run benchmarks

Usage: slowkey bench

Options:
  -h, --help  Print help
```

### Running Stability Tests

```sh
Run stability tests

Usage: slowkey stability-test [OPTIONS] --tasks <TASKS>

Options:
  -t, --tasks <TASKS>            Number of tasks
  -i, --iterations <ITERATIONS>  Number of iterations to perform (must be greater than 0 and lesser than or equal 2000) [default: 2000]
  -h, --help                     Print help
```

## Build

### Mac OS ARM64

```sh
cargo build --release --target aarch64-apple-darwin
```

### Mac OS x64

```sh
cargo build --release --target x86_64-apple-darwin
```

### Linux x64

```sh
CROSS_CONTAINER_OPTS="--platform linux/amd64" cross build --release --target=x86_64-unknown-linux-gnu
```

### Linux ARM64

Install the ARM64 Linux target on a Mac:

```sh
rustup target add aarch64-unknown-linux-gnu
```

Use `homebrew` to install a community-provided macOS cross-compiler toolchains:

```sh
brew tap messense/macos-cross-toolchains
brew install aarch64-unknown-linux-gnu
```

```sh
export CC_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-g++
export AR_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc
cargo build --release --target aarch64-unknown-linux-gnu
```

## Examples

In this tool, the input provided by the user is first evaluated to determine its format. If the input string begins with `0x`, it is interpreted as a hexadecimal representation of a byte array. The tool will then parse this hexadecimal string into its corresponding byte sequence, allowing for hexadecimal data to be input directly in a recognizable format. Conversely, if the input does not start with `0x`, it is treated as raw data and used as is, without any conversion. This dual functionality enables flexibility, allowing users to input either hexadecimal or raw data based on their needs.

Let's try to derive the key for the password `password`, using the salt `saltsaltsaltsalt`:

> slowkey derive -i 10

```sh
Please input all data either in raw or hex format starting with the 0x prefix

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Fingerprint: 438AD0BD7EF347F5

████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/10       30%    (19s)

Iteration time moving average (10): 2s 546ms, last iteration time: 2s 536ms
```

Final result:

```sh
✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 2s 526ms, last iteration time: 2s 529ms

Output is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-13 19:20:53
End time: 2024-12-13 19:21:18
Total running time: 25s
Average iteration time: 2s 526ms
```

You can also use a secrets file instead of entering the password and salt interactively:

> slowkey derive -i 10 --secrets ~/my_secrets.dat

```sh
Please input all data either in raw or hex format starting with the 0x prefix

Loading password and salt from a secrets file: ~/my_secrets.dat

✔ Enter your secrets encryption key · ********

Hardening the secrets encryption key using SlowKey

Loaded password and salt from secrets file

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

Fingerprint: 438AD0BD7EF347F5

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 2s 526ms, last iteration time: 2s 529ms

Output is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-13 19:20:53
End time: 2024-12-13 19:21:18
Total running time: 25s
Average iteration time: 2s 526ms
```

Please note that salt must be `16` bytes long, therefore shorter/longer salts will be SHA512 hashed and then truncated into `16` bytes:

In order to hide the output from prying eyes, we set both the background and foreground colors of text to black in a terminal, so that text becomes "hidden" because it blends into the background. However, in some terminals, highlighting this text with the cursor won't reveal it because the highlight color itself might be configured in a way that doesn't provide sufficient contrast against the black text. This occurs because terminals use default color sets for text, background, and highlights, which can vary based on the terminal and its settings.

To work around the issue of invisible text during selection in the terminal, you can change the highlight color in the terminal's settings to ensure it contrasts with the black text and background. Typically, this involves accessing the settings or preferences menu of your terminal, navigating to the color scheme or appearance settings, and choosing a new color for selections or highlights. By setting the highlight color to white or another light shade, you can make the black text visible when selected, ensuring better usability and accessibility in your terminal sessions.

Despite the text being invisible, it's important to note that the text remains present in the terminal's buffer. This means that even if you cannot see the text, you can still copy it by selecting the area where the text is located and pasting it into a different application or a different part of the terminal that uses visible colors. The pasted text will appear in the default colors of the destination, revealing the hidden content.

```sh
✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

Warning: Salt's length 4 is shorter than 16; hashing with SHA512 and truncating to 16 bytes
```

```sh
✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

Warning: Salt's length 20 is longer than 16; hashing with SHA512 and truncating to 16 byte
```

### Checkpoint Operations

The tool also supports the creation of periodic checkpoints, which are securely encrypted and stored on the disk. Each checkpoint captures all parameters and the output from the last iteration, enabling you to resume computation from a previously established checkpoint. Additionally, the tool allows for the retention of multiple checkpoints.

Please note that even if the last checkpoint is done at the final iteration (in the case that the number of iterations divides by the check-pointing interval), the checkpoint still won't have the actual output until you complete the recovery process.

Each checkpoint, except for the one that coincides with the first iteration, also includes the output of the previous iteration. This allows the system to verify that the password and salt match the checkpoint by attempting to derive the checkpoint's iteration data from the previous iteration's data.

Please exercise caution when using this feature. Resuming computation from a compromised checkpoint may undermine your expectations regarding the duration of the key stretching process.

Please note that encryption key must be `32` bytes long, therefore shorter/longer will be first SHA512 hashed and then truncated into `32` bytes. In addition, the entered encryption key is further hardened by running a single SlowKey iteration with fixed parameters (independent of future defaults):

- iterations: 1
- length: 32
- Scrypt: n = 1,048,576 (2^20), r = 8, p = 1
- Argon2id: m_cost = 2,097,152 KiB (2^21), t_cost = 2
- Balloon Hash: s_cost = 131,072 KiB (2^17), t_cost = 1
- Salt: 16 zero bytes (`0x00000000000000000000000000000000`)

This hardening applies to all prompts for file encryption keys (e.g., checkpoint, output, and secrets files) and is intentionally constant over time so changes to global defaults do not affect file key derivation.

For instance, to elaborate on the previous example, suppose we want to create a checkpoint every `5` iterations forcefully terminate the execution at the `8th` iteration:

> slowkey derive -i 10 --checkpoint-interval 5 --max-checkpoints-to-keep 2 --checkpoint-dir ~/checkpoints

```sh
Please input all data either in raw or hex format starting with the 0x prefix

Checkpoint will be created every 5 iterations and saved to the "~/checkpoints" checkpoints directory

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

✔ Enter your checkpoint encryption key · ********

████████████████████████████████████████████████████████████████░░░░░░░░░░░░░░░░       5/10      80%    (10s)

Iteration time moving average (10): 2s 544ms, last iteration time: 2s 521ms
Created checkpoint #5 with data hash 0xc33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0
```

We can see that the `checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0` was retained in the `~/checkpoints` directory. Please note that file name contains iteration the checkpoint was taken at and a salted hash of the data.

Let's use the `checkpoint show` command to decrypt its contents and verify the parameters:

> slowkey checkpoint show --path ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)
```

We can also verify that the password and salt match the checkpoint by passing the optional `--verify` flag:

> slowkey checkpoint show --path ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0 --verify

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Verifying the checkpoint...

The password, salt and internal data are correct
```

Let's continue the derivation process from this checkpoint and verify that we arrive at the same final result as before. Please make sure to specify the correct number of iterations, as the checkpoint does not store the original iteration count.

> slowkey checkpoint restore -i 10 --path ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Verifying the checkpoint...

The password, salt and internal data are correct

Fingerprint: 438AD0BD7EF347F5

████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        5/10        0%    (4s)

Iteration time moving average (10): 4s 74ms, last iteration time: 4s 212ms
```

Final result:

```sh
████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 78ms, last iteration time: 4s 376ms

Output is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-13 19:27:29
End time: 2024-12-13 19:27:50
Total running time: 20s
Average iteration time: 2s 40ms
```

In addition to the above, you can use a checkpoint while specifying a larger iteration count. For example, if you originally ran 10,000 iterations and want to continue from checkpoint 9,000, you can set a higher iteration count, such as 100,000, when restoring from this checkpoint:

> slowkey checkpoint restore -i 20 --path ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Iterations: 20
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Verifying the checkpoint...

The password, salt and internal data are correct

Fingerprint: 438AD0BD7EF347F5

████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        5/20        0%    (56s)
```

Final result:

```sh
████████████████████████████████████████████████████████████████████████████████       20/20      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Output is (please highlight to see): 0x9e1a4e794f9c4f62a753f12b8c6971629579822c326c7ffcfdb8605a6146f94b

Start time: 2024-12-06 22:10:30
End time: 2024-12-06 22:11:09
Total running time: 39s
Average iteration time: 1s 993ms
```

You can also provide checkpoint data in an interactive way by specifying the `--interactive` flag:

> slowkey checkpoint restore -i 10 --interactive

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint encryption key · ********

Please enter the checkpoint data manually:

Version: 2
Iteration: 5
Data: 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
Previous data: 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

Length: 32

Scrypt log_n: 20
Scrypt r: 8
Scrypt p: 1

Argon2id m_cost: 2097152
Argon2id t_cost: 2

Balloon Hash s_cost: 131072
Balloon Hash t_cost: 1

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Verifying the checkpoint...

The password, salt and internal data are correct

Fingerprint: 438AD0BD7EF347F5

████████████████████████████████████████████████████████████████████████████████       10/10       100%    (0s)

Iteration time moving average (10): 3s 705ms, last iteration time: 2s 505ms

Output is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-13 19:35:09
End time: 2024-12-13 19:35:28
Total running time: 18s
Average iteration time: 1s 853ms
```

### Output Commands

By default, the tool outputs they key in a hexadecimal format, but the tool also supports both [Base64](https://en.wikipedia.org/wiki/Base64) and [Base58](https://en.wikipedia.org/wiki/Binary-to-text_encoding#Base58) formats optionally:

> slowkey derive -i 10 --base64 --base58

```sh
Please input all data either in raw or hex format starting with the 0x prefix

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Fingerprint: 438AD0BD7EF347F5

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Output is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a
Key (base64) is (please highlight to see): 2hWL7fAOWrupAODAJ8JJkS461c5UME/bVPGTndsUIyo
Key (base58) is (please highlight to see): FgJwB6BRc5wYjbeQnWh2q8egP3WVxK9hRqLsojvELRiR

Start time: 2024-12-06 21:56:34
End time: 2024-12-06 21:57:01
Total running time: 27s
Average iteration time: 2s 717ms
```

In addition to the above, the tool also supports saving the output to be encrypted and stored to the disk:

> slowkey derive -i 10 --output ~/output.enc

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your output encryption key · ********

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Fingerprint: 438AD0BD7EF347F5

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Output is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Saved encrypted output to "~/output.enc"

Start time: 2024-12-06 21:56:34
End time: 2024-12-06 21:57:01
Total running time: 27s
Average iteration time: 2s 717ms
```

Let's use the `output show` command to decrypt its contents:

> slowkey output show --path ~/output.enc

```sh
Output:
  Version: 2:
  Data (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a
  Previous Iteration's Data (please highlight to see): 0x339f2d3942a0eafba023a76b70148efd0b57aa760c17e61a2047b11c771d7e9b

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

Fingerprint: 438AD0BD7EF347F5
```

The output file checkpoint, except for the one that coincides with the first iteration, also includes the output of the previous iteration. This allows the system to verify that the password and salt match the output by attempting to derive the output's data from the previous iteration's data. This verification is optional and requires the `--verify` flag:

> slowkey output show --path ~/output.enc --verify

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your output encryption key · ********

Output:
  Version: 2:
  Data (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a
  Previous Iteration's Data (please highlight to see): 0x339f2d3942a0eafba023a76b70148efd0b57aa760c17e61a2047b11c771d7e9b

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (log_n: 20, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

Fingerprint: 438AD0BD7EF347F5

✔ Enter your salt · ********

Salt hint is: "s...t" (length: 16)

✔ Enter your password · ********

Password hint is: "p...d" (length: 8)

Verifying the output...

The password, salt and internal data are correct
```

## Benchmarks

In order to run the benchmark suite, you can run the `bench` command:

> slowkey bench

```sh
Benchmarking SHA2/1
Benchmarking SHA2/1: Warming up for 3.0000 s
Benchmarking SHA2/1: Collecting 100 samples in estimated 5.0008 s (22M iterations)
Benchmarking SHA2/1: Analyzing
SHA2/1                  time:   [224.03 ns 224.52 ns 225.05 ns]
                        change: [+0.1348% +0.7772% +1.2479%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

Benchmarking SHA3/1
Benchmarking SHA3/1: Warming up for 3.0000 s
Benchmarking SHA3/1: Collecting 100 samples in estimated 5.0006 s (22M iterations)
Benchmarking SHA3/1: Analyzing
SHA3/1                  time:   [228.68 ns 228.91 ns 229.17 ns]
                        change: [-2.3990% -1.4834% -0.8176%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 6 outliers among 100 measurements (6.00%)
  3 (3.00%) high mild
  3 (3.00%) high severe

Benchmarking Algorithms/Scrypt (Default)/n: 1048576, r: 8, p: 1
Benchmarking Algorithms/Scrypt (Default)/n: 1048576, r: 8, p: 1: Warming up for 3.0000 s
Benchmarking Algorithms/Scrypt (Default)/n: 1048576, r: 8, p: 1: Collecting 10 samples in estimated 40.363 s (20 iterations)
Benchmarking Algorithms/Scrypt (Default)/n: 1048576, r: 8, p: 1: Analyzing
Algorithms/Scrypt (Default)/n: 1048576, r: 8, p: 1
                        time:   [2.0214 s 2.0439 s 2.0689 s]
                        change: [+2.6760% +4.1539% +5.5774%] (p = 0.00 < 0.05)
                        Performance has regressed.
Benchmarking Algorithms/Argon2id (Default)/m_cost: 2097152, t_cost: 2
Benchmarking Algorithms/Argon2id (Default)/m_cost: 2097152, t_cost: 2: Warming up for 3.0000 s
Benchmarking Algorithms/Argon2id (Default)/m_cost: 2097152, t_cost: 2: Collecting 10 samples in estimated 48.981 s (20 iterations)
Benchmarking Algorithms/Argon2id (Default)/m_cost: 2097152, t_cost: 2: Analyzing
Algorithms/Argon2id (Default)/m_cost: 2097152, t_cost: 2
                        time:   [2.4135 s 2.4707 s 2.5275 s]
                        change: [+2.4967% +5.0294% +7.5737%] (p = 0.00 < 0.05)
                        Performance has regressed.
Benchmarking Algorithms/Balloon Hash (Default)/s_cost: 131072, t_cost: 1
Benchmarking Algorithms/Balloon Hash (Default)/s_cost: 131072, t_cost: 1: Warming up for 3.0000 s
Benchmarking Algorithms/Balloon Hash (Default)/s_cost: 131072, t_cost: 1: Collecting 10 samples in estimated 43.529 s (20 iterations)
Benchmarking Algorithms/Balloon Hash (Default)/s_cost: 131072, t_cost: 1: Analyzing
Algorithms/Balloon Hash (Default)/s_cost: 131072, t_cost: 1
                        time:   [2.1706 s 2.1747 s 2.1788 s]
                        change: [-1.0131% -0.4052% +0.1218%] (p = 0.21 > 0.05)
                        No change in performance detected.
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (m_cost: 209...
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (m_cost: 209...: Warming up for 3.0000 s
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (m_cost: 209...: Collecting 10 samples in estimated 51.109 s (20 iterations)
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (m_cost: 209...: Analyzing
Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (m_cost: 209...
                        time:   [2.5249 s 2.5369 s 2.5501 s]
                        change: [-1.1563% +0.0329% +1.1232%] (p = 0.95 > 0.05)
                        No change in performance detected.

Saved benchmark reports to: "~/benchmarks"
```

An HTML report will be generated in the `benchmarks` directory, but please make sure to install `gnuplot` beforehand.

## Stability Tests

The stability test works by ensuring the iteration outputs match expected pre-computed results. Setting a higher task count may take longer to complete but also increases stress testing on the system's resources, specifically CPU and RAM, in order to uncover faulty hardware or overclock settings which may result in incorrect hashing results that otherwise wouldn't be detected and could lead to random results. In general if you are using an overclocked system or suspected defective hardware it is recommended to also use an external stress testing application to ensure system stability.

Too many tasks may cause the application to be killed prematurely, therefore you should consider how many cpu cores are available when choosing a max task count. The higher the task count the heavier the load and the more likely to detect an error faster and in general. If an error is detected the task which failed is reported and the process is stopped. In this event it's important to further check for faulty RAM and/or unstable overclock settings before relying on your computer for using this key stretching tool.

Please note that based on your operation system environment each task may use a single CPU thread for all 3 hash functions (Scrypt, Argon2, Balloon Hash) or alternatively may use more than one thread collectively.

Technically the user doesn't need to let the tool finish the full 2000 iterations however the longer it runs the more certain you can be that your system is stable for the purposes of using this key stretching tool. If you plan on doing very long-term key stretching (weeks or months) and prefer to run the stability test for more than 2000 iterations simply restart the test process when it finishes either manually or using a script. Regardless, it is always recommended to run two separate instances of the key stretch to verify you generate the same output.

The stability test is also useful as a general sanity check as it verifies the results match correct pre-computed outputs, however it is not a replacement for manually verifying the results yourself by running the key stretching process with the same parameters a second time (or running two stretches in parallel assuming you have a large number of iterations and want to save time). Technically this can be done on the same computer but for the truly paranoid it's recommended to use a separate setup.

Disclaimer: This test is meant only to uncover some potential issues with your specific hardware/software environment but by no means does it guarantee the key stretching process will work correctly 100% of the time. You must manually verify the results yourself especially with higher iteration counts as key stretching is a memory and computationally resource intensive process therefore hardware heat issues and general hardware exhaustion can lead to faulty results without the user knowing.

Please note that specifically RAM overheating can cause computational glitches during the key stretching process without affecting the operating system / generating any visible errors even with the newest on-die ECC enabled DDR5 memory; therefore it is HIGHLY recommended to have a proper and robust cooling setup. The lower the operating temperatures of all the hardware components, the better the long-term stability of the system.

In order to run stability tests, you can run the `stability-test` command and specifying the number of tasks via the `-t/--tasks` argument:

> slowkey stability-test -t 8

```sh
Setting up a stability test task pool with 8 tasks, each running 2000 iterations

░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        3/2000     0%    (4h)
```

## Sanity Mode

If using the `--sanity` flag the application will run each of the 3 primary hash functions twice (6 threads in parallel) on the same input data and also derive the iteration output twice, and compare all the outputs to verify they are identical. If there is a discrepancy it will halt the process and provide details regarding the mismatch.

This is similar to the `stability-test`  function however can be used in real-time when key stretching and has the advantage of immediately notifying the user when an error has occurred. This can happen due to overstressed or faulty hardware, or problematic environment configurations and is an indication that the system in use in its current state is not stable enough for the purposes of key stretching. While it does provide a form of verification it does not guarantee that other types of errors might have occurred, and is not a replacement for verifying the results on a separate system either subsequently or in parallel.

Please note that due to how different operating systems manage multi-threaded processes, performance may be affected differently. For example using the `--sanity` flag may run just as fast as running two separate instances without the flag, or it may run significantly slower despite the fact that it is essentially the same number of threads/resources/computational overhead.

## License

MIT License

Copyright (c) 2024 Leonid Beder

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
