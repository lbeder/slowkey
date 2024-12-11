# SlowKey: Advanced Key Derivation Tool Using Scrypt, Argon2id, SHA2, and SHA3

[![Build Status](https://github.com/lbeder/slowkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lbeder/slowkey/actions/workflows/ci.yml)

## Introduction

SlowKey is a cutting-edge [Key Derivation Function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF) tool designed to enhance cryptographic security in various applications, from securing sensitive data to protecting user passwords. At its core, SlowKey leverages the power of three renowned cryptographic algorithms: [Scrypt](https://en.wikipedia.org/wiki/Scrypt), [Argon2](https://en.wikipedia.org/wiki/Argon2), [Balloon Hash](https://en.wikipedia.org/wiki/Balloon_hashing), [SHA2](https://en.wikipedia.org/wiki/SHA-2), and [SHA3](https://en.wikipedia.org/wiki/SHA-3), each selected for its unique strengths in ensuring data integrity and security.

SlowKey incorporates Scrypt, a memory-hard KDF that is specifically engineered to make brute-force attacks prohibitively expensive. By requiring significant amounts of memory and processing power to compute the hash functions, Scrypt ensures that the cost and time to perform large-scale custom hardware attacks are beyond the reach of most attackers, offering robust protection against rainbow table and brute-force attacks.

SlowKey integrates Argon2, an advanced, memory-hard Key Derivation Function (KDF) designed to effectively thwart brute-force and side-channel attacks. As the winner of the Password Hashing Competition, Argon2 is tailored to ensure that the computation of hash functions demands substantial memory and processing resources, making it exceedingly difficult for attackers to mount large-scale custom hardware attacks. This requirement for significant computational effort not only increases the security against brute-force and rainbow table attacks but also provides a customizable framework that can be tuned for specific defense needs, ensuring an adaptable and formidable barrier against unauthorized access attempts.

SlowKey incorporates Balloon Hash, a memory-hard Key Derivation Function (KDF) specifically designed to resist brute-force and large-scale custom hardware attacks. By requiring sequential memory access and significant computational resources, Balloon Hash ensures that attackers face steep costs in time and resources when attempting to compute hash functions at scale. Its emphasis on simplicity and flexibility, combined with its resistance to side-channel attacks, makes it an effective tool for securing passwords and sensitive data against rainbow table, brute-force, and hardware-accelerated attacks. This robust memory-hard approach provides a strong foundation for modern cryptographic security requirements.

Alongside Scrypt, Argon2, and Balloon Hash, SlowKey utilizes SHA2 and SHA3 for their exceptional hash functions, providing an additional layer of security. SHA2, a member of the Secure Hash Algorithm family, offers a high level of resistance against hash collision attacks, making it an excellent choice for secure hashing needs. SHA3, the latest member of the Secure Hash Algorithm family, further strengthens SlowKey's cryptographic capabilities with its resistance to various attack vectors, including those that may affect earlier SHA versions.

A cornerstone of SlowKey's design philosophy is its commitment to resilience through diversity. By integrating Scrypt, SHA2, and SHA3 within its cryptographic framework, SlowKey not only capitalizes on the unique strengths of each algorithm but also ensures a level of security redundancy that is critical in the face of evolving cyber threats. This strategic mixture means that even if one of these algorithms were to be compromised or "broken" due to unforeseen vulnerabilities, the overall security scheme of SlowKey would remain robust and intact, safeguarded by the uncompromised integrity of the remaining algorithms. This approach mirrors the principle of layered security in cybersecurity, where multiple defensive strategies are employed to protect against a single point of failure. Consequently, SlowKey offers an advanced, forward-thinking solution that anticipates and mitigates the potential impact of future cryptographic breakthroughs or advancements in quantum computing that could threaten individual hash functions. Through this multi-algorithm strategy, SlowKey provides a safeguard against the entire spectrum of cryptographic attacks, ensuring long-term security for its users in a landscape where the only constant is change.

## SlowKey Key Derivation Scheme

The SlowKey Key Derivation Scheme is defined as follows:

### Definitions

- `Concatenate(data1, data2, data3)`: Function to concatenate `data1`, `data2`, and `data3`.
- `SHA2(data)`: Function to compute SHA2 (SHA512) hash of `data`.
- `SHA3(data)`: Function to compute SHA3 (Keccak512) hash of `data`.
- `Scrypt(data, salt)`: Function to derive a key using Scrypt KDF with `data` and `salt`.
- `Argon2id(data, salt)`: Function to derive a key using Argon2id KDF with `data` and `salt`.
- `BalloonHash(data, salt)`: Function to derive a key using Balloon Hash KDF with `data` and `salt`.

### Inputs

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

### General

```sh
Usage: slowkey [COMMAND]

Commands:
  derive                   Derive a key using using Scrypt, Argon2, Balloon Hash, SHA2, and SHA3
  restore-from-checkpoint  Continue derivation process from an existing checkpoint
  show-checkpoint          Decrypt and print a checkpoint
  show-output              Decrypt and print an output file
  bench                    Run benchmarks

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
      --scrypt-n <SCRYPT_N>
          Scrypt CPU/memory cost parameter (must be lesser than 18446744073709551615) [default: 1048576]
      --scrypt-r <SCRYPT_R>
          Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and lesser than or equal to 4294967295) [default: 8]
      --scrypt-p <SCRYPT_P>
          Scrypt parallelization parameter (must be greater than 0 and lesser than 4294967295) [default: 1]
      --argon2-m-cost <ARGON2_M_COST>
          Argon2 number of 1 KiB memory block (must be greater than 8 and lesser than 4294967295) [default: 2097152]
      --argon2-t-cost <ARGON2_T_COST>
          Argon2 number of iterations (must be greater than 2 and lesser than 4294967295) [default: 2]
      --balloon-s-cost <BALLOON_S_COST>
          Balloon Hash space (memory) cost number of 1 KiB memory block (must be greater than 1 and lesser than 4294967295) [default: 131072]
      --balloon-t-cost <BALLOON_T_COST>
          Balloon Hash number of iterations (must be greater than 1 and lesser than 4294967295) [default: 1]
      --output <OUTPUT>
          Optional path for storing the encrypted output
      --checkpoint-dir <CHECKPOINT_DIR>
          Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named "checkpoint.i", indicating the iteration number at which the checkpoint was created
      --checkpoint-interval <CHECKPOINT_INTERVAL>
          Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save
      --max-checkpoints-to-keep <MAX_CHECKPOINTS_TO_KEEP>
          Specifies the number of most recent checkpoints to keep, while automatically deleting older ones [default: 1]
      --base64
          Show the result in Base64 (in addition to hex)
      --base58
          Show the result in Base58 (in addition to hex)
      --iteration-moving-window <ITERATION_MOVING_WINDOW>
          Iteration time sampling moving window size [default: 10]
  -h, --help
          Print help
```

### Restoring from a checkpoint

```sh
Continue derivation process from an existing checkpoint

Usage: slowkey restore-from-checkpoint [OPTIONS] --iterations <ITERATIONS>

Options:
  -i, --iterations <ITERATIONS>
          Number of iterations (must be greater than 1 and lesser than or equal to 4294967295)
      --output <OUTPUT>
          Optional path for storing the encrypted output
      --checkpoint-dir <CHECKPOINT_DIR>
          Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named "checkpoint.i", indicating the iteration number at which the checkpoint was created
      --checkpoint-interval <CHECKPOINT_INTERVAL>
          Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save
      --max-checkpoints-to-keep <MAX_CHECKPOINTS_TO_KEEP>
          Specifies the number of most recent checkpoints to keep, while automatically deleting older ones [default: 1]
      --checkpoint <CHECKPOINT>
          Path to an existing checkpoint from which to resume the derivation process
      --interactive
          Input checkpoint data interactively (instead of providing the path to an existing checkpoint)
      --base64
          Show the result in Base64 (in addition to hex)
      --base58
          Show the result in Base58 (in addition to hex)
      --iteration-moving-window <ITERATION_MOVING_WINDOW>
          Iteration time sampling moving window size [default: 10]
  -h, --help
          Print help
```

### Running Benchmarks

```sh
Run benchmarks

Usage: slowkey bench

Options:
  -h, --help  Print help
```

## Build

### Mac OS ARM64

```sh
git clone https://github.com/lbeder/slowkey
cd slowkey

cargo build --release
```

Depending on whether you are using x64 or arm64, you might need to add either the `x86_64-apple-darwin` or the `aarch64-apple-darwin` target accordingly:

```sh
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
```

### Linux x64

In order to get stuff working later, use the `nightly` branch of Rust:

```sh
rustup override set nightly
```

Install a standard Linux target on a Mac (note, that the opposite is currently impossible):

```sh
rustup target add x86_64-unknown-linux-musl
```

Use `homebrew` to install a community-provided macOS cross-compiler toolchains:

```sh
brew tap messense/macos-cross-toolchains
brew install x86_64-unknown-linux-musl
```

Now you can build it:

```sh
export CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-gcc
CROSS_COMPILE=x86_64-linux-musl- cargo build --target=x86_64-unknown-linux-musl
cargo build --target=x86_64-unknown-linux-musl
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
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░       1/10      10%    (54s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms
```

Final result:

```sh
✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Key is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-06 21:56:34
End time: 2024-12-06 21:57:01
Total running time: 27s
Average iteration time: 2s 717ms
```

Please note that salt must be `16` bytes long, therefore shorter/longer salts will be SHA512 hashed and then truncated into `16` bytes:

In order to hide the output from prying eyes, we set both the background and foreground colors of text to black in a terminal, so that text becomes "hidden" because it blends into the background. However, in some terminals, highlighting this text with the cursor won't reveal it because the highlight color itself might be configured in a way that doesn't provide sufficient contrast against the black text. This occurs because terminals use default color sets for text, background, and highlights, which can vary based on the terminal and its settings.

To work around the issue of invisible text during selection in the terminal, you can change the highlight color in the terminal's settings to ensure it contrasts with the black text and background. Typically, this involves accessing the settings or preferences menu of your terminal, navigating to the color scheme or appearance settings, and choosing a new color for selections or highlights. By setting the highlight color to white or another light shade, you can make the black text visible when selected, ensuring better usability and accessibility in your terminal sessions.

Despite the text being invisible, it's important to note that the text remains present in the terminal's buffer. This means that even if you cannot see the text, you can still copy it by selecting the area where the text is located and pasting it into a different application or a different part of the terminal that uses visible colors. The pasted text will appear in the default colors of the destination, revealing the hidden content.

```sh
✔ Enter your salt · ********

Salt is: s...t

Salt's size 4 is shorter than 16 and will be SHA512 hashed and then truncated into 16 bytes.
Do you want to continue? [y/n]
```

```sh
✔ Enter your salt · ********

Salt is: s...t

Salt's size 20 is longer than 16 and will be SHA512 hashed and then truncated into 16 bytes.
Do you want to continue? [y/n]
```

### Checkpoints

```sh
Decrypt and print a checkpoint

Usage: slowkey show-checkpoint [OPTIONS] --checkpoint <CHECKPOINT>

Options:
      --checkpoint <CHECKPOINT>  Path to an existing checkpoint
      --verify                   Verify that the password and salt match the checkpoint
      --base64                   Show the result in Base64 (in addition to hex)
      --base58                   Show the result in Base58 (in addition to hex)
  -h, --help                     Print help
```

The tool also supports the creation of periodic checkpoints, which are securely encrypted and stored on the disk. Each checkpoint captures all parameters and the output from the last iteration, enabling you to resume computation from a previously established checkpoint. Additionally, the tool allows for the retention of multiple checkpoints.

Please note that even if the last checkpoint is done at the final iteration (in the case that the number of iterations divides by the check-pointing interval), the checkpoint still won't have the actual output until you complete the recovery process.

Each checkpoint, except for the one that coincides with the first iteration, also includes the output of the previous iteration. This allows the system to verify that the password and salt match the checkpoint by attempting to derive the checkpoint's iteration data from the previous iteration's data.

Please exercise caution when using this feature. Resuming computation from a compromised checkpoint may undermine your expectations regarding the duration of the key stretching process.

Please note that encryption key must be `32` bytes long, therefore shorter/longer will be first SHA512 hashed and then truncated into `32` bytes:

For instance, to elaborate on the previous example, suppose we want to create a checkpoint every `5` iterations forcefully terminate the execution at the `8th` iteration:

> slowkey derive -i 10 --checkpoint-interval 5 --max-checkpoints-to-keep 2 --checkpoint-dir ~/checkpoints

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint will be created every 5 iterations and saved to the "~/checkpoints" checkpoints directory

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

████████████████████████████████████████████████████████████████░░░░░░░░░░░░░░░░       5/10      80%    (10s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms
Created checkpoint #5 with data hash 0xc33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0
```

We can see that the `checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0` was retained in the `~/checkpoints` directory. Please note that file name contains iteration the checkpoint was taken at and a salted hash of the data.

Let's use the `show-checkpoint` command to decrypt its contents and verify the parameters:

> slowkey show-checkpoint --checkpoint ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)
```

We can also verify that the password and salt match the checkpoint by passing the optional `--verify` flag:

> slowkey show-checkpoint --checkpoint ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0 --verify

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

Verifying the checkpoint...

The password, salt and internal data are correct
```

Let's continue the derivation process from this checkpoint and verify that we arrive at the same final result as before. Please make sure to specify the correct number of iterations, as the checkpoint does not store the original iteration count.

> slowkey restore-from-checkpoint -i 10 --checkpoint ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0

```sh

Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

Verifying the checkpoint...

The password, salt and internal data are correct

████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        5/10        0%    (4s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms
```

Final result:

```sh
████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Key is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-06 22:10:30
End time: 2024-12-06 22:11:09
Total running time: 39s
Average iteration time: 1s 993ms
```

In addition to the above, you can use a checkpoint while specifying a larger iteration count. For example, if you originally ran 10,000 iterations and want to continue from checkpoint 9,000, you can set a higher iteration count, such as 100,000, when restoring from this checkpoint:

> slowkey restore-from-checkpoint -i 20 --checkpoint ~/checkpoints/checkpoint.05.c33f06fe6bdaac774ab473181aa4fe46a3baadee4b8f4dc02be2248dea5308c0

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint:
  Version: 2:
  Iteration: 5:
  Data (please highlight to see): 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
  Previous Iteration's Data (please highlight to see): 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

SlowKey Parameters:
  Iterations: 20
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

Verifying the checkpoint...

The password, salt and internal data are correct

████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░        5/20        0%    (56s)
```

Final result:

```sh
████████████████████████████████████████████████████████████████████████████████       20/20      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Key is (please highlight to see): 0x9e1a4e794f9c4f62a753f12b8c6971629579822c326c7ffcfdb8605a6146f94b

Start time: 2024-12-06 22:10:30
End time: 2024-12-06 22:11:09
Total running time: 39s
Average iteration time: 1s 993ms
```

You can also provide checkpoint data in an interactive way by specifying the `--interactive` flag:

> slowkey restore-from-checkpoint -i 10 --interactive

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Please enter the checkpoint data manually:

Version: 2

Length: 32
Iteration: 5
Data: 0x7ce6792307959432459050b666260a72c7105d18e66c31cc59d3044fb827f482
Previous data: 0xf131df94fd3c0294685d19097f9c331bd41abafdcc972695cce89d0d21707ec2

Scrypt n: 1048576
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
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

Verifying the checkpoint...

The password, salt and internal data are correct

████████████████████████████████████████████████████████████████████████████████       10/10       100%    (0s)

Iteration time moving average (10): 2s 610ms, last iteration time: 2s 625ms

Key is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Start time: 2024-12-10 08:47:27
End time: 2024-12-10 08:47:40
Total running time: 13s
Average iteration time: 1s 305ms
```

### Outputs

By default, the tool outputs they key in a hexadecimal format, but the tool also supports both [Base64](https://en.wikipedia.org/wiki/Base64) and [Base58](https://en.wikipedia.org/wiki/Binary-to-text_encoding#Base58) formats optionally:

> slowkey derive -i 10 --base64 --base58

```sh
Please input all data either in raw or hex format starting with the 0x prefix

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Key is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a
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

✔ Enter your checkpoint/output encryption key · ********

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

████████████████████████████████████████████████████████████████████████████████       10/10      100%    (0s)

Iteration time moving average (10): 4s 425ms, last iteration time: 4s 322ms

Key is (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a

Saved encrypted output to "~/output.enc"

Start time: 2024-12-06 21:56:34
End time: 2024-12-06 21:57:01
Total running time: 27s
Average iteration time: 2s 717ms
```

Let's use the `show-output` command to decrypt its contents:

```sh
Decrypt and print an output file

Usage: slowkey show-output [OPTIONS] --output <OUTPUT>

Options:
      --output <OUTPUT>  Path to an existing output
      --verify           Verify that the password and salt match the output
      --base64           Show the result in Base64 (in addition to hex)
      --base58           Show the result in Base58 (in addition to hex)
  -h, --help             Print help
```

> slowkey show-output --output ~/output.enc

```sh
Output:
  Data (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a
  Previous Iteration's Data (please highlight to see): 0x1022becf0bd59c89fd6db6c9b0ccd0514c0022204521616a93d208bcdfa53e85

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)
```

The output file checkpoint, except for the one that coincides with the first iteration, also includes the output of the previous iteration. This allows the system to verify that the password and salt match the output by attempting to derive the output's data from the previous iteration's data. This verification is optional and requires the `--verify` flag:

> slowkey show-output --output ~/output.enc --verify

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Output:
  Data (please highlight to see): 0xda158bedf00e5abba900e0c027c249912e3ad5ce54304fdb54f1939ddb14232a
  Previous Iteration's Data (please highlight to see): 0x1022becf0bd59c89fd6db6c9b0ccd0514c0022204521616a93d208bcdfa53e85

SlowKey Parameters:
  Iterations: 10
  Length: 32
  Scrypt: (n: 1048576, r: 8, p: 1)
  Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
  Balloon Hash: (hash: SHA512, s_cost: 131072, t_cost: 1)

✔ Enter your salt · ********

Salt is: s...t

✔ Enter your password · ********

Password is: p...d

Verifying the output...

The password, salt and internal data are correct
```

## Run Benchmark

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
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (m_cost: 209...
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (m_cost: 209...: Warming up for 3.0000 s
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (m_cost: 209...: Collecting 10 samples in estimated 51.109 s (20 iterations)
Benchmarking Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (m_cost: 209...: Analyzing
Algorithms/SlowKey (Default)/iterations: 1, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (m_cost: 209...
                        time:   [2.5249 s 2.5369 s 2.5501 s]
                        change: [-1.1563% +0.0329% +1.1232%] (p = 0.95 > 0.05)
                        No change in performance detected.

Saved benchmark reports to: "~/benchmarks"
```

An HTML report will be generated in the `benchmarks` directory, but please make sure to install `gnuplot` beforehand.

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
