# SlowKey: Advanced Key Derivation Tool Using Scrypt, Argon2id, SHA2, and SHA3

[![Build Status](https://github.com/lbeder/slowkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lbeder/slowkey/actions/workflows/ci.yml)

## Introduction

SlowKey is a cutting-edge [Key Derivation Function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF) tool designed to enhance cryptographic security in various applications, from securing sensitive data to protecting user passwords. At its core, SlowKey leverages the power of three renowned cryptographic algorithms: [Scrypt](https://en.wikipedia.org/wiki/Scrypt), [Argon2](https://en.wikipedia.org/wiki/Argon2), [SHA2](https://en.wikipedia.org/wiki/SHA-2), and [SHA3](https://en.wikipedia.org/wiki/SHA-3), each selected for its unique strengths in ensuring data integrity and security.

SlowKey incorporates Scrypt, a memory-hard KDF that is specifically engineered to make brute-force attacks prohibitively expensive. By requiring significant amounts of memory and processing power to compute the hash functions, Scrypt ensures that the cost and time to perform large-scale custom hardware attacks are beyond the reach of most attackers, offering robust protection against rainbow table and brute-force attacks.

SlowKey integrates Argon2, an advanced, memory-hard Key Derivation Function (KDF) designed to effectively thwart brute-force and side-channel attacks. As the winner of the Password Hashing Competition, Argon2 is tailored to ensure that the computation of hash functions demands substantial memory and processing resources, making it exceedingly difficult for attackers to mount large-scale custom hardware attacks. This requirement for significant computational effort not only increases the security against brute-force and rainbow table attacks but also provides a customizable framework that can be tuned for specific defense needs, ensuring an adaptable and formidable barrier against unauthorized access attempts.

Alongside Scrypt, and Argon2, SlowKey utilizes SHA2 and SHA3 for their exceptional hash functions, providing an additional layer of security. SHA2, a member of the Secure Hash Algorithm family, offers a high level of resistance against hash collision attacks, making it an excellent choice for secure hashing needs. SHA3, the latest member of the Secure Hash Algorithm family, further strengthens SlowKey's cryptographic capabilities with its resistance to various attack vectors, including those that may affect earlier SHA versions.

A cornerstone of SlowKey's design philosophy is its commitment to resilience through diversity. By integrating Scrypt, SHA2, and SHA3 within its cryptographic framework, SlowKey not only capitalizes on the unique strengths of each algorithm but also ensures a level of security redundancy that is critical in the face of evolving cyber threats. This strategic mixture means that even if one of these algorithms were to be compromised or "broken" due to unforeseen vulnerabilities, the overall security scheme of SlowKey would remain robust and intact, safeguarded by the uncompromised integrity of the remaining algorithms. This approach mirrors the principle of layered security in cybersecurity, where multiple defensive strategies are employed to protect against a single point of failure. Consequently, SlowKey offers an advanced, forward-thinking solution that anticipates and mitigates the potential impact of future cryptographic breakthroughs or advancements in quantum computing that could threaten individual hash functions. Through this multi-algorithm strategy, SlowKey provides a safeguard against the entire spectrum of cryptographic attacks, ensuring long-term security for its users in a landscape where the only constant is change.

## SlowKey Key Derivation Scheme

The SlowKey Key Derivation Scheme is defined as follows:

### Definitions

- `Concatenate(data1, data2, data3)`: Function to concatenate `data1`, `data2`, and `data3`.
- `SHA2(data)`: Function to compute SHA2 (SHA512) hash of `data`.
- `SHA3(data)`: Function to compute SHA3 (Keccak512) hash of `data`.
- `Scrypt(data, salt)`: Function to derive a key using Scrypt KDF with `data` and `salt`.
- `Argon2id(data, salt)`: Function to derive a key using Argon2id KDF with `data` and `salt`.

### Inputs

- `password`: User's password.
- `salt`: Unique salt for hashing. Please note that the salt must be `16` bytes long, therefore shorter salts will be padded with 0s, while longer salts will be first SHA512 hashed and then truncated to `16` bytes.
- `iterations`: Number of iterations the process should be repeated.

### Output

- `finalKey`: Derived key after all iterations.

### Scheme

```pseudo
function deriveKey(password, salt, iterations):
    previousResult = ""

    for i from 1 to iterations:
        step1 = SHA2(concatenate(previousResult, salt, password))
        step2 = SHA3(concatenate(step1, salt, password))
        step3 = Scrypt(step2, salt)
        step4 = SHA2(concatenate(step3, salt, password))
        step5 = SHA3(concatenate(step4, salt, password))
        step6 = Argon2id(step5, salt)
        previousResult = step6

    finalStep1 = SHA2(concatenate(previousResult, salt, password))
    finalStep2 = SHA3(concatenate(finalStep1, salt, password))
    finalKey = finalStep2

    return finalKey
```

## Usage

### General

```sh
Usage: slowkey [COMMAND]

Commands:
  derive           Derive a key using using Scrypt, Argon2, SHA2, and SHA3
  show-checkpoint  Decrypt a checkpoint
  show-output      Decrypt an output file
  test             Print test vectors

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Deriving

```sh
Derive a key using using Scrypt, Argon2, SHA2, and SHA3

Usage: slowkey derive [OPTIONS]

Options:
  -i, --iterations <ITERATIONS>
          Number of iterations (must be greater than 1 and lesser than or equal to 4294967295) [default: 100]
  -l, --length <LENGTH>
          Length of the derived result (must be greater than 10 and lesser than or equal to 128) [default: 16]
      --base64
          Output the result in Base64 (in addition to hex)
      --base58
          Output the result in Base58 (in addition to hex)
      --output <OUTPUT>
          Optional path for storing the encrypted output
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
      --checkpoint-dir <CHECKPOINT_DIR>
          Optional directory for storing encrypted checkpoints, each appended with an iteration-specific suffix. For each iteration i, the corresponding checkpoint file is named "checkpoint.i", indicating the iteration number at which the checkpoint was created
      --checkpoint-interval <CHECKPOINT_INTERVAL>
          Frequency of saving encrypted checkpoints to disk, specified as the number of iterations between each save. This argument is only required if --checkpoint-interval is provided [default: 0]
      --restore-from-checkpoint <RESTORE_FROM_CHECKPOINT>
          Path to an existing checkpoint from which to resume the derivation process
      --max-checkpoints-to-keep <MAX_CHECKPOINTS_TO_KEEP>
          Specifies the number of most recent checkpoints to keep, while automatically deleting older ones [default: 1]
  -h, --help
          Print help
```

### Printing Test Vectors

```sh
Print test vectors

Usage: slowkey test

Options:
  -h, --help  Print help
```

## Build

### Mac OS

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

### Linux x86_x64

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

Let's try to derive the key for the password `password`, using the salt `saltsaltsaltsalt`:

> slowkey derive

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your salt · saltsaltsaltsalt

✔ Enter your password · ********

███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░       9/100     9%    (8m)
```

Final result:

```sh
✔ Enter your salt · saltsaltsaltsalt

✔ Enter your password · ********

████████████████████████████████████████████████████████████████████████████████       1/1       100%    (0s)

Key (hex) is (please highlight to see): fd194763d687d50dafa952eec758df13

Finished in 8m 9s
```

Please note that salt must be `16` bytes long, therefore shorter salts will be padded with 0s, while longer salts will be first SHA512 hashed and then truncated to `16` bytes:

```sh
✔ Enter your salt · salt

Salt is shorter than 16 and will padded with 0s. Do you want to continue? [y/n]
```

```sh
✔ Enter your salt · saltsaltsaltsaltsalt

Salt is longer than 16 and will first SHA512 hashed and then truncated to 16 bytes. Do you want to continue? [y/n]
```

### Checkpoints

The tool also supports the creation of periodic checkpoints, which are securely encrypted and stored on the disk. Each checkpoint captures all parameters and the output from the last iteration, enabling you to resume computation from a previously established checkpoint. Additionally, the tool allows for the retention of multiple checkpoints.

Please exercise caution when using this feature. Resuming computation from a compromised checkpoint may undermine your expectations regarding the duration of the key stretching process.

Please note that encryption key must be `32` bytes long, therefore shorter keys will be padded with 0s, while longer keys will be first SHA512 hashed and then truncated to `32` bytes:

For instance, to elaborate on the previous example, suppose we want to create a checkpoint every `5` iterations forcefully terminate the execution at the `22nd` iteration:

> slowkey derive --checkpoint-interval 5 --checkpoint-dir ~/checkpoints

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint will be created every 5 iterations and saved to the "~/checkpoints" checkpoints directory

✔ Enter your salt · saltsaltsaltsalt

✔ Enter your password · ********

SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

█████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      22/100     22%    (8m)

Created checkpoint #20 with data hash (salted) b4c0a8ef28897913854364bc80ab0676edb5e95384918c48700f1b5a57ac2c2c
```

We can see that the last `checkpoint.020.b4c0a8ef28897913854364bc80ab0676edb5e95384918c48700f1b5a57ac2c2c` was retained in the `~/checkpoints` directory. Please note that file name contains iteration the checkpoint was taken at and a salted hash of the data.

Let's use the `show-checkpoint` command to decrypt its contents and verify the parameters:

> slowkey show-checkpoint --checkpoint ~/checkpoint.020.b4c0a8ef28897913854364bc80ab0676edb5e95384918c48700f1b5a57ac2c2c

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint: iteration: 20, data (please highlight to see): 9edb1ad22baf39c9d7865e181caf7852
SlowKey Parameters: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
```

Let's now continue the derivation process from this checkpoint and verify that we get the same final result as in the beginning:

> slowkey derive --restore-from-checkpoint ~/checkpoint.020.b4c0a8ef28897913854364bc80ab0676edb5e95384918c48700f1b5a57ac2c2c

```sh

Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

Checkpoint: iteration: 20, data (please highlight to see): 9edb1ad22baf39c9d7865e181caf7852

✔ Enter your salt · saltsaltsaltsalt

✔ Enter your password · ********

SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      20/100     20%    (15s)
```

Final result:

```sh
████████████████████████████████████████████████████████████████████████████████     100/100     100%    (0s)

Key (hex) is (please highlight to see): fd194763d687d50dafa952eec758df13

Finished in 6m 33s
```

### Outputs

By default, the tool outputs they key in a hexadecimal format, but the tool also supports both [Base64](https://en.wikipedia.org/wiki/Base64) and [Base58](https://en.wikipedia.org/wiki/Binary-to-text_encoding#Base58) formats optionally:

> slowkey derive --base64 --base58

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your salt · saltsaltsaltsalt

✔ Enter your password · ********

███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░       9/100     9%    (8m)

Key (hex) is (please highlight to see): fd194763d687d50dafa952eec758df13
Key (base64) is (please highlight to see): /RlHY9aH1Q2vqVLux1jfEw==
Key (base58) is (please highlight to see): YFiVHD3GYGPDVvSvmstsMk

Finished in 8m 8s
```

In addition to the above, the tool also supports saving the output to be encrypted and stored to the disk:

> slowkey derive --output ~/output.enc

```sh
Please input all data either in raw or hex format starting with the 0x prefix

✔ Enter your checkpoint/output encryption key · ********

✔ Enter your salt · saltsaltsaltsalt

✔ Enter your password · ********

SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

████████████████████████████████████████████████████████████████████████████████     100/100     100%    (0s)

Key (hex) is (please highlight to see): fd194763d687d50dafa952eec758df13

Saved encrypted output to "~/output.enc"

Finished in 8m 51s
```

Let's use the `show-output` command to decrypt its contents:

> slowkey show-output --output ~/output.enc

```sh
Output: iteration: 16, data (please highlight to see): fd194763d687d50dafa952eec758df13
SlowKey Parameters: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)
```

## Test Vectors

In order to verify the validity of the Scrypt calculation, you can pass the `-t/--test` flag.

Test vectors:

### #1

- Password: "" (the empty string)
- Salt: "SlowKeySlowKey16"
- Iterations: 1
- Length: 64
- Scrypt Parameters:
  - n: 1048576
  - r: 8
  - p: 1
- Argon2id Parameters:
  - version: 19
  - m_cost: 2097152
  - t_cost: 2

### #2

- Password: "Hello World"
- Salt: "SlowKeySlowKey16"
- Iterations: 3
- Length: 64
- Scrypt Parameters:
  - n: 1048576
  - r: 8
  - p: 1
- Argon2id Parameters:
  - version: 19
  - m_cost: 2097152
  - t_cost: 2

Results should be:

```sh
SlowKey: iterations: 1, length: 64, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2), salt: "SlowKeySlowKey16", password: ""
Derived key: 93e1459001ad83e3b39133cfba4ced8ce69f68e58553b093114abeee4174118b87d87d1b3d2c67d2d3ea5ca050b83ab49346eb9583e5fb31cc8f51f8d3343bf1

SlowKey: iterations: 3, length: 64, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2), salt: "SlowKeySlowKey16", password: "Hello World"
Derived key: 746f3a93557814a0e496a13af627a25954f3f15e129471b8eec713958ed12a273b932d02ba4f218edacb7d8a4b9bd4e6368004531f77e1981393f127c7f3ab64
```

## License

MIT License

Copyright (c) 2018 Leonid Beder

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
