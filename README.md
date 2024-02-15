# slowkey

[![Build Status](https://github.com/lbeder/slowkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lbeder/slowkey/actions/workflows/ci.yml)

## SlowKey: Advanced Key Derivation Tool Using Scrypt, Argon2id, SHA2, and SHA3

SlowKey is a cutting-edge [Key Derivation Function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF) tool designed to enhance cryptographic security in various applications, from securing sensitive data to protecting user passwords. At its core, SlowKey leverages the power of three renowned cryptographic algorithms: [Scrypt](https://en.wikipedia.org/wiki/Scrypt), [Argon2](https://en.wikipedia.org/wiki/Argon2), [SHA2](https://en.wikipedia.org/wiki/SHA-2), and [SHA3](https://en.wikipedia.org/wiki/SHA-3), each selected for its unique strengths in ensuring data integrity and security.

SlowKey incorporates Scrypt, a memory-hard KDF that is specifically engineered to make brute-force attacks prohibitively expensive. By requiring significant amounts of memory and processing power to compute the hash functions, Scrypt ensures that the cost and time to perform large-scale custom hardware attacks are beyond the reach of most attackers, offering robust protection against rainbow table and brute-force attacks.

SlowKey integrates Argon2, an advanced, memory-hard Key Derivation Function (KDF) designed to effectively thwart brute-force and side-channel attacks. As the winner of the Password Hashing Competition, Argon2 is tailored to ensure that the computation of hash functions demands substantial memory and processing resources, making it exceedingly difficult for attackers to mount large-scale custom hardware attacks. This requirement for significant computational effort not only increases the security against brute-force and rainbow table attacks but also provides a customizable framework that can be tuned for specific defense needs, ensuring an adaptable and formidable barrier against unauthorized access attempts.

Alongside Scrypt, and Argon2, SlowKey utilizes SHA2 and SHA3 for their exceptional hash functions, providing an additional layer of security. SHA2, a member of the Secure Hash Algorithm family, offers a high level of resistance against hash collision attacks, making it an excellent choice for secure hashing needs. SHA3, the latest member of the Secure Hash Algorithm family, further strengthens SlowKey's cryptographic capabilities with its resistance to various attack vectors, including those that may affect earlier SHA versions.

A cornerstone of SlowKey's design philosophy is its commitment to resilience through diversity. By integrating Scrypt, SHA2, and SHA3 within its cryptographic framework, SlowKey not only capitalizes on the unique strengths of each algorithm but also ensures a level of security redundancy that is critical in the face of evolving cyber threats. This strategic mixture means that even if one of these algorithms were to be compromised or "broken" due to unforeseen vulnerabilities, the overall security scheme of SlowKey would remain robust and intact, safeguarded by the uncompromised integrity of the remaining algorithms. This approach mirrors the principle of layered security in cybersecurity, where multiple defensive strategies are employed to protect against a single point of failure. Consequently, SlowKey offers an advanced, forward-thinking solution that anticipates and mitigates the potential impact of future cryptographic breakthroughs or advancements in quantum computing that could threaten individual hash functions. Through this multi-algorithm strategy, SlowKey provides a safeguard against the entire spectrum of cryptographic attacks, ensuring long-term security for its users in a landscape where the only constant is change.

## Usage

### General

```sh
Usage: slowkey [COMMAND]

Commands:
  derive  Derive a key using using Scrypt, Argon2, SHA2, and SHA3
  test    Print test vectors

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Deriving

```sh
Derive a key using using Scrypt, Argon2, SHA2, and SHA3

Usage: slowkey derive [OPTIONS]

Options:
  -i, --iterations <ITERATIONS>        Number of iterations (must be greater than 0 and lesser than or equal to 4294967295) [default: 100]
  -l, --length <LENGTH>                Length of the derived result (must be greater than 10 and lesser than or equal to 128) [default: 16]
      --scrypt-n <SCRYPT_N>            Scrypt CPU/memory cost parameter (must be lesser than 18446744073709551615) [default: 1048576]
      --scrypt-r <SCRYPT_R>            Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and lesser than or equal to 4294967295) [default: 8]
      --scrypt-p <SCRYPT_P>            Scrypt parallelization parameter (must be greater than 0 and lesser than 4294967295) [default: 1]
      --argon2-m-cost <ARGON2_M_COST>  Argon2 number of 1 KiB memory block (must be greater than 8 and lesser than 4294967295) [default: 2097152]
      --argon2-t-cost <ARGON2_T_COST>  Argon2 number of iterations (must be greater than 2 and lesser than 4294967295) [default: 2]
      --offset <OFFSET>                Start the derivation from this offset. In order to use it, you also have to specify the intermediary offset data in hex format [default: 0]
      --offset-data <OFFSET_DATA>      Start the derivation with this intermediary data in hex format
      --base64                         Output the result in Base64 (in addition to hex)
      --base58                         Output the result in Base58 (in addition to hex)
  -h, --help                           Print help
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

### For Windows

In order to get stuff working later, use the `nightly` branch of Rust:

```sh
rustup override set nightly
```

Install the standard Windows target on a Mac (note, that the opposite is currently impossible):

```sh
rustup target add x86_64-pc-windows-gnu
```

Use `homebrew` to install mingw-w64:

```sh
brew install mingw-w64
```

Now you can build it:

```sh
cargo build --release --target=x86_64-pc-windows-gnu
```

## Examples

Let's try to derive the key for the password `secret`, using the salt `saltsaltsaltsalt`:

> slowkey derive

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

Enter your salt (must be 16 characters/bytes long in either raw or hex format starting with 0x): saltsaltsaltsalt
Enter your password (in either raw or hex format starting with 0x): 🔑
Enter your password again: 🔑

Processing: 12 / 100 [==============>--------------------------------------------------------------------------------------------------------------] 12.00 % 9m
```

Final result:

```sh
Enter your salt (must be 16 characters/bytes long in either raw or hex format starting with 0x): saltsaltsaltsalt
Enter your password (in either raw or hex format starting with 0x): 🔑
Enter your password again: 🔑

Processing: 100 / 100 [=======================================================================================================================================] 100.00 %

Key (hex) is (please highlight to see): dc4228e2b23375b3560166d8c822400b

Finished in 8m 9s
```

### Resuming Previous Derivation

To help with resuming previously stopped derivations, we're registering a `CTRL_C`, `CTRL_BREAK`, `SIGINT`, `SIGTERM`, and `SIGHUP` termination handler which will output the intermediary result (if possible).

For example, if we will abort the previous derivation after the `10th` iteration, the tool will output:

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

Enter your salt (must be 16 characters/bytes long in either raw or hex format starting with 0x): saltsaltsaltsalt
Enter your password (in either raw or hex format starting with 0x): 🔑
Enter your password again: 🔑

Processing: 10 / 100 [==========================================================================>-------------------------------------------------] 10.00 % 7m

Terminated. To resume, please specify --offset 10 and --offset-data (please highlight to see) 9d3088829bb0d2049488215d2c96f62c
```

You can then use this output to resume the previous derivation by specifying a starting offset and data like so:

> slowkey derive --offset 10 --offset-data 9d3088829bb0d2049488215d2c96f62c

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2)

Enter your salt (must be 16 characters/bytes long in either raw or hex format starting with 0x): saltsaltsaltsalt

Resuming from iteration 10 with intermediary offset data 9d3088829bb0d2049488215d2c96f62c

Processing: 90 / 90 [===============================================================================================================================] 100.00 % 8m

Key (hex) is (please highlight to see): dc4228e2b23375b3560166d8c822400b

Finished in 4m 15s
```

## Test Vectors

In order to verify the validity of the Scrypt calculation, you can pass the `-t/--test` flag.

Test vectors:

### #1

* Password: "" (the empty string)
* Salt: "SlowKeySlowKey16"
* Iterations: 1
* Length: 64
* Scrypt Parameters:
  * n: 1048576
  * r: 8
  * p: 1
* Argon2id Parameters:
  * m_cost: 2097152
  * t_cost: 2

### #2

* Password: "Hello World"
* Salt: "SlowKeySlowKey16"
* Iterations: 3
* Length: 64
* Scrypt Parameters:
  * n: 1048576
  * r: 8
  * p: 1
* Argon2id Parameters:
  * m_cost: 2097152
  * t_cost: 2

Results should be:

```sh
SSlowKey: iterations: 1, length: 64, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2), salt: "SlowKeySlowKey16", password: ""
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
