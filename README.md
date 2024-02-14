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
  -l, --length <LENGTH>                Length of the derived result (must be greater than 10 and lesser than or equal to 64) [default: 16]
      --scrypt-n <SCRYPT_N>            Scrypt CPU/memory cost parameter (must be lesser than 18446744073709551615) [default: 1048576]
      --scrypt-r <SCRYPT_R>            Scrypt block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and lesser than or equal to 4294967295) [default: 8]
      --scrypt-p <SCRYPT_P>            Scrypt parallelization parameter (must be greater than 0 and lesser than 4294967295) [default: 1]
      --argon2-m-cost <ARGON2_M_COST>  Argon2 number of 1 KiB memory block (must be greater than 8 and lesser than 4294967295) [default: 2097152]
      --argon2-t-cost <ARGON2_T_COST>  Argon2 number of iterations (must be greater than 2 and lesser than 4294967295) [default: 2]
      --argon2-p-cost <ARGON2_P_COST>  Argon2 number of threads (must be greater than 1 and lesser than 16777215) [default: 4]
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

Let's try to derive the key for the secret `secret`, using the salt `saltsalt`:

> slowkey derive

XXX

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2, p_cost: 4)

Enter your salt: saltsalt
Enter your secret: 🔑
Enter your secret again: 🔑

Processing: 12 / 100 [==============>--------------------------------------------------------------------------------------------------------------] 12.00 % 3m
```

Final result:

```sh
Enter your salt: saltsalt
Enter your secret: 🔑
Enter your secret again: 🔑

Processing: 100 / 100 [=======================================================================================================================================] 100.00 %

Key (hex) is (please highlight to see): 176de269e7ff4c4624c4108e896930cb

Finished in 4m 42s
```

### Resuming Previous Derivation

To help with resuming previously stopped derivations, we're registering a `CTRL_C`, `CTRL_BREAK`, `SIGINT`, `SIGTERM`, and `SIGHUP` termination handler which will output the intermediary result (if possible).

For example, if we will abort the previous derivation after the `10th` iteration, the tool will output:

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2, p_cost: 4)

Enter your salt: saltsalt
Enter your secret: 🔑
Enter your secret again: 🔑

Processing: 10 / 100 [==========================================================================>-------------------------------------------------] 10.00 % 4m

Terminated. To resume, please specify --offset 10 and --offset-data (please highlight to see) f4565d04caa3e3bfc8d6ddb06b4f0d99
```

You can then use this output to resume the previous derivation by specifying a starting offset and data like so:

> slowkey derive --offset 10 --offset-data f4565d04caa3e3bfc8d6ddb06b4f0d99

```sh
SlowKey: iterations: 100, length: 16, Scrypt: (log_n: 20, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2, p_cost: 4)

Enter your salt: saltsalt

Resuming from iteration 10 with intermediary offset data f4565d04caa3e3bfc8d6ddb06b4f0d99

Processing: 90 / 90 [===============================================================================================================================] 100.00 % 4m

Key (hex) is (please highlight to see): 176de269e7ff4c4624c4108e896930cb

Finished in 4m 15s
```

## Test Vectors

In order to verify the validity of the Scrypt calculation, you can pass the `-t/--test` flag.

Test vectors:

### #1

* Secret: "" (the empty string)
* Salt: "SlowKeySalt"
* Iterations: 1
* Length: 64
* Scrypt Parameters:
  * n: 1048576
  * r: 8
  * p: 1
* Argon2id Parameters:
  * m_cost: 2097152
  * t_cost: 2
  * p_cost: 4

### #2

* Secret: "Hello World"
* Salt: "SlowKeySalt"
* Iterations: 3
* Length: 64
* Scrypt Parameters:
  * n: 1048576
  * r: 8
  * p: 1
* Argon2id Parameters:
  * m_cost: 2097152
  * t_cost: 2
  * p_cost: 4

Results should be:

```sh
SlowKey: iterations: 1, length: 64, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2, p_cost: 4), salt: "SlowKeySalt", secret: ""
Derived key: 91e119bd892f0a6b4bc5adf23693db6409a8d053a5b6a451d0ab340a5e01cb6b6a04d31eb6d78e7dc89809869d59a24ea88aae9f9fa7aa0630040a2c02f0b1d1

SlowKey: iterations: 3, length: 64, Scrypt: (n: 1048576, r: 8, p: 1), Argon2id: (version: 19, m_cost: 2097152, t_cost: 2, p_cost: 4), salt: "SlowKeySalt", secret: "Hello World"
Derived key: 78acc4cf9c4597b4312454fa6e78134f9e0308f79a07e97e457207d0919374c6d3d31b78c523fba364156da4df930b87596a42a1b1991cec5af708762b9e2e95
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
