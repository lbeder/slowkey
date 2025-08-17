use crate::log;
use crate::utils::algorithms::{
    argon2id::{Argon2id, Argon2idOptions},
    balloon_hash::{BalloonHash, BalloonHashOptions},
    scrypt::{Scrypt, ScryptOptions},
};
use balloon_hash::password_hash::SaltString;
use criterion::{black_box, BenchmarkId, Criterion, SamplingMode};
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Keccak512};
use std::{path::Path, time::Duration};

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct SlowKeyOptions {
    pub iterations: usize,
    pub length: usize,
    pub scrypt: ScryptOptions,
    pub argon2id: Argon2idOptions,
    pub balloon_hash: BalloonHashOptions,
}

impl SlowKeyOptions {
    pub const MIN_ITERATIONS: usize = 1;
    pub const MAX_ITERATIONS: usize = u32::MAX as usize;

    pub const MIN_KEY_SIZE: usize = 9;
    pub const MAX_KEY_SIZE: usize = 64;
    pub const DEFAULT_OUTPUT_SIZE: usize = 32;

    #[inline]
    pub fn new(
        iterations: usize, length: usize, scrypt: &ScryptOptions, argon2id: &Argon2idOptions,
        balloon_hash: &BalloonHashOptions,
    ) -> Self {
        if iterations < Self::MIN_ITERATIONS {
            panic!(
                "iterations {} is lesser than the min value of {}",
                Self::MIN_ITERATIONS,
                length
            );
        }

        if length < Self::MIN_KEY_SIZE {
            panic!(
                "length {} is shorter than the min length of {}",
                Self::MIN_KEY_SIZE,
                length
            );
        }

        if length > Self::MAX_KEY_SIZE {
            panic!(
                "length {} is longer than the max length of {}",
                Self::MAX_KEY_SIZE,
                length
            );
        }

        Self {
            iterations,
            length,
            scrypt: *scrypt,
            argon2id: *argon2id,
            balloon_hash: *balloon_hash,
        }
    }

    pub fn print(&self) {
        log!(
            "{}:\n  {}: {}\n  {}: {}\n  {}: (log_n: {}, r: {}, p: {})\n  {}: (version: {}, m_cost: {}, t_cost: {})\n  {}: (hash: {}, s_cost: {}, t_cost: {})\n",
            "SlowKey Parameters".yellow(),
            "Iterations".green(),
            &self.iterations.to_string().cyan(),
            "Length".green(),
            &self.length.to_string().cyan(),
            "Scrypt".green(),
            &self.scrypt.log_n().to_string().cyan(),
            &self.scrypt.r().to_string().cyan(),
            &self.scrypt.p().to_string().cyan(),
            "Argon2id".green(),
            Argon2id::VERSION.to_string().cyan(),
            &self.argon2id.m_cost().to_string().cyan(),
            &self.argon2id.t_cost().to_string().cyan(),
            "Balloon Hash".green(),
            BalloonHash::HASH.cyan(),
            &self.balloon_hash.s_cost().to_string().cyan(),
            &self.balloon_hash.t_cost().to_string().cyan()
        );
    }
}

pub struct SlowKey<'a> {
    iterations: usize,
    length: usize,
    scrypt: Scrypt,
    argon2id: Argon2id,
    balloon_hash: BalloonHash<'a>,
}

impl SlowKey<'_> {
    pub const SALT_SIZE: usize = 16;
    pub const DEFAULT_SALT: [u8; SlowKey::SALT_SIZE] = [0; SlowKey::SALT_SIZE];

    #[inline]
    pub fn new(opts: &SlowKeyOptions) -> Self {
        if opts.iterations == 0 {
            panic!("Invalid iterations number");
        }

        Self {
            iterations: opts.iterations,
            length: opts.length,
            scrypt: Scrypt::new(opts.length, &opts.scrypt),
            argon2id: Argon2id::new(opts.length, &opts.argon2id),
            balloon_hash: BalloonHash::new(opts.length, &opts.balloon_hash),
        }
    }

    #[inline]
    pub fn derive_key_with_callback<F: FnMut(usize, &Vec<u8>)>(
        &self, salt: &[u8], password: &[u8], offset_data: &[u8], offset: usize, sanity: bool, mut callback: F,
    ) -> Vec<u8> {
        if salt.len() != Self::SALT_SIZE {
            panic!("Salt must be {} long", Self::SALT_SIZE);
        }

        // If this is the first iteration, calculate the SHA2 and SHA3 hashes of the result and the inputs. Otherwise,
        // continue from where it has stopped
        let mut res = match offset {
            0 => self.double_hash(salt, password, None, &Vec::new()),
            _ => offset_data.to_vec(),
        };

        let salt_string = SaltString::encode_b64(salt).unwrap();

        for i in offset..self.iterations {
            let iteration = i as u64;

            let mut scrypt_output = Vec::new();
            let mut argon2_output = Vec::new();
            let mut balloon_hash_output = Vec::new();

            if sanity {
                let mut scrypt_output2 = Vec::new();
                let mut argon2_output2 = Vec::new();
                let mut balloon_hash_output2 = Vec::new();

                // Run all KDF algorithms in parallel with an additional sanity check
                rayon::scope(|s| {
                    s.spawn(|_| scrypt_output = self.scrypt(salt, password, iteration, &res));
                    s.spawn(|_| argon2_output = self.argon2id(salt, password, iteration, &res));
                    s.spawn(|_| balloon_hash_output = self.balloon_hash(salt, &salt_string, password, iteration, &res));
                    s.spawn(|_| scrypt_output2 = self.scrypt(salt, password, iteration, &res));
                    s.spawn(|_| argon2_output2 = self.argon2id(salt, password, iteration, &res));
                    s.spawn(|_| {
                        balloon_hash_output2 = self.balloon_hash(salt, &salt_string, password, iteration, &res)
                    });
                });

                if scrypt_output != scrypt_output2 {
                    panic!("Sanity check has failed: different Scrypt outputs");
                }

                if argon2_output != argon2_output2 {
                    panic!("Sanity check has failed: different Argon2 outputs");
                }

                if balloon_hash_output != balloon_hash_output2 {
                    panic!("Sanity check has failed: different Balloon Hash outputs");
                }
            } else {
                // Run all KDF algorithms in parallel
                rayon::scope(|s| {
                    s.spawn(|_| scrypt_output = self.scrypt(salt, password, iteration, &res));
                    s.spawn(|_| argon2_output = self.argon2id(salt, password, iteration, &res));
                    s.spawn(|_| balloon_hash_output = self.balloon_hash(salt, &salt_string, password, iteration, &res));
                });
            }

            // Pre-allocate total capacity needed
            let total_len = scrypt_output.len()
                + argon2_output.len()
                + balloon_hash_output.len()
                + salt.len()
                + password.len()
                + std::mem::size_of::<u64>();
            res = Vec::with_capacity(total_len);

            // Concatenate all the results and the inputs
            res.extend_from_slice(&scrypt_output);
            res.extend_from_slice(&argon2_output);
            res.extend_from_slice(&balloon_hash_output);
            res.extend_from_slice(salt);
            res.extend_from_slice(password);
            res.extend_from_slice(&iteration.to_le_bytes());

            // Calculate the SHA2 and SHA3 hashes of the result and the inputs
            let hash_output = self.double_hash(salt, password, Some(iteration), &res);

            // Perform an additional optional sanity check
            if sanity && hash_output != self.double_hash(salt, password, Some(iteration), &res) {
                panic!("Sanity check has failed: different double hash outputs");
            }

            res = hash_output[0..self.length].to_vec();

            callback(i, &res);
        }

        res
    }

    #[inline]
    pub fn derive_key(&self, salt: &[u8], password: &[u8], offset_data: &[u8], offset: usize) -> Vec<u8> {
        self.derive_key_with_callback(salt, password, offset_data, offset, false, |_, _| {})
    }

    #[inline]
    fn double_hash(&self, salt: &[u8], password: &[u8], iteration: Option<u64>, input: &[u8]) -> Vec<u8> {
        let total_len = input.len() + salt.len() + password.len() + iteration.map_or(0, |_| std::mem::size_of::<u64>());
        let mut res = Vec::with_capacity(total_len);
        res.extend_from_slice(input);
        res.extend_from_slice(salt);
        res.extend_from_slice(password);

        if let Some(iteration) = iteration {
            res.extend_from_slice(&iteration.to_le_bytes());
        }

        let mut sha512 = Sha512::new();
        sha512.update(&res);
        let sha_result = sha512.finalize();

        let total_len =
            sha_result.len() + salt.len() + password.len() + iteration.map_or(0, |_| std::mem::size_of::<u64>());
        res = Vec::with_capacity(total_len);
        res.extend_from_slice(&sha_result);
        res.extend_from_slice(salt);
        res.extend_from_slice(password);

        if let Some(iteration) = iteration {
            res.extend_from_slice(&iteration.to_le_bytes());
        }

        let mut keccack512 = Keccak512::new();
        keccack512.update(&res);
        keccack512.finalize().to_vec()
    }

    #[inline]
    fn scrypt(&self, salt: &[u8], password: &[u8], iteration: u64, input: &[u8]) -> Vec<u8> {
        let total_len = input.len() + salt.len() + password.len() + std::mem::size_of::<u64>();
        let mut res = Vec::with_capacity(total_len);
        res.extend_from_slice(input);
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        self.scrypt.hash(salt, &res)
    }

    #[inline]
    fn argon2id(&self, salt: &[u8], password: &[u8], iteration: u64, input: &[u8]) -> Vec<u8> {
        let total_len = input.len() + salt.len() + password.len() + std::mem::size_of::<u64>();
        let mut res = Vec::with_capacity(total_len);
        res.extend_from_slice(input);
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        self.argon2id.hash(salt, &res)
    }

    #[inline]
    fn balloon_hash(
        &self, salt: &[u8], salt_string: &SaltString, password: &[u8], iteration: u64, input: &[u8],
    ) -> Vec<u8> {
        let total_len = input.len() + salt.len() + password.len() + std::mem::size_of::<u64>();
        let mut res = Vec::with_capacity(total_len);
        res.extend_from_slice(input);
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        self.balloon_hash.hash(salt_string, &res)
    }

    pub fn benchmark(output_path: &Path) {
        let mut c = Criterion::default().output_directory(output_path);

        // Just some random data
        let input: [u8; 32] = [
            0x8a, 0x40, 0xd0, 0xce, 0x8b, 0x69, 0x8c, 0x6b, 0xc5, 0xc3, 0xb5, 0x29, 0x80, 0xca, 0x29, 0x99, 0x91, 0xfb,
            0xc5, 0x37, 0x98, 0xbd, 0x2e, 0x71, 0x10, 0x79, 0x8e, 0xef, 0x71, 0x04, 0xa4, 0x6c,
        ];

        c.bench_with_input(BenchmarkId::new("SHA2", 1), &input, |b, data| {
            b.iter(|| {
                let mut hasher = Sha512::new();
                hasher.update(black_box(data));
                let _result = hasher.finalize();
            });
        });

        c.bench_with_input(BenchmarkId::new("SHA3", 1), &input, |b, data| {
            b.iter(|| {
                let mut hasher = Keccak512::new();
                hasher.update(black_box(data));
                let _result = hasher.finalize();
            });
        });

        let salt = [0u8; 32];
        let salt_string = SaltString::encode_b64(&salt).unwrap();

        let mut group = c.benchmark_group("Algorithms");
        group
            .sample_size(10)
            .measurement_time(Duration::from_secs(30))
            .sampling_mode(SamplingMode::Flat);

        let options = ScryptOptions::default();
        group.bench_with_input(
            BenchmarkId::new(
                "Scrypt (Default)",
                format!("n: {}, r: {}, p: {}", options.n(), options.r(), options.p()),
            ),
            &input,
            |b, data| {
                b.iter(|| {
                    let _result = Scrypt::new(32, &options).hash(black_box(&salt), black_box(data));
                });
            },
        );

        let options = Argon2idOptions::default();
        group.bench_with_input(
            BenchmarkId::new(
                "Argon2id (Default)",
                format!("m_cost: {}, t_cost: {}", options.m_cost(), options.t_cost()),
            ),
            &input,
            |b, data| {
                b.iter(|| {
                    let _result = Argon2id::new(32, &options).hash(black_box(&salt), black_box(data));
                });
            },
        );

        let options = BalloonHashOptions::default();
        group.bench_with_input(
            BenchmarkId::new(
                "Balloon Hash (Default)",
                format!("s_cost: {}, t_cost: {}", options.s_cost(), options.t_cost()),
            ),
            &input,
            |b, data| {
                b.iter(|| {
                    let _result = BalloonHash::new(32, &options).hash(black_box(&salt_string), black_box(data));
                });
            },
        );

        let options = SlowKeyOptions {
            iterations: 1,
            length: SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            scrypt: ScryptOptions::default(),
            argon2id: Argon2idOptions::default(),
            balloon_hash: BalloonHashOptions::default(),
        };
        group.bench_with_input(
            BenchmarkId::new(
                "SlowKey (Default)",
                format!(
                    "iterations: {}, Scrypt: (log_n: {}, r: {}, p: {}), Argon2id: (m_cost: {}, t_cost: {}), BalloonHash: (s_cost: {}, t_cost: {})",
                    options.iterations,
                    options.scrypt.log_n(),
                    options.scrypt.r(),
                    options.scrypt.p(),
                    options.argon2id.m_cost(),
                    options.argon2id.t_cost(),
                    options.balloon_hash.s_cost(),
                    options.balloon_hash.t_cost()
                ),
            ),
            &input,
            |b, data| {
                b.iter(|| {
                    let _result = SlowKey::new(&options).derive_key(black_box(&[0u8; 16]), black_box(data), &[], 0);
                });
            },
        );

        group.finish();

        c.final_summary();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::sodium_init::initialize;
    use rstest::rstest;

    #[rstest]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "2d819b3d8903a8037630d2a92f88f200fef9d847cd98c958e076526ce7766645aa8f7a2f7177f739c8b117ec23a51d3eaede566c3b3c46af700932bf7182c647")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::new(12, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "7c586b43929ed4aa3d9bc98fc0de795df6240e3a7a356c67934c5e2d0557fe08")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::new(1 << 4, 2),
        balloon_hash: BalloonHashOptions::new(1 << 5, 3),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "d1817a0f0ae560729c7ef40c56ddd186351552f437d1431e9db68395c5aca69d")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(20, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "e222eb8b3fb65e4b79d9c46b49cfbade3d105822cd5c5546e51d2d47e70f49e579a9d3cbdab23d3f211c78ddc11da48843a7b433b736fc6b18cfa98dbd6aa28c")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(15, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"", &Vec::new(), 0,
    "5b9c7f850cc65a18d8a327cacc57a8dc2279ff722461e5e4de14e0b49a6975d563a04363876095955e07db22a5b769f6bf1ed6849ea07138a04b9302b19963b3")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(15, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "c8219c24a42cb713771ce19bb07c687875a99839965628c2ad4e4ba2bee66f4183b1a8f91f1da808cac74a5a5bd8c12c934a5f457513154978d6ca3d13d66d62")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(15, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsal2", b"test", &Vec::new(), 0,
    "eab33d73bcf48337d42605da85cd0cfc0c30e384d905d9634cbf1551530352c67209d656513039fab9de47f99a80a11471c9fd89490b676592b6fcca0eeba847")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(15, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test2", &Vec::new(), 0,
    "19987e685650347eb7229dbd339d57a88bb18bb901aae8c97441ac43ce17c17a888e593ead9690528235081b16764fbaaab6aa1e467199d37f9ea97886293905")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::new(12, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 1,
    "df88794d493027643559641176ee44acdd263a56e9144c3724926f350179ca95")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(15, 8, 1),
        argon2id: Argon2idOptions::default(),
        balloon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "881460654568cc80a8b53de0d49aa3fd665cc27c830b751d7738d14f3e2baf246171d591e8e1b20ca7e5d01dc04d65148f8b2c65505cfb03c114044e2946fde0")]

    fn derive_test(
        #[case] options: &SlowKeyOptions, #[case] salt: &[u8], #[case] password: &[u8], #[case] offset_data: &[u8],
        #[case] offset: usize, #[case] expected: &str,
    ) {
        initialize();

        let kdf = SlowKey::new(options);
        let key = kdf.derive_key(salt, password, offset_data, offset);
        assert_eq!(hex::encode(key), expected);
    }
}
