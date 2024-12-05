use crate::utils::{
    argon2id::{Argon2id, Argon2idOptions},
    scrypt::{Scrypt, ScryptOptions},
};
use criterion::{black_box, BenchmarkId, Criterion};
use crossterm::style::Stylize;
use rayon::join;
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
}

impl SlowKeyOptions {
    pub const MIN_ITERATIONS: usize = 1;
    pub const MAX_ITERATIONS: usize = u32::MAX as usize;
    pub const DEFAULT_ITERATIONS: usize = 100;

    pub const MIN_KEY_SIZE: usize = 9;
    pub const MAX_KEY_SIZE: usize = 64;
    pub const DEFAULT_KEY_SIZE: usize = 32;

    pub fn new(iterations: usize, length: usize, scrypt: &ScryptOptions, argon2id: &Argon2idOptions) -> Self {
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
        }
    }

    pub fn print(&self) {
        println!(
            "{}:\n  {}: {}\n  {}: {}\n  {}: (n: {}, r: {}, p: {})\n  {}: (version: {}, m_cost: {}, t_cost: {})\n",
            "SlowKey Parameters".yellow(),
            "Iterations".green(),
            &self.iterations.to_string().cyan(),
            "Length".green(),
            &self.length.to_string().cyan(),
            "Scrypt".green(),
            &self.scrypt.n.to_string().cyan(),
            &self.scrypt.r.to_string().cyan(),
            &self.scrypt.p.to_string().cyan(),
            "Argon2id".green(),
            Argon2id::VERSION.to_string().cyan(),
            &self.argon2id.m_cost.to_string().cyan(),
            &self.argon2id.t_cost.to_string().cyan()
        );
    }
}

impl Default for SlowKeyOptions {
    fn default() -> Self {
        Self {
            iterations: Self::DEFAULT_ITERATIONS,
            length: Self::DEFAULT_KEY_SIZE,
            scrypt: ScryptOptions::default(),
            argon2id: Argon2idOptions::default(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct TestSlowKeyOptions {
    pub opts: SlowKeyOptions,
    pub salt: Vec<u8>,
    pub password: Vec<u8>,
    pub offset_data: Vec<u8>,
    pub offset: usize,
}

lazy_static! {
    pub static ref TEST_VECTORS: Vec<TestSlowKeyOptions> = vec![
        TestSlowKeyOptions {
            opts: SlowKeyOptions {
                iterations: 1,
                length: 64,
                scrypt: ScryptOptions::default(),
                argon2id: Argon2idOptions::default()
            },
            salt: b"SlowKeySlowKey16".to_vec(),
            password: Vec::new(),
            offset_data: Vec::new(),
            offset: 0,
        },
        TestSlowKeyOptions {
            opts: SlowKeyOptions {
                iterations: 3,
                length: 64,
                scrypt: ScryptOptions::default(),
                argon2id: Argon2idOptions::default()
            },
            salt: b"SlowKeySlowKey16".to_vec(),
            password: b"Hello World".to_vec(),
            offset_data: Vec::new(),
            offset: 0,
        },
    ];
}

pub struct SlowKey {
    iterations: usize,
    length: usize,
    scrypt: Scrypt,
    argon2id: Argon2id,
}

impl SlowKey {
    pub const SALT_SIZE: usize = 16;
    pub const DEFAULT_SALT: [u8; SlowKey::SALT_SIZE] = [0; SlowKey::SALT_SIZE];

    pub fn new(opts: &SlowKeyOptions) -> Self {
        if opts.iterations == 0 {
            panic!("Invalid iterations number");
        }

        Self {
            iterations: opts.iterations,
            length: opts.length,
            scrypt: Scrypt::new(opts.length, &opts.scrypt),
            argon2id: Argon2id::new(opts.length, &opts.argon2id),
        }
    }

    pub fn derive_key_with_callback<F: FnMut(usize, &Vec<u8>)>(
        &self, salt: &[u8], password: &[u8], offset_data: &[u8], offset: usize, mut callback: F,
    ) -> Vec<u8> {
        if salt.len() != Self::SALT_SIZE {
            panic!("Salt must be {} long", Self::SALT_SIZE);
        }

        // If this is the first iteration, calculate the SHA2 and SHA3 hashes of the result and the inputs. Otherwise,
        // continue from where it has stopped
        let mut res = match offset {
            0 => self.double_hash(salt, password, 0, &Vec::new()),
            _ => offset_data.to_vec(),
        };

        for i in offset..self.iterations {
            let iteration = i as u64;

            // Run all hashing algorithms in parallel
            let (scrypt_output, argon2_output) = join(
                || self.scrypt(salt, password, iteration, &res),
                || self.argon2id(salt, password, iteration, &res),
            );

            // Concatenate all the results and the inputs
            res = [
                scrypt_output,
                argon2_output,
                [salt, password, &iteration.to_le_bytes()].concat(),
            ]
            .concat();

            // Calculate the SHA2 and SHA3 hashes of the result and the inputs
            res = self.double_hash(salt, password, iteration, &res);

            res.truncate(self.length);

            callback(i, &res);
        }

        res
    }

    pub fn derive_key(&self, salt: &[u8], password: &[u8], offset_data: &[u8], offset: usize) -> Vec<u8> {
        self.derive_key_with_callback(salt, password, offset_data, offset, |_, _| {})
    }

    fn double_hash(&self, salt: &[u8], password: &[u8], iteration: u64, input: &[u8]) -> Vec<u8> {
        let mut res: Vec<u8> = input.to_vec();

        // Calculate the SHA2 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        let mut sha512 = Sha512::new();
        sha512.update(&res);
        res = sha512.finalize().to_vec();

        // Calculate the SHA3 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        let mut keccack512 = Keccak512::new();
        keccack512.update(&res);

        keccack512.finalize().to_vec()
    }

    fn scrypt(&self, salt: &[u8], password: &[u8], iteration: u64, input: &[u8]) -> Vec<u8> {
        let mut res: Vec<u8> = input.to_vec();

        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        self.scrypt.hash(salt, &res)
    }

    fn argon2id(&self, salt: &[u8], password: &[u8], iteration: u64, input: &[u8]) -> Vec<u8> {
        let mut res: Vec<u8> = input.to_vec();

        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        self.argon2id.hash(salt, &res)
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

        let mut group = c.benchmark_group("Algorithms");
        group.sample_size(10).measurement_time(Duration::from_secs(300));

        let options = ScryptOptions::default();

        group.bench_with_input(
            BenchmarkId::new(
                "Scrypt (Default)",
                format!("n: {}, r: {}, p: {}", options.n, options.r, options.p),
            ),
            &input,
            |b, data| {
                b.iter(|| {
                    let _result = Scrypt::new(32, &options).hash(black_box(&[0u8; 32]), black_box(data));
                });
            },
        );

        let options = Argon2idOptions::default();

        group.bench_with_input(
            BenchmarkId::new(
                "Argon2id (Default)",
                format!("m_cost: {}, t_cost: {}", options.m_cost, options.t_cost),
            ),
            &input,
            |b, data| {
                b.iter(|| {
                    let _result = Argon2id::new(32, &options).hash(black_box(&[0u8; 32]), black_box(data));
                });
            },
        );

        let options = SlowKeyOptions {
            iterations: 2,
            ..SlowKeyOptions::default()
        };

        group.bench_with_input(
            BenchmarkId::new(
                "SlowKey (Default)",
                format!(
                    "iterations: {}, Scrypt: (n: {}, r: {}, p: {}), Argon2id: (m_cost: {}, t_cost: {})",
                    options.iterations,
                    options.scrypt.n,
                    options.scrypt.r,
                    options.scrypt.p,
                    options.argon2id.m_cost,
                    options.argon2id.t_cost
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

    pub fn fast_benchmark(output_path: &Path) {
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

        let mut group = c.benchmark_group("Algorithms");
        group.sample_size(50);

        for options in [ScryptOptions::new(1 << 10, 8, 1), ScryptOptions::new(1 << 12, 8, 2)] {
            group.bench_with_input(
                BenchmarkId::new(
                    "Scrypt",
                    format!("n: {}, r: {}, p: {}", options.n, options.r, options.p),
                ),
                &input,
                |b, data| {
                    b.iter(|| {
                        let _result = Scrypt::new(32, &options).hash(black_box(&[0u8; 32]), black_box(data));
                    });
                },
            );
        }

        for options in [Argon2idOptions::new(1 << 10, 2), Argon2idOptions::new(1 << 11, 4)] {
            group.bench_with_input(
                BenchmarkId::new(
                    "Argon2id",
                    format!("m_cost: {}, t_cost: {}", options.m_cost, options.t_cost),
                ),
                &input,
                |b, data| {
                    b.iter(|| {
                        let _result = Argon2id::new(32, &options).hash(black_box(&[0u8; 32]), black_box(data));
                    });
                },
            );
        }

        let options = SlowKeyOptions {
            iterations: 10,
            length: 32,
            scrypt: ScryptOptions::new(1 << 10, 8, 1),
            argon2id: Argon2idOptions::new(1 << 10, 2),
        };

        group.bench_with_input(
            BenchmarkId::new(
                "SlowKey",
                format!(
                    "iterations: {}, Scrypt: (n: {}, r: {}, p: {}), Argon2id: (m_cost: {}, t_cost: {})",
                    options.iterations,
                    options.scrypt.n,
                    options.scrypt.r,
                    options.scrypt.p,
                    options.argon2id.m_cost,
                    options.argon2id.t_cost
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
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].password, &TEST_VECTORS[0].offset_data, TEST_VECTORS[0].offset, "b2c1bcd2674c0c96473e61b17d6e30d6e8a46ac258f730075b476a732284c64e36df041f7bd50260d68128b62e6cffac03e4ff585025d18b04d41dda4633b800")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].password, &TEST_VECTORS[1].offset_data, TEST_VECTORS[1].offset, "e24c16e6912d2348e8be84977d22bd229382b72b65b501afe0066a32d6771df57f3557de0719070bbafb8faf1d0649562be693e3bf33c6e0a107d0af712030ef")]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "b143409d7030a3a2d1099de2071452406e0a94d7ccae6ef9fc570f724bfe15358b3b530d90b93e47b742f5883330f9742f1ca367b9a4c519daf66be30af100b6")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { n: 1 << 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "6fe4ad1ea824710e75b4a3914c6f3c617c70b3aeb0451639188c253b6f52880e")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions { m_cost: 16, t_cost: 2 }
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "744cfcc54433dfb5f4027163cc94c81d4630a63a6e60799c44f2a5801ad2bc77")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "3ed36a2cb71a043a901cbe237df6976b7a724acadfbc12112c90402548876dd5e76be1da2a1cb57e924a858c36b51c68db13b986e70ddc23254d7fa7a15c2ee0")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"", &Vec::new(), 0,
    "3af13ebf654ddf60014f4a7f37826f5f60e4defddefffdfc6bf5431e37420c1e308e823bef30a6adb3f862c4b4270aa55e9b0440af7e8ec8d52a3458c1cb3ff4")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "c2a74fca9621ca13f2ab1a1bdf7cb8e6abe231d7494c280ff40024b1e92f964579d7c77e4b5c32ec438f2932b612f8eae9eeedbba93b0708e1f1b497bcdaed5d")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsal2", b"test", &Vec::new(), 0,
    "016bbfa52b69c0fc366f9b93b5209d0c9783c018102101eb755f217627541778b13c5db624a105ed6470d7a916e8e5843f952f20bb9f0e9b6053e72176b6158b")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test2", &Vec::new(), 0,
    "f20e5bf61c9c0ab9208eb1b5a2f3a51a8276dbc5490862f17afbba5ffe539ee95765095aff000d86371ed6ca927efe736008fd048fbde77af56b20331ebde083")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { n: 1 << 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 1,
    "dc4ca67e268ac2df2bbaa377afabafda82012b6188d562d67ef57f66f2f592e1")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "488d73ed1e5c22edfe060d542dc1bc517cdc567aede68fbf87f344fc153b1febbfff6bb52f236a21fa6aaa16e39769248f7eb01c80a48988049a9faee7434f99")]

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
