use balloon_hash::password_hash::SaltString;
use criterion::{black_box, BenchmarkId, Criterion, SamplingMode};
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Keccak512};
use std::{path::Path, time::Duration};

use crate::utils::algorithms::{
    argon2id::{Argon2id, Argon2idOptions},
    balloon_hash::{BalloonHash, BalloonHashOptions},
    scrypt::{Scrypt, ScryptOptions},
};

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct SlowKeyOptions {
    pub iterations: usize,
    pub length: usize,
    pub scrypt: ScryptOptions,
    pub argon2id: Argon2idOptions,
    pub ballon_hash: BalloonHashOptions,
}

impl SlowKeyOptions {
    pub const MIN_ITERATIONS: usize = 1;
    pub const MAX_ITERATIONS: usize = u32::MAX as usize;
    pub const DEFAULT_ITERATIONS: usize = 100;

    pub const MIN_KEY_SIZE: usize = 9;
    pub const MAX_KEY_SIZE: usize = 64;
    pub const DEFAULT_KEY_SIZE: usize = 32;

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
            ballon_hash: *balloon_hash,
        }
    }

    pub fn print(&self) {
        println!(
            "{}:\n  {}: {}\n  {}: {}\n  {}: (n: {}, r: {}, p: {})\n  {}: (version: {}, m_cost: {}, t_cost: {})\n  {}: (hash: {}, s_cost: {}, t_cost: {})\n",
            "SlowKey Parameters".yellow(),
            "Iterations".green(),
            &self.iterations.to_string().cyan(),
            "Length".green(),
            &self.length.to_string().cyan(),
            "Scrypt".green(),
            &self.scrypt.n().to_string().cyan(),
            &self.scrypt.r().to_string().cyan(),
            &self.scrypt.p().to_string().cyan(),
            "Argon2id".green(),
            Argon2id::VERSION.to_string().cyan(),
            &self.argon2id.m_cost().to_string().cyan(),
            &self.argon2id.t_cost().to_string().cyan(),
            "Balloon Hash".green(),
            BalloonHash::HASH.cyan(),
            &self.ballon_hash.s_cost().to_string().cyan(),
            &self.ballon_hash.t_cost().to_string().cyan()
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
            ballon_hash: BalloonHashOptions::default(),
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
                argon2id: Argon2idOptions::default(),
                ballon_hash: BalloonHashOptions::default()
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
                argon2id: Argon2idOptions::default(),
                ballon_hash: BalloonHashOptions::default()
            },
            salt: b"SlowKeySlowKey16".to_vec(),
            password: b"Hello World".to_vec(),
            offset_data: Vec::new(),
            offset: 0,
        },
    ];
}

pub struct SlowKey<'a> {
    iterations: usize,
    length: usize,
    scrypt: Scrypt,
    argon2id: Argon2id,
    balloon_hash: BalloonHash<'a>,
}

impl<'a> SlowKey<'a> {
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
            balloon_hash: BalloonHash::new(opts.length, &opts.ballon_hash),
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

        let salt_string = SaltString::encode_b64(salt).unwrap();

        for i in offset..self.iterations {
            let iteration = i as u64;

            let mut scrypt_output = Vec::new();
            let mut argon2_output = Vec::new();
            let mut balloon_hash_output = Vec::new();

            // Run all KDF algorithms in parallel
            rayon::scope(|s| {
                s.spawn(|_| scrypt_output = self.scrypt(salt, password, iteration, &res));
                s.spawn(|_| argon2_output = self.argon2id(salt, password, iteration, &res));
                s.spawn(|_| balloon_hash_output = self.balloon_hash(salt, &salt_string, password, iteration, &res));
            });

            // Concatenate all the results and the inputs
            res = [
                scrypt_output,
                argon2_output,
                balloon_hash_output,
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

    fn balloon_hash(
        &self, salt: &[u8], salt_string: &SaltString, password: &[u8], iteration: u64, input: &[u8],
    ) -> Vec<u8> {
        let mut res: Vec<u8> = input.to_vec();

        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        self.balloon_hash.hash(salt_string, &res)
    }

    fn perform_benchmark(
        sample_size: usize, measurement_time: Duration, sampling_mode: SamplingMode, output_path: &Path,
    ) {
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
            .sample_size(sample_size)
            .measurement_time(measurement_time)
            .sampling_mode(sampling_mode);

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
            ..SlowKeyOptions::default()
        };
        group.bench_with_input(
            BenchmarkId::new(
                "SlowKey (Default)",
                format!(
                    "iterations: {}, Scrypt: (n: {}, r: {}, p: {}), Argon2id: (m_cost: {}, t_cost: {}), BalloonHash: (s_cost: {}, t_cost: {})",
                    options.iterations,
                    options.scrypt.n(),
                    options.scrypt.r(),
                    options.scrypt.p(),
                    options.argon2id.m_cost(),
                    options.argon2id.t_cost(),
                    options.ballon_hash.s_cost(),
                    options.ballon_hash.t_cost()
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

    pub fn benchmark(output_path: &Path) {
        Self::perform_benchmark(10, Duration::from_secs(300), SamplingMode::Auto, output_path);
    }

    pub fn fast_benchmark(output_path: &Path) {
        Self::perform_benchmark(10, Duration::from_secs(30), SamplingMode::Flat, output_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::sodium_init::initialize;
    use rstest::rstest;

    #[rstest]
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].password, &TEST_VECTORS[0].offset_data, TEST_VECTORS[0].offset, "e30eb9608393fe87f5947bb15d78545f183b8c2b68b1122d18e8fccf643c0018d517fd1b07a2de16ec9b86b195f535330b0406bc1ac8b59549cae823842da415")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].password, &TEST_VECTORS[1].offset_data, TEST_VECTORS[1].offset, "0bd43af1d71da862864bfa0d1e1246efe9246228e4c2ba5d5c8162f97998939cf926d671f718f43b08efe7c4ad045022590b6fc5123ac908bd62ccb182456249")]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "b78f9be249176f0876e2a410eacb76c7948f138aa6b262e22fb511e597bbec9364cc29712639faa88144bbd61dc843542c1ad9a14514cf7b859c534f78c87e8d")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::new(1 << 12, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "0544c2195e196ccddac50d88f90288ab90a5037622fe6a296e6f71c397f0dc95")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::new(1 << 4, 2),
        ballon_hash: BalloonHashOptions::new(1 << 5, 3),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "a485803cd0c5fc80cec047d3872f36bf1fbb08f2e9cefdcd88f34f60dd41d74d")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(1 << 20, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "fbb9672c3191a51e3efb966cdde1ab18ef762544d3372ba6ded39e9226ebffe6a1ed97f1591d2fdbdcf6f61f26cd1432ac2519e219363ea7871f752eb3ba22de")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(1 << 15, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"", &Vec::new(), 0,
    "bcd8c72981421e8f695e4cb1e0beafce9ac60beafb970a5824381a1716beda47614a170b7c8ea82fb435f836352fdabf0b3d47615c04f714928d963557f996d3")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(1 << 15, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "5113c07f49fe6d342e369a3f281fa596241cae9acfb15686404b2b3f0c77f1340fe7638755ea7a8a1e1b2205c4c3fd84da373377cfedde0382fc932d10f5e687")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(1 << 15, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsal2", b"test", &Vec::new(), 0,
    "49a5593ad6437a362137d2f35099133e7f68e96fd5d4b234859282158307971362a1f785cc2981f5a15e9f391eea61d042fa3be41cb478f8516fed0fbbb6f6ea")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(1 << 15, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test2", &Vec::new(), 0,
    "e73278c6d6178cdb6ab0035f77d91288ff198cd3594fc2ba8ee5c83f7213f3f7cd45784bf91f6135975e92b68af703ce6707cb2501b7426bdf3c71f35e4b41d3")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::new(1 << 12, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 1,
    "df88794d493027643559641176ee44acdd263a56e9144c3724926f350179ca95")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: SlowKeyOptions::MAX_KEY_SIZE,
        scrypt: ScryptOptions::new(1 << 15, 8, 1),
        argon2id: Argon2idOptions::default(),
        ballon_hash: BalloonHashOptions::default(),
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
