use std::fmt::{self, Display, Formatter};

use crate::utils::{
    argon2id::{Argon2id, Argon2idOptions},
    scrypt::{Scrypt, ScryptOptions},
};
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Keccak512};

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

    pub const MIN_KEY_SIZE: usize = 10;
    pub const MAX_KEY_SIZE: usize = 128;
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
}

impl Display for SlowKeyOptions {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let output = format!(
            "{}:\n  {}: {}\n  {}: {}\n  {}: (n: {}, r: {}, p: {})\n  {}: (version: {}, m_cost: {}, t_cost: {})",
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

        write!(f, "{}", output)
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

    pub fn new(opts: &SlowKeyOptions) -> Self {
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
            panic!("salt must be {} long", Self::SALT_SIZE);
        }

        let mut res = match offset {
            0 => Vec::new(),
            _ => offset_data.to_vec(),
        };

        for i in offset..self.iterations {
            let iteration = i as u64;

            // Calculate the SHA2 and SHA3 hashes of the result and the inputs
            self.double_hash(salt, password, iteration, &mut res);

            // Calculate the Scrypt hash of the result and the inputs
            self.scrypt(salt, password, iteration, &mut res);

            // Calculate the SHA2 and SHA3 hashes of the result and the inputs again
            self.double_hash(salt, password, iteration, &mut res);

            // Calculate the Argon2 hash of the result and the inputs
            self.argon2id(salt, password, iteration, &mut res);

            callback(i, &res);
        }

        res.truncate(self.length);

        res
    }

    pub fn derive_key(&self, salt: &[u8], password: &[u8], offset_data: &[u8], offset: usize) -> Vec<u8> {
        self.derive_key_with_callback(salt, password, offset_data, offset, |_, _| {})
    }

    fn double_hash(&self, salt: &[u8], password: &[u8], iteration: u64, res: &mut Vec<u8>) {
        // Calculate the SHA2 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        let mut sha512 = Sha512::new();
        sha512.update(&res);
        *res = sha512.finalize().to_vec();

        // Calculate the SHA3 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        let mut keccack512 = Keccak512::new();
        keccack512.update(&res);
        *res = keccack512.finalize().to_vec();
    }

    fn scrypt(&self, salt: &[u8], password: &[u8], iteration: u64, res: &mut Vec<u8>) {
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        *res = self.scrypt.hash(salt, res);
    }

    fn argon2id(&self, salt: &[u8], password: &[u8], iteration: u64, res: &mut Vec<u8>) {
        res.extend_from_slice(salt);
        res.extend_from_slice(password);
        res.extend_from_slice(&iteration.to_le_bytes());

        *res = self.argon2id.hash(salt, res);
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
        length: 64,
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
        length: 64,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "3ed36a2cb71a043a901cbe237df6976b7a724acadfbc12112c90402548876dd5e76be1da2a1cb57e924a858c36b51c68db13b986e70ddc23254d7fa7a15c2ee0")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 128,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "8e69eb21b3aa9cf0d5b42d18b5a80c8db50908c3baadd9c425d8dfc21ca0f37a503e37a18c5312cf040654f643cc1a5b1801e1f8e86fde355d05a5d2699725b088bf6bf02b0a5888e9198c1876ce82b2664185ff914c853b86b6ead34a351fcfd7124e75bfd643fbdb391025eee3483f30b1f765eae304547a1a1168d0ef448b")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"", &Vec::new(), 0,
    "3af13ebf654ddf60014f4a7f37826f5f60e4defddefffdfc6bf5431e37420c1e308e823bef30a6adb3f862c4b4270aa55e9b0440af7e8ec8d52a3458c1cb3ff4")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "c2a74fca9621ca13f2ab1a1bdf7cb8e6abe231d7494c280ff40024b1e92f964579d7c77e4b5c32ec438f2932b612f8eae9eeedbba93b0708e1f1b497bcdaed5d")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsal2", b"test", &Vec::new(), 0,
    "016bbfa52b69c0fc366f9b93b5209d0c9783c018102101eb755f217627541778b13c5db624a105ed6470d7a916e8e5843f952f20bb9f0e9b6053e72176b6158b")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
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
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "488d73ed1e5c22edfe060d542dc1bc517cdc567aede68fbf87f344fc153b1febbfff6bb52f236a21fa6aaa16e39769248f7eb01c80a48988049a9faee7434f99")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 128,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "0ff28531af487240b664d549ebc2a367df89a2b5d94baed94a53025601b2b2f5ced135415c7cf880b4cc1fe97ea5ba052838caebb8301719d268b7a2d795d75908712910839c8145a70b7ebdf49e2f61a4c1466e89e2e5bd8fb45eb076a72baa60bc803162ee20481b1b85a5985d768908b283e95e52df4466f116ab9014945a")]

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
