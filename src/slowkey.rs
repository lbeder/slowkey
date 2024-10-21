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
            // Calculate the SHA2 and SHA3 hashes of the result and the inputs
            self.double_hash(salt, password, &mut res);

            // Calculate the Scrypt hash of the result and the inputs
            self.scrypt(salt, password, &mut res);

            // Calculate the SHA2 and SHA3 hashes of the result and the inputs again
            self.double_hash(salt, password, &mut res);

            // Calculate the Argon2 hash of the result and the inputs
            self.argon2id(salt, password, &mut res);

            callback(i, &res);
        }

        res.truncate(self.length);

        res
    }

    pub fn derive_key(&self, salt: &[u8], password: &[u8], offset_data: &[u8], offset: usize) -> Vec<u8> {
        self.derive_key_with_callback(salt, password, offset_data, offset, |_, _| {})
    }

    fn double_hash(&self, salt: &[u8], password: &[u8], res: &mut Vec<u8>) {
        // Calculate the SHA2 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(password);

        let mut sha512 = Sha512::new();
        sha512.update(&res);
        *res = sha512.finalize().to_vec();

        // Calculate the SHA3 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(password);

        let mut keccack512 = Keccak512::new();
        keccack512.update(&res);
        *res = keccack512.finalize().to_vec();
    }

    fn scrypt(&self, salt: &[u8], password: &[u8], res: &mut Vec<u8>) {
        res.extend_from_slice(salt);
        res.extend_from_slice(password);

        *res = self.scrypt.hash(salt, res);
    }

    fn argon2id(&self, salt: &[u8], password: &[u8], res: &mut Vec<u8>) {
        res.extend_from_slice(salt);
        res.extend_from_slice(password);

        *res = self.argon2id.hash(salt, res);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::sodium_init::initialize;
    use rstest::rstest;

    #[rstest]
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].password, &TEST_VECTORS[0].offset_data, TEST_VECTORS[0].offset, "1805476033e579abf06772db32b52886e07d9c579c99be05dcc1826e2f162b5c4bf846b7fae13ac5e57991da69769f1d2aac2d9046b9c60cbce9af35b371d4bd")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].password, &TEST_VECTORS[1].offset_data, TEST_VECTORS[1].offset, "edada70cd27e31ddcfc41edba2f63a03418fc1acd352ff78eff149573c5e247f0e06850cf03dc50dd9eef63275061cb85cdff8b47c3593d749145f1a226e8b7b")]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: 64,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "3dcbcc11d08ee43af8c4b537daf61087ce4c740f70e89b72b1f19083a6aa25a6d978eb94e452db49fc9c2309db56edbae93f68a0858e6b1d31aa38e1c63bbe03")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { n: 1 << 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "2943950259d56a78c439065d0bf2baa86e32a7be9ad9509e3e0ba78c2bc1494a")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions { m_cost: 16, t_cost: 2 }
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "d4509baa22a5cd0065e99b304e3efe2681a564e4d1fe5f19e57017d58f06c59e")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "6b66b1280b06539fbb571cfd4b44b3f114ab0d4f40e2d5e881cc1a329f2dd615088aa2b86f63422897cdf465ab11d68919bc247cb1517e4bd5abff78677dfb47")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 128,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "ecfe68be26c4cd219e44ab9a0d287252b07e9fc4ce3203563d578bc713fbfe65bb2c4cb167ff67dad2225521eb78aa73ee646c3a3b4d5caca7ff37cc59573a047c66d7761164d5b1b5586ec4bc953e75e128accda5fe2cb70ac4f860a825de3483a61839d6f6f9e14a3826a4fab2a6fbc8fad0f8ce4a71e7c15f4f14b08635cc")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"", &Vec::new(), 0,
    "dcec23f3d34f980291e6a5246eb87a87039729d68f71b6c601ad1bbb7997c4b3584edb681eda73b60a232cd5fd672afc4516ed9c0d3ed922a209a93e155b22fb")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "bc4f95aeddc434ba2f308865a31a06365fc45d9bcb47f70fbcb59be948f3c104a18eed7a3eaa595bf90233b3f1cafe545cf3e06eee49e2f9952b68a86a66b2a9")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsal2", b"test", &Vec::new(), 0,
    "8006abf493c49f65ed7a8d47719fd5b2b90f63e8c3d6759ba012d87e9bcd8791598984de8100bbaadef4c9228683f69dab74b53dcda8f8693e7bff58c3491b36")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test2", &Vec::new(), 0,
    "07b6fc97a02cd99fd6d7b1618dcf972421bed33bffa72eaea7c22e6ac224735ac80192dc90818d02ff1ab8c00d84513c6156f1f301e951a4cb9a313874c2df59")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { n: 1 << 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 1,
    "653f16de895c368d2ec8cd1950fe68b1fd4177050118f98d967a39c1057c1cc8")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "f5bd30aebebdaa919d54a0cabceba79dd1ee175de91a5ce9b2b9ba83b96dfd6a1dda7cf298e8aeccc56a5826ead128b9eb1669150426499f3cc8475b54702c18")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 128,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "93c1738ae91ff2011cc630f781f278573f0397f5bebc676fd43619fe92019ac0f53c00a6773bfa06275ce4d92828f66fa33681f88950fd59b20d6f7e9ecb9b454d0988a0ff76a1780e7d93a9fca7b0869de6ebb5f673e200ea7def18ddf1923597e75d2e6985750e62d2326f887bef2c1d88a8252d2d4d0c77d23af8535bf020")]

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
