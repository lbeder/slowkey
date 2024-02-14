use crate::utils::{
    argon2id::{Argon2id, Argon2idOptions},
    scrypt::{Scrypt, ScryptOptions},
};
use sha2::Sha512;
use sha3::{Digest, Keccak512};

#[derive(PartialEq, Debug, Clone)]
pub struct SlowKeyOptions {
    pub iterations: u32,
    pub length: usize,
    pub scrypt: ScryptOptions,
    pub argon2id: Argon2idOptions,
}

impl SlowKeyOptions {
    pub const MIN_ITERATIONS: u32 = 0;
    pub const MAX_ITERATIONS: u32 = u32::MAX;
    pub const DEFAULT_ITERATIONS: u32 = 100;

    pub const MIN_KDF_LENGTH: usize = 10;
    pub const MAX_KDF_LENGTH: usize = 64;
    pub const DEFAULT_KDF_LENGTH: usize = 16;

    pub fn new(iterations: u32, length: usize, scrypt: &ScryptOptions, argon2id: &Argon2idOptions) -> Self {
        if length < Self::MIN_KDF_LENGTH {
            panic!(
                "kdf {} is shorter than the min length of {}",
                Self::MIN_KDF_LENGTH,
                length
            );
        }

        if length > Self::MAX_KDF_LENGTH {
            panic!(
                "kdf {} is longer than the max length of {}",
                Self::MAX_KDF_LENGTH,
                length
            );
        }

        SlowKeyOptions {
            iterations,
            length,
            scrypt: scrypt.clone(),
            argon2id: argon2id.clone(),
        }
    }
}

impl Default for SlowKeyOptions {
    fn default() -> Self {
        Self {
            iterations: Self::DEFAULT_ITERATIONS,
            length: Self::DEFAULT_KDF_LENGTH,
            scrypt: ScryptOptions::default(),
            argon2id: Argon2idOptions::default(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct TestSlowKeyOptions {
    pub opts: SlowKeyOptions,
    pub salt: Vec<u8>,
    pub secret: Vec<u8>,
    pub offset_data: Vec<u8>,
    pub offset: u32,
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
            salt: b"SlowKeySalt".to_vec(),
            secret: Vec::new(),
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
            salt: b"SlowKeySalt".to_vec(),
            secret: b"Hello World".to_vec(),
            offset_data: Vec::new(),
            offset: 0,
        },
    ];
}

pub struct SlowKey {
    iterations: u32,
    length: usize,
    scrypt: Scrypt,
    argon2id: Argon2id,
}

impl SlowKey {
    pub const MIN_SALT_LENGTH: usize = 8;
    pub const MAX_SALT_LENGTH: usize = 0xFFFFFFFF;

    pub fn new(opts: &SlowKeyOptions) -> Self {
        SlowKey {
            iterations: opts.iterations,
            length: opts.length,
            scrypt: Scrypt::new(opts.length, &opts.scrypt),
            argon2id: Argon2id::new(opts.length, &opts.argon2id),
        }
    }

    fn double_hash(&self, salt: &[u8], secret: &[u8], res: &mut Vec<u8>) {
        // Calculate the SHA2 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(secret);

        let mut sha512 = Sha512::new();
        sha512.update(&res);
        *res = sha512.finalize().to_vec();

        // Calculate the SHA3 hash of the result and the inputs
        res.extend_from_slice(salt);
        res.extend_from_slice(secret);

        let mut keccack512 = Keccak512::new();
        keccack512.update(&res);
        *res = keccack512.finalize().to_vec();
    }

    fn scrypt(&self, salt: &[u8], secret: &[u8], res: &mut Vec<u8>) {
        res.extend_from_slice(salt);
        res.extend_from_slice(secret);

        *res = self.scrypt.hash(salt, res);
    }

    fn argon2id(&self, salt: &[u8], secret: &[u8], res: &mut Vec<u8>) {
        res.extend_from_slice(salt);
        res.extend_from_slice(secret);

        *res = self.argon2id.hash(salt, res);
    }

    pub fn derive_key_with_callback<F: FnMut(u32, &Vec<u8>)>(
        &self, salt: &[u8], secret: &[u8], offset_data: &[u8], offset: u32, mut callback: F,
    ) -> Vec<u8> {
        let mut res = match offset {
            0 => Vec::new(),
            _ => offset_data.to_vec(),
        };

        for i in 0..(self.iterations - offset) {
            // Calculate the SHA3 and SHA2 hashes of the result and the inputs
            self.double_hash(salt, secret, &mut res);

            // Calculate the Scrypt hash of the result and the inputs
            self.scrypt(salt, secret, &mut res);

            // Calculate the SHA3 and SHA2 hashes of the result and the inputs again
            self.double_hash(salt, secret, &mut res);

            // Calculate the Argon2 hash of the result and the inputs
            self.argon2id(salt, secret, &mut res);

            callback(i, &res);
        }

        // Calculate the final SHA3 and SHA2 hashes (and trim the result, if required)
        self.double_hash(salt, secret, &mut res);
        res.truncate(self.length);

        res
    }

    pub fn derive_key(&self, salt: &[u8], secret: &[u8], offset_data: &[u8], offset: u32) -> Vec<u8> {
        self.derive_key_with_callback(salt, secret, offset_data, offset, |_, _| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].secret, &TEST_VECTORS[0].offset_data, TEST_VECTORS[0].offset, "91e119bd892f0a6b4bc5adf23693db6409a8d053a5b6a451d0ab340a5e01cb6b6a04d31eb6d78e7dc89809869d59a24ea88aae9f9fa7aa0630040a2c02f0b1d1")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].secret, &TEST_VECTORS[1].offset_data, TEST_VECTORS[1].offset, "78acc4cf9c4597b4312454fa6e78134f9e0308f79a07e97e457207d0919374c6d3d31b78c523fba364156da4df930b87596a42a1b1991cec5af708762b9e2e95")]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: 64,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test", &Vec::new(), 0,
    "96140c82d8fdc8f845b0765ff5b80026872278f220f9261e5ab46a6146a02ad2feb9fea8be0f44551c0d4e731460ffebee3879da9140f090f137a9fab18308e0")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { log_n: 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test", &Vec::new(), 0,
    "a0a2b2b3cdb9002208a32b598025dfe7789bf2b3cceed8928fd873554d461128")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions { m_cost: 16, t_cost: 2, p_cost: 2 }
    }, b"saltsalt", b"test", &Vec::new(), 0,
    "bb599595d1f5cf42fc39b414fa81798085c00fce25dfece2b84bbc038c3737a9")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { log_n: 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test", &Vec::new(), 0,
    "d256abf03bea97bdde3b14e5248c74055f289a7d954572de9280a451cf4961c967d94076979dc77ddffc3ed21fcd11724ac22d927d7f47861f4c93e6afc5743d")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"", &Vec::new(), 0,
    "d7b3c1eb6ac6c933e9de68803832d67588f255cab90a4c2abdbdbaf28db5fac172fcf037b3e8d0ba23567414391418ae225cbde9feda8c1305df5773a7d2aa12")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test", &Vec::new(), 0,
    "dd8a764e87063965dc28627e4114fb239ff87d442d87754fa9cff0f254cb740e1e992907ff8746f1d824585b6135952aa130560d82b3f0799f919d85c6900a61")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt2", b"test", &Vec::new(), 0,
    "3989531a09fa72b8184d18c267e6380260484bc3892e45e520bd7056667add4d7e436fb24daa168f6bdd3ff8d436d0b74af449d174cf1119244317e5c750eb41")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test2", &Vec::new(), 0,
    "7114ee8eecab95fefb06a4369d30462ae743a70367d23c73a83501cc2d398bf930e62b6332caf283a97ef2269e5fce5cd597a5ff12deb5f9af6ed418dd89b01a")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { log_n: 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test", &Vec::new(), 1,
    "260dbbff8a342c3915aaa2e54823f7da2d006227305572129fbae9706158fdab")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsalt", b"test", &Vec::new(), 5,
    "2686ceace042c42bc15519be2450edcaacce45fe9e26db10d6b3f74708ebb1279d48c225fbeacff7d84da6723fe71a5b5cc87b05677d23ff5b9bd30a1fc0e0d8")]

    fn derive_test(
        #[case] options: &SlowKeyOptions, #[case] salt: &[u8], #[case] secret: &[u8], #[case] offset_data: &[u8],
        #[case] offset: u32, #[case] expected: &str,
    ) {
        let kdf = SlowKey::new(options);
        let key = kdf.derive_key(salt, secret, offset_data, offset);
        assert_eq!(hex::encode(key), expected);
    }
}
