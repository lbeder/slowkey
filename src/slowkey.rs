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

    pub const MIN_KEY_LENGTH: usize = 10;
    pub const MAX_KEY_LENGTH: usize = 128;
    pub const DEFAULT_KEY_LENGTH: usize = 16;

    pub fn new(iterations: u32, length: usize, scrypt: &ScryptOptions, argon2id: &Argon2idOptions) -> Self {
        if length < Self::MIN_KEY_LENGTH {
            panic!(
                "length {} is shorter than the min length of {}",
                Self::MIN_KEY_LENGTH,
                length
            );
        }

        if length > Self::MAX_KEY_LENGTH {
            panic!(
                "length {} is longer than the max length of {}",
                Self::MAX_KEY_LENGTH,
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
            length: Self::DEFAULT_KEY_LENGTH,
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
            salt: b"SlowKeySlowKey16".to_vec(),
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
            salt: b"SlowKeySlowKey16".to_vec(),
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
    pub const SALT_LENGTH: usize = 16;

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
        if salt.len() != SlowKey::SALT_LENGTH {
            panic!("salt must be {} long", SlowKey::SALT_LENGTH);
        }

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
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].secret, &TEST_VECTORS[0].offset_data, TEST_VECTORS[0].offset, "93e1459001ad83e3b39133cfba4ced8ce69f68e58553b093114abeee4174118b87d87d1b3d2c67d2d3ea5ca050b83ab49346eb9583e5fb31cc8f51f8d3343bf1")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].secret, &TEST_VECTORS[1].offset_data, TEST_VECTORS[1].offset, "746f3a93557814a0e496a13af627a25954f3f15e129471b8eec713958ed12a273b932d02ba4f218edacb7d8a4b9bd4e6368004531f77e1981393f127c7f3ab64")]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: 64,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "d1870125c94e2525c39cfe926f64010f53326f30c6f9800c8b13e11adc9a6ec35ccdf1aa0278aa5684c2f6fb1c46bdddea3360975eefa4455435fbc92b64e1b3")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { n: 1 << 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "3a0e5d6dc5bebaea2dbf60fec066e1a224263000c96dc123b786576a1773aad4")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions { m_cost: 16, t_cost: 2 }
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "35320ebf4ec70ef596c769c41b0922a740cf162d7959557971b7832cc7118d9e")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "6f823e9b1dbb8ed1890dc1b417ae45d47f0f8449611349323eaea840fa4ec1a4aab516b1448ac893e2ac543c77d06305a05342bdc403215dc8bc6ff3ed6c949e")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 128,
        scrypt: ScryptOptions { n: 1 << 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "6fce30905ab3f0af90443d2b4501845447003d4f07b76a9ba0de716fb2cacd72c3d0ec8f51ab0c3bff1f40e5ccd5909f2cce21afc5a94fa535ca28dc01f81fd5")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"", &Vec::new(), 0,
    "f006bfa25a0584f7031a91ca2449f4f733d974e9f880b79534185c6154e53ef0b430c24433354b18548083594cff870ae4342b72dcfcc1435373c2b36e2b2aa6")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 0,
    "897778a12e2e2a82e1c351f4f3c3935bdd81ebd67de1f9a4b92922e6b318f677877b7a28f5cdcaa722baf4ebefad7dfb71daae4b9850b120d9463b47b73aa9c0")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsal2", b"test", &Vec::new(), 0,
    "d911524b4f5d60bf682f10c73858bfe02895ddfec7edd1481cb575cf2bd99220bb6cd9e91a4b4c7a88356d01dab41269b0bc5bf4ab139a36e1d5f3ff21c75228")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test2", &Vec::new(), 0,
    "9d4d28b7d8320a6f67bb4b2e70afbc07a043f0c23a8506faa9d3fb780fed5927b9223cf96269d5bf33833d9faf7f2d0e1a260043fdc8e301c123ade23835aa2c")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { n: 1 << 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 1,
    "a67355dd4bac46f8e7b4b7a397dbf3ba4c932ff6e3edcc73ba7ac8bde78af8ee")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "3b4122fc16d9246ccf3a6edd7de721c0a81446be1fae445e1ce9ef84d71bebf5faad2b26ee8dc316f4b8f1ca638db64071b93d156844d3f6d4e0b82d8807b0f4")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 128,
        scrypt: ScryptOptions { n: 1 << 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, b"saltsaltsaltsalt", b"test", &Vec::new(), 5,
    "960aef828739c9e1a3c932d51b1d05fbc9fd57956b1e67bc78cabdf3aa4d8e67eb1472ef6668160040423487fe2907340b7474932f1319c7b796542f17437cd8")]

    fn derive_test(
        #[case] options: &SlowKeyOptions, #[case] salt: &[u8], #[case] secret: &[u8], #[case] offset_data: &[u8],
        #[case] offset: u32, #[case] expected: &str,
    ) {
        let kdf = SlowKey::new(options);
        let key = kdf.derive_key(salt, secret, offset_data, offset);
        assert_eq!(hex::encode(key), expected);
    }
}
