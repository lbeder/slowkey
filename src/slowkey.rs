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
            salt: "SlowKeySalt".as_bytes().to_vec(),
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
            salt: "SlowKeySalt".as_bytes().to_vec(),
            secret: "Hello World".as_bytes().to_vec(),
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
        let mut res: Vec<u8> = secret.to_vec();

        if offset != 0 {
            res = offset_data.to_vec();
        }

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
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].secret, &TEST_VECTORS[0].offset_data, TEST_VECTORS[0].offset, "87b358f9513d06d943ed59915f140b42f39393536112c09eb4b29b86eb33c6422de5f27b53bc527f7ff8e2cbd1512cb4f890882d5103eb6640de7b8c32261063")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].secret, &TEST_VECTORS[1].offset_data, TEST_VECTORS[1].offset, "c68c8a6dff34f44655a70dca9618680e10940630f153123670630f1342f86d0407f48bd6588e36914ff9bbeb3e22849fcbdfeba62d979e2d4cfc10975a6ab2e1")]
    #[case(&SlowKeyOptions {
        iterations: 1,
        length: 64,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 0,
    "72f47a5f6bcb1b96a9d77b2c2f1463395d4a3a325fada6290fc0fef7bcddb58eb46e36a0d944613790c2e7bc9ea0e8447b9c4b493734c43526a14963e4a56bdc")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { log_n: 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 0,
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions::default(),
        argon2id: Argon2idOptions { m_cost: 16, t_cost: 2, p_cost: 2 }
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 0,
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { log_n: 20, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 0,
    "bd13f3cba884d87aeb68ca53efcd65175af1ee9d60907cf71d91e6bbddfa95ee7fb4d48442e54c8a28ac1d02298cdd793618827755ca69704b6cb9ec2b1e2f8e")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &Vec::new(), &"test".as_bytes(), &Vec::new(), 0,
    "8c18f4925f57caa69143d178e48d9a559963b045e413dc30ff02fd1c3c9ba1c5a5bf684aaf2aceb4fbc2eef11f4f9ac71b837b68797dc9c19062653b3e96664a")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &Vec::new(), &Vec::new(), &Vec::new(), 0,
    "7cb7f9c94b25bbf9afa023d20340bff9164658ccce3f09b164b5ce7130aaf84ec8fccbfc9d9de76a133218b7220da069430f40c58ef4bc53c639d5ea72b4437a")]
    #[case(&SlowKeyOptions {
        iterations: 4,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"".as_bytes(), &Vec::new(), 0,
    "9843308b393a354dd7166eab6a3da12cf324c88417899e195bc9231004acacab26c75bd0ac6b1e6d48f6f12ffd0869e485a67f4d98dd54d1d36384e94abfc11f")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 0,
    "e409d625547cb5702ade6e74460e3b90768164e0771975f3548dda809bfadcb1ae4484ca0c7c659bc9e6d9753c28dc7d1ddb9ebfadde8375045dd3cbbaa2eac7")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt2".as_bytes(), &"test".as_bytes(), &Vec::new(), 0,
    "d885f5c4c1196fc99eb97f5a08ae318d7a525dbbfdac2d5e8c8c210eb0ef2c58994cdef063463ba37caf47b6fc94693cced3ab03fefc9baf2cb05707d75767d2")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test2".as_bytes(), &Vec::new(), 0,
    "ff71c6680cd2e221a6a0d13d4527cddea71da1649d721a8392d969cc5f3bf7bc41d58cc2001296b9d985ea319473aa24813065bbaa675cb135372b1133f71d5c")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 32,
        scrypt: ScryptOptions { log_n: 12, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 1,
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e")]
    #[case(&SlowKeyOptions {
        iterations: 10,
        length: 64,
        scrypt: ScryptOptions { log_n: 15, r: 8, p: 1 },
        argon2id: Argon2idOptions::default()
    }, &"salt".as_bytes(), &"test".as_bytes(), &Vec::new(), 5,
    "e409d625547cb5702ade6e74460e3b90768164e0771975f3548dda809bfadcb1ae4484ca0c7c659bc9e6d9753c28dc7d1ddb9ebfadde8375045dd3cbbaa2eac7")]

    fn derive_test(
        #[case] options: &SlowKeyOptions, #[case] salt: &[u8], #[case] secret: &[u8], #[case] offset_data: &[u8],
        #[case] offset: u32, #[case] expected: &str,
    ) {
        let kdf = SlowKey::new(options);
        let key = kdf.derive_key(salt, secret, offset_data, offset);
        assert_eq!(hex::encode(key), expected);
    }
}
