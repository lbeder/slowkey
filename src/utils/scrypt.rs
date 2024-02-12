use scrypt::{scrypt, Params};

#[derive(PartialEq, Debug, Clone)]
pub struct ScryptOptions {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl ScryptOptions {
    pub const MAX_LOG_N: u32 = usize::BITS;
    pub const MIN_R: u32 = 0;
    pub const MAX_R: u32 = u32::MAX;
    pub const MIN_P: u32 = 0;
    pub const MAX_P: u32 = u32::MAX;

    pub const DEFAULT_LOG_N: u8 = 20;
    pub const DEFAULT_R: u32 = 8;
    pub const DEFAULT_P: u32 = 1;

    pub fn new(log_n: u8, r: u32, p: u32) -> Self {
        if log_n as u32 > Self::MAX_LOG_N {
            panic!("log_n {} is longer than the max length of {}", Self::MAX_LOG_N, log_n);
        }

        // Note that there is no need to check if either r or p are in bounds, since both are bound by the maximum and
        // the minimum values for this type

        ScryptOptions { log_n, r, p }
    }
}

impl Default for ScryptOptions {
    fn default() -> Self {
        Self {
            log_n: Self::DEFAULT_LOG_N,
            r: Self::DEFAULT_R,
            p: Self::DEFAULT_P,
        }
    }
}
pub struct Scrypt {
    pub length: usize,
    pub opts: ScryptOptions,
}

impl Scrypt {
    pub fn new(length: usize, opts: &ScryptOptions) -> Self {
        Scrypt {
            length,
            opts: opts.clone(),
        }
    }

    pub fn hash(&self, salt: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut dk = vec![0; self.length];

        scrypt(
            secret,
            salt,
            &Params::new(self.opts.log_n, self.opts.r, self.opts.p, dk.len()).unwrap(),
            &mut dk,
        )
        .unwrap();

        dk.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&Vec::new(), &Vec::new(), 64, &ScryptOptions::default(), "d436cba148427322d47a09a84b9bbb64d5ff086545170518711f3ec6936124e0383b3f47409e0329776231b295df5038ab07b096b8717718fd6f092195bfb03a")]
    #[case(&"salt".as_bytes(), &"".as_bytes(), 64, &ScryptOptions { log_n: 15, r: 8, p: 1 }, "6e6d0720a5766a2f99679af8dbf78794d8cfe4c2b658ec82a1d005c0d54582846583ccf105fa66271ad7907868b4e3f5bb61f12b427fe0dd2c75df55afce74c1")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 64, &ScryptOptions::default(), "c91328bf58e9904c6c3aa15b26178b7ff03caf4eab382e3b9e1a335fb487c775b64ff03b82391a33b655047a632391b6216b98b2595cd82e89eaa1d9c8c2ccf5")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 32, &ScryptOptions::default(), "c91328bf58e9904c6c3aa15b26178b7ff03caf4eab382e3b9e1a335fb487c775")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 16, &ScryptOptions::default(), "c91328bf58e9904c6c3aa15b26178b7f")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 64, &ScryptOptions { log_n: 12, r: 8, p: 2 }, "3ed57e6edeae5e46f2932b6d22e0a73e47ff22c66d3acab5f0488cda26297425693b2d5cbd463c3521c8132056fb801997b915a9f8d051948a430142c7aa5855")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 32, &ScryptOptions { log_n: 12, r: 8, p: 2 }, "3ed57e6edeae5e46f2932b6d22e0a73e47ff22c66d3acab5f0488cda26297425")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 16, &ScryptOptions { log_n: 12, r: 8, p: 2 }, "3ed57e6edeae5e46f2932b6d22e0a73e")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 64, &ScryptOptions { log_n: 12, r: 16, p: 1 }, "107a4e74f205207f82c8fd0f8a4a5fbe3a485fb9509e1b839d9cb98d63649354a0d56eaad6340f2c1e92dd25a6883b51f9806b6c7980c60c1b290b96dbceec45")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 32, &ScryptOptions { log_n: 12, r: 16, p: 1 }, "107a4e74f205207f82c8fd0f8a4a5fbe3a485fb9509e1b839d9cb98d63649354")]
    #[case(&"salt".as_bytes(), &"test".as_bytes(), 16, &ScryptOptions { log_n: 12, r: 16, p: 1 }, "107a4e74f205207f82c8fd0f8a4a5fbe")]

    fn scrypt_test(
        #[case] salt: &[u8], #[case] secret: &[u8], #[case] length: usize, #[case] opts: &ScryptOptions,
        #[case] expected: &str,
    ) {
        let scrypt = Scrypt::new(length, opts);
        let key = scrypt.hash(salt, secret);

        assert_eq!(hex::encode(key), expected);
    }
}
