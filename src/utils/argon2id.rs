use libsodium_sys::{crypto_pwhash_ALG_ARGON2ID13, crypto_pwhash_argon2id};

#[derive(PartialEq, Debug, Clone)]
pub struct Argon2idOptions {
    pub m_cost: u32,
    pub t_cost: u32,
}

impl Argon2idOptions {
    pub const MIN_M_COST: u32 = 8;
    pub const MAX_M_COST: u32 = u32::MAX;
    pub const DEFAULT_M_COST: u32 = 1 << 21;

    pub const MIN_T_COST: u32 = 2;
    pub const MAX_T_COST: u32 = u32::MAX;
    pub const DEFAULT_T_COST: u32 = 2;

    pub fn new(m_cost: u32, t_cost: u32) -> Self {
        if m_cost < Self::MIN_M_COST {
            panic!(
                "m_cost {} is shorter than the min length of {}",
                Self::MIN_M_COST,
                m_cost
            );
        }

        // Note that there is no need to check if m_cost > Self::MAX_M_COST because Self::MAX_M_COST is the maximum
        // value for this type

        if t_cost < Self::MIN_T_COST {
            panic!(
                "t_cost {} is shorter than the min length of {}",
                Self::MIN_T_COST,
                t_cost
            );
        }

        // Note that there is no need to check if t_cost > Self::MAX_T_COST because Self::MAX_T_COST is the maximum
        // value for this type

        Self { m_cost, t_cost }
    }
}

impl Default for Argon2idOptions {
    fn default() -> Self {
        Self {
            m_cost: Self::DEFAULT_M_COST,
            t_cost: Self::DEFAULT_T_COST,
        }
    }
}

pub struct Argon2id {
    length: usize,
    opts: Argon2idOptions,
}

impl Argon2id {
    pub const VERSION: u8 = 0x13;
    const BYTES_IN_KIB: usize = 1024;

    pub fn new(length: usize, opts: &Argon2idOptions) -> Self {
        Self {
            length,
            opts: opts.clone(),
        }
    }

    pub fn hash(&self, salt: &[u8], password: &[u8]) -> Vec<u8> {
        let mut dk = vec![0; self.length];

        unsafe {
            let ret = crypto_pwhash_argon2id(
                dk.as_mut_ptr(),
                dk.len() as u64,
                password.as_ptr() as *const _,
                password.len() as u64,
                salt.as_ptr(),
                self.opts.t_cost as u64,
                (self.opts.m_cost as usize) * Self::BYTES_IN_KIB,
                crypto_pwhash_ALG_ARGON2ID13 as i32,
            );

            if ret != 0 {
                println!("crypto_pwhash_argon2id failed with: {ret}");
            }
        }

        dk.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(b"saltsaltsaltsalt", b"", 64, &Argon2idOptions::default(), "a43c6186cdd281634715d061841de2781c2c12fa968bd94de8c2cc0e1aeb6b31472681caeca9ea5a4c355350949258bb3877918efcbf9de9be10c8169a364793")]
    #[case(b"saltsaltsaltsalt", b"test", 64, &Argon2idOptions::default(), "b545c20926e06955c505deb14c01ca8126fb9e167470393797bc3627e46a232f9e16186a26e197eb58f6c4ec2e3897f366b32846040eb5715be6427a8f04233c")]
    #[case(b"saltsaltsaltsalt", b"test", 32, &Argon2idOptions::default(), "a9db18ddae667012b832af543436a77de985cd51de591e2b3916a73198ce5940")]
    #[case(b"saltsaltsaltsalt", b"test", 16, &Argon2idOptions::default(), "2b5ccde09d4c345912874cb0a4b15b54")]
    #[case(b"saltsaltsaltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST }, "3aab062d5ba93d7da6573746f19d85c6abaa735aeac5c13c12358f1a9d16d9e87e984e245b41613079e76096062aefbccc5bc36fe6d9626b08ccbe545c7fa357")]
    #[case(b"saltsaltsaltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST }, "9224d42695a83bb30ef48faf18751c5e53f5f97a084d0fe7409b19a954ccedbe")]
    #[case(b"saltsaltsaltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST }, "844320f4c7cfce471b902a3d4848b79c")]
    #[case(b"saltsaltsaltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2}, "57033d89807061a02b859b28fa7428ef4547db408ce4c73e7bc31a4bab3359f6413a87d861eb9a43015e141d9a88866d225035e04ea1fb771c64505b5fe8660c")]
    #[case(b"saltsaltsaltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2}, "3e0d26c8b6f9c8c001e25595195d98c0e5658756dfc9c88fc5375c2295fb03bd")]
    #[case(b"saltsaltsaltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2}, "c2f48dba626afcbfe5283c3a3cba9c60")]

    fn argon2_test(
        #[case] salt: &[u8], #[case] password: &[u8], #[case] length: usize, #[case] opts: &Argon2idOptions,
        #[case] expected: &str,
    ) {
        let argon2 = Argon2id::new(length, opts);
        let key = argon2.hash(salt, password);

        assert_eq!(hex::encode(key), expected);
    }
}
