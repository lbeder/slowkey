use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2 as RustArgon2, Params, Version,
};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Argon2idOptions {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2idOptions {
    pub const MIN_M_COST: u32 = Params::MIN_M_COST;
    pub const MAX_M_COST: u32 = Params::MAX_M_COST;
    pub const DEFAULT_M_COST: u32 = 1 << 21;

    pub const MIN_T_COST: u32 = Params::MIN_T_COST;
    pub const MAX_T_COST: u32 = Params::MAX_T_COST;
    pub const DEFAULT_T_COST: u32 = 2;

    pub const MIN_P_COST: u32 = Params::MIN_P_COST;
    pub const MAX_P_COST: u32 = Params::MAX_P_COST;
    pub const DEFAULT_P_COST: u32 = 1;

    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
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

        if p_cost < Self::MIN_P_COST {
            panic!(
                "p_cost {} is shorter than the min length of {}",
                Self::MIN_P_COST,
                p_cost
            );
        }

        if p_cost > Self::MAX_P_COST {
            panic!(
                "p_cost {} is greater than the max length of {}",
                Self::MAX_P_COST,
                p_cost
            );
        }

        Self { m_cost, t_cost, p_cost }
    }
}

impl Default for Argon2idOptions {
    fn default() -> Self {
        Self {
            m_cost: Self::DEFAULT_M_COST,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
        }
    }
}

pub struct Argon2id<'a> {
    argon2: RustArgon2<'a>,
}

impl<'a> Argon2id<'a> {
    pub const VERSION: Version = Version::V0x13;

    pub fn new(length: usize, opts: &Argon2idOptions) -> Self {
        Self {
            argon2: RustArgon2::new(
                Algorithm::Argon2id,
                Argon2id::VERSION,
                Params::new(opts.m_cost, opts.t_cost, opts.p_cost, Some(length)).unwrap(),
            ),
        }
    }

    pub fn hash(&self, salt: &SaltString, password: &[u8]) -> Vec<u8> {
        let res = self.argon2.hash_password(password, salt).unwrap();

        match res.hash {
            Some(output) => output.as_bytes().to_vec(),
            None => panic!("hash_password failed"),
        }
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
    #[case(b"saltsaltsaltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST, p_cost: Argon2idOptions::DEFAULT_P_COST }, "3aab062d5ba93d7da6573746f19d85c6abaa735aeac5c13c12358f1a9d16d9e87e984e245b41613079e76096062aefbccc5bc36fe6d9626b08ccbe545c7fa357")]
    #[case(b"saltsaltsaltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST, p_cost: Argon2idOptions::DEFAULT_P_COST }, "9224d42695a83bb30ef48faf18751c5e53f5f97a084d0fe7409b19a954ccedbe")]
    #[case(b"saltsaltsaltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST, p_cost: Argon2idOptions::DEFAULT_P_COST }, "844320f4c7cfce471b902a3d4848b79c")]
    #[case(b"saltsaltsaltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST}, "57033d89807061a02b859b28fa7428ef4547db408ce4c73e7bc31a4bab3359f6413a87d861eb9a43015e141d9a88866d225035e04ea1fb771c64505b5fe8660c")]
    #[case(b"saltsaltsaltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST}, "3e0d26c8b6f9c8c001e25595195d98c0e5658756dfc9c88fc5375c2295fb03bd")]
    #[case(b"saltsaltsaltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST}, "c2f48dba626afcbfe5283c3a3cba9c60")]
    #[case(b"saltsaltsaltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST * 2}, "ed114b4c0a2a7a4e9244b262bcf61ee48cf509093498ccb3b1596a3c365fd568f9fb0409d454b67bd70c518e4d1bf4ce9af819ce8b23b1c75d87294cb89c2410")]
    #[case(b"saltsaltsaltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST * 2}, "d1b91a999cd989aefe64ff99a73f1cb9ea49bbc0590e5001e755b2f32f472171")]
    #[case(b"saltsaltsaltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST* 2}, "05b1bc2ff5a8ca60d93904dcd578dad6")]

    fn argon2_test(
        #[case] salt: &[u8], #[case] password: &[u8], #[case] length: usize, #[case] opts: &Argon2idOptions,
        #[case] expected: &str,
    ) {
        let argon2 = Argon2id::new(length, opts);
        let key = argon2.hash(&SaltString::encode_b64(salt).unwrap(), password);

        assert_eq!(hex::encode(key), expected);
    }
}
