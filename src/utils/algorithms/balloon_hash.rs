use balloon_hash::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Balloon, Params,
};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::num::NonZero;

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BalloonHashOptions {
    s_cost: u32,
    t_cost: u32,
}

impl BalloonHashOptions {
    pub const MIN_S_COST: u32 = 1;
    pub const MAX_S_COST: u32 = u32::MAX;
    pub const DEFAULT_S_COST: u32 = 1 << 17;

    pub const MIN_T_COST: u32 = 1;
    pub const MAX_T_COST: u32 = u32::MAX;
    pub const DEFAULT_T_COST: u32 = 1;

    pub fn new(s_cost: u32, t_cost: u32) -> Self {
        if s_cost < Self::MIN_S_COST {
            panic!(
                "s_cost {} is shorter than the min length of {}",
                Self::MIN_S_COST,
                s_cost
            );
        }

        if t_cost < Self::MIN_T_COST {
            panic!(
                "t_cost {} is shorter than the min length of {}",
                Self::MIN_T_COST,
                t_cost
            );
        }

        Self { s_cost, t_cost }
    }

    pub fn s_cost(&self) -> u32 {
        self.s_cost
    }

    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }
}

impl Default for BalloonHashOptions {
    fn default() -> Self {
        Self {
            s_cost: Self::DEFAULT_S_COST,
            t_cost: Self::DEFAULT_T_COST,
        }
    }
}

pub struct BalloonHash<'a> {
    length: usize,
    balloon: Balloon<'a, Sha512>,
}

impl<'a> BalloonHash<'a> {
    pub const VERSION: &'static str = "SHA512";

    pub fn new(length: usize, opts: &BalloonHashOptions) -> Self {
        Self {
            length,
            balloon: Balloon::<Sha512>::new(
                Algorithm::Balloon,
                Params {
                    s_cost: NonZero::new(opts.s_cost).unwrap(),
                    t_cost: NonZero::new(opts.t_cost).unwrap(),
                    p_cost: NonZero::new(1).unwrap(),
                },
                None,
            ),
        }
    }

    pub fn hash(&self, salt: &SaltString, password: &[u8]) -> Vec<u8> {
        match self.balloon.hash_password(password, salt).unwrap().hash {
            Some(output) => output.as_bytes()[..self.length].to_vec(),
            None => panic!("hash_password failed!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::sodium_init::initialize;
    use rstest::rstest;

    #[rstest]
    #[case(b"salt", &Vec::new(), 64, &BalloonHashOptions::default(), "cc7166af8ebb375f3aaf6bcda5de10f460771001d3ee15fcf8b6dcea1043c5ea66b21f4d35f720bafd11098f2eb8dc506385b49f061b2450af8288a40a01e496")]
    #[case(b"salt", b"", 64, &BalloonHashOptions::new(1 << 15, 1), "92bea78baf9d5864976f533016f36c397745d1c78f9c0ddbfcd3663622a23933f191bdf487157eb5c4c3caa364b448a7128fa874066285f8ec4c21c67a9d35cc")]
    #[case(b"salt", b"test", 64, &BalloonHashOptions::default(), "c19d781cc052324839b3cf8964172723bf774823544f370096ecc02768370c99c75e008c6f9cff57898ce979f328d370a7baf573604a18ebd8ba76dded76c169")]
    #[case(b"salt", b"test", 32, &BalloonHashOptions::default(), "c19d781cc052324839b3cf8964172723bf774823544f370096ecc02768370c99")]
    #[case(b"salt", b"test", 16, &BalloonHashOptions::default(), "c19d781cc052324839b3cf8964172723")]
    #[case(b"salt", b"test", 64, &BalloonHashOptions::new(1 << 13, 1), "3e884abfc200dbbd723a7ff738a2edf2d2746b433edded07916fd1f311cef2c7358a9220e7d2468106e5d09c0e1a0fadaf3e3a2353ad6588e8c2bd0d9dee9cdd")]
    #[case(b"salt", b"test", 32, &BalloonHashOptions::new(1 << 13, 1), "3e884abfc200dbbd723a7ff738a2edf2d2746b433edded07916fd1f311cef2c7")]
    #[case(b"salt", b"test", 16, &BalloonHashOptions::new(1 << 13, 1), "3e884abfc200dbbd723a7ff738a2edf2")]
    #[case(b"salt", b"test", 64, &BalloonHashOptions::new(1 << 12, 1), "2804d7e03a92308722227d47da0136867522a55a3ba46334c2042880b1db10b573862a261a355b93295d37f9d7423c43e545114cb7a914b24058c99a49412ac7")]
    #[case(b"salt", b"test", 32, &BalloonHashOptions::new(1 << 12, 1), "2804d7e03a92308722227d47da0136867522a55a3ba46334c2042880b1db10b5")]
    #[case(b"salt", b"test", 16, &BalloonHashOptions::new(1 << 12, 1), "2804d7e03a92308722227d47da013686")]

    fn balloon_hash_test(
        #[case] salt: &[u8], #[case] password: &[u8], #[case] length: usize, #[case] opts: &BalloonHashOptions,
        #[case] expected: &str,
    ) {
        initialize();

        let balloon = BalloonHash::new(length, opts);
        let salt_string = SaltString::encode_b64(salt).unwrap();
        let key = balloon.hash(&salt_string, password);

        assert_eq!(hex::encode(key), expected);
    }
}
