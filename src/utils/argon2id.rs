use argon2::{Algorithm, Argon2, Params, Version};

#[derive(PartialEq, Debug, Clone)]
pub struct Argon2idOptions {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2idOptions {
    pub const MIN_M_COST: u32 = Params::MIN_M_COST;
    pub const MAX_M_COST: u32 = Params::MAX_M_COST;

    pub const MIN_T_COST: u32 = Params::MIN_T_COST;
    pub const MAX_T_COST: u32 = Params::MAX_T_COST;

    pub const MIN_P_COST: u32 = Params::MIN_P_COST;
    pub const MAX_P_COST: u32 = Params::MAX_P_COST;

    // The "FIRST RECOMMENDED option" by RFC 9106 ():
    pub const DEFAULT_M_COST: u32 = 1 << 21;
    pub const DEFAULT_T_COST: u32 = 1;
    pub const DEFAULT_P_COST: u32 = 4;

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
                "p_cost {} is longer than the max length of {}",
                Self::MAX_P_COST,
                p_cost
            );
        }

        Argon2idOptions { m_cost, t_cost, p_cost }
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

pub struct Argon2id {
    pub length: usize,
    pub opts: Argon2idOptions,
}

impl Argon2id {
    pub const VERSION: Version = Version::V0x13;

    pub fn new(length: usize, opts: &Argon2idOptions) -> Self {
        Argon2id {
            length,
            opts: opts.clone(),
        }
    }

    pub fn hash(&self, salt: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut dk = vec![0; self.length];

        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Self::VERSION,
            Params::new(self.opts.m_cost, self.opts.t_cost, self.opts.t_cost, Some(self.length)).unwrap(),
        );

        argon2.hash_password_into(secret, salt, &mut dk).unwrap();

        dk.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&"saltsalt".as_bytes(), &"".as_bytes(), 64, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST}, "8ba3b2729636801d72b72378e9b3498218a9698c1e0c352135828b2025679c437447ac2cfd2d77d557a318191d577030d672a5f70777d83eac7200fbe70fc581")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 64, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST}, "090bf49aedef873885c7bf3fd7e74601f49e21561249c79f635a8772e10850a1428ece0d8137a87a3ea3982cd1eeff3cf5dc66addcf8fb958efce6ad2056408e")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 32, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST}, "b07e2a24dfefb87bfe1e0b05a3470534da9ec3c3639d3a63e53269023fc4f54c")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 16, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST}, "3122fe683f4c0ea968ba9e9e6a1e95a2")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 64, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST * 2 }, "2ea32d06a83bbcf48e62e64570e852fe06689bffd9826f7f17ef2e6bdd30fcde4c2895d3ed56936e93fafbf980deeaa825524a6277cc597f4b13b246d907823b")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 32, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST * 2 }, "b5ff8b38f1871d121b97f90e1c56fbb982dd960fe6e09456720dba3e3f5302bd")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 16, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST * 2 }, "8ce847ad689abdbcfebf3b7a38f75fcf")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 64, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST * 2, p_cost: Params::DEFAULT_P_COST}, "42fafed10f874cd668d243a59c8971b66c345acf54cb130cfc179ea89fac680fe4a35f6c46c248c8c48129f1ada19d2116108a9dbcd68d33e1e7060ce0b1ad7b")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 32, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST * 2, p_cost: Params::DEFAULT_P_COST}, "0147b1acc940c244a661f99d7b02df81c5079981b45046f181a1232871ed06d1")]
    #[case(&"saltsalt".as_bytes(), &"test".as_bytes(), 16, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST * 2, p_cost: Params::DEFAULT_P_COST}, "9a73b0d65a1444c9fee635e11ac24594")]

    fn argon2_test(
        #[case] salt: &[u8], #[case] secret: &[u8], #[case] length: usize, #[case] opts: &Argon2idOptions,
        #[case] expected: &str,
    ) {
        let argon2 = Argon2id::new(length, opts);
        let key = argon2.hash(salt, secret);

        assert_eq!(hex::encode(key), expected);
    }
}
