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

    // The "FIRST RECOMMENDED option" by RFC 9106 (https://datatracker.ietf.org/doc/html/rfc9106), but with t_cost of 2
    // instead of 1:
    pub const DEFAULT_M_COST: u32 = 1 << 21;
    pub const DEFAULT_T_COST: u32 = 2;
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
            Params::new(self.opts.m_cost, self.opts.t_cost, self.opts.p_cost, Some(self.length)).unwrap(),
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
    #[case(b"saltsalt", b"", 64, &Argon2idOptions::default(), "110a3202612f4af228ff817a5d0545c4bccfc68ec876a6330602ed8fdd3eb04367e748a38eba826dfb6bd41f54c06bfbcf3404014b6194767ca7cf4e6828fc87")]
    #[case(b"saltsalt", b"test", 64, &Argon2idOptions::default(), "9e8dc8d00570edb4e7474a3e7c59cffa828f4145081e24c87612fcd2dad526e2d942a55225c94af995fc87d554e2845f7b3449f5d86db069a94c3670a3288675")]
    #[case(b"saltsalt", b"test", 32, &Argon2idOptions::default(), "e209f7dcd8b44a509c680fa61f9204b286f221b932afc0fbf54f7d53f0f34da8")]
    #[case(b"saltsalt", b"test", 16, &Argon2idOptions::default(), "c8506852d2d0ea5d9bd43a3997304a91")]
    #[case(b"saltsalt", b"test", 64, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST * 2 }, "2ea32d06a83bbcf48e62e64570e852fe06689bffd9826f7f17ef2e6bdd30fcde4c2895d3ed56936e93fafbf980deeaa825524a6277cc597f4b13b246d907823b")]
    #[case(b"saltsalt", b"test", 32, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST * 2 }, "b5ff8b38f1871d121b97f90e1c56fbb982dd960fe6e09456720dba3e3f5302bd")]
    #[case(b"saltsalt", b"test", 16, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST, p_cost: Params::DEFAULT_P_COST * 2 }, "8ce847ad689abdbcfebf3b7a38f75fcf")]
    #[case(b"saltsalt", b"test", 64, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST * 2, p_cost: Params::DEFAULT_P_COST}, "8d8a16f98d2083e949adcfa2b66b78ad86a284a6f3bbf85a428f2f41f102a2761bb5ba3232085ae337b347174ca2057580730646b97109ebcfae18bafb9f9dce")]
    #[case(b"saltsalt", b"test", 32, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST * 2, p_cost: Params::DEFAULT_P_COST}, "0090960e76b193fb67e96ddeb68e3d9771b66e4ed16bb4d843edd2788a039d8c")]
    #[case(b"saltsalt", b"test", 16, &Argon2idOptions { m_cost: Params::DEFAULT_M_COST / 2, t_cost: Params::DEFAULT_T_COST * 2, p_cost: Params::DEFAULT_P_COST}, "5c4a7816c50c8480ae45e2a4df9c3251")]

    fn argon2_test(
        #[case] salt: &[u8], #[case] secret: &[u8], #[case] length: usize, #[case] opts: &Argon2idOptions,
        #[case] expected: &str,
    ) {
        let argon2 = Argon2id::new(length, opts);
        let key = argon2.hash(salt, secret);

        assert_eq!(hex::encode(key), expected);
    }
}
