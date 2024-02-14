use argon2_kdf::{Algorithm, Hasher};

#[derive(PartialEq, Debug, Clone)]
pub struct Argon2idOptions {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2idOptions {
    pub const MIN_M_COST: u32 = 8;
    pub const MAX_M_COST: u32 = u32::MAX;

    pub const MIN_T_COST: u32 = 2;
    pub const MAX_T_COST: u32 = u32::MAX;

    pub const MIN_P_COST: u32 = 1;
    pub const MAX_P_COST: u32 = 0xFFFFFF;

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
    length: usize,
    opts: Argon2idOptions,
}

impl Argon2id {
    pub const VERSION: u8 = 0x13;

    pub fn new(length: usize, opts: &Argon2idOptions) -> Self {
        Argon2id {
            length,
            opts: opts.clone(),
        }
    }

    pub fn hash(&self, salt: &[u8], secret: &[u8]) -> Vec<u8> {
        let argon2 = Hasher::new()
            .algorithm(Algorithm::Argon2id)
            .salt_length(salt.len() as u32)
            .hash_length(self.length as u32)
            .memory_cost_kib(self.opts.m_cost)
            .iterations(self.opts.t_cost)
            .threads(self.opts.p_cost)
            .custom_salt(salt);

        argon2.hash(secret).unwrap().as_bytes().to_vec()
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
    #[case(b"saltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST, p_cost: Argon2idOptions::DEFAULT_P_COST * 2 }, "f87fd3a6cf5b64651805dc9a1f480f83797be5b5c8da98ab596973d91d6b42af268e1f1a70a424b0201307ae62f8a191ce25e2eafc2ef9555a4ff4de5241dd46")]
    #[case(b"saltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST, p_cost: Argon2idOptions::DEFAULT_P_COST * 2 }, "cace633b8a7e5ee4c4884792a75ed565a017fc92600098914db8ebbcf2f61390")]
    #[case(b"saltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST, p_cost: Argon2idOptions::DEFAULT_P_COST * 2 }, "6802f05eb7ec1d3ea0b41b082b5090ad")]
    #[case(b"saltsalt", b"test", 64, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST}, "2592ec8929f796cd8f37b2b5474c6bf281cf399e37665fe336cf239cbd7872faa5a441385086d14c1e94eabf52a2349d9a770613a0302fe67416642c8882bb48")]
    #[case(b"saltsalt", b"test", 32, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST}, "cfb1300fc376ce9fffc09e6796080b2d9d8b50bf05a46c4ba42e2b180b28a2be")]
    #[case(b"saltsalt", b"test", 16, &Argon2idOptions { m_cost: Argon2idOptions::DEFAULT_M_COST / 2, t_cost: Argon2idOptions::DEFAULT_T_COST * 2, p_cost: Argon2idOptions::DEFAULT_P_COST}, "500ae20a3e4356b34b2a89f72d1ddc50")]

    fn argon2_test(
        #[case] salt: &[u8], #[case] secret: &[u8], #[case] length: usize, #[case] opts: &Argon2idOptions,
        #[case] expected: &str,
    ) {
        let argon2 = Argon2id::new(length, opts);
        let key = argon2.hash(salt, secret);

        assert_eq!(hex::encode(key), expected);
    }
}
