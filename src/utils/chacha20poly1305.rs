use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305 as ChaCha20Poly1305Alg, Nonce as ChaChaNonce,
};
use serde::{de::DeserializeOwned, Serialize};

pub enum Nonce<'a> {
    Random,

    #[allow(dead_code)]
    Input(&'a [u8]),
}

pub struct ChaCha20Poly1305 {
    cipher: ChaCha20Poly1305Alg,
}

impl ChaCha20Poly1305 {
    pub const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12; // 96 bits

    pub fn new(key: &[u8]) -> Self {
        if key.len() != Self::KEY_SIZE {
            panic!("key must be {} long", Self::KEY_SIZE);
        }

        ChaCha20Poly1305 {
            cipher: ChaCha20Poly1305Alg::new(key.into()),
        }
    }

    pub fn encrypt_raw(&self, nonce: Nonce, data: &[u8]) -> Vec<u8> {
        let nonce = match nonce {
            Nonce::Random => ChaCha20Poly1305Alg::generate_nonce(&mut OsRng),
            Nonce::Input(nonce) => {
                if nonce.len() != Self::NONCE_SIZE {
                    panic!("nonce must be {} long", Self::NONCE_SIZE);
                }

                *ChaChaNonce::from_slice(nonce)
            },
        };

        [nonce.as_slice(), self.cipher.encrypt(&nonce, data).unwrap().as_slice()].concat()
    }

    pub fn encrypt<T: Serialize>(&self, nonce: Nonce, data: &T) -> Vec<u8> {
        let json = serde_json::to_string(&data).unwrap();

        self.encrypt_raw(nonce, json.as_bytes())
    }

    pub fn decrypt_raw(&self, data: &[u8]) -> Vec<u8> {
        // Split the nonce and the encrypted data
        let (raw_nonce, json) = data.split_at(Self::NONCE_SIZE);

        self.cipher
            .decrypt(ChaChaNonce::from_slice(raw_nonce), json.as_ref())
            .expect("Decryption failed")
    }

    pub fn decrypt<T: DeserializeOwned>(&self, data: &[u8]) -> T {
        serde_json::from_slice(&self.decrypt_raw(data)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        b"test",
        b"9d03f80d079908f21015baec59ae7943",
        b"25b7e633332a",
        "323562376536333333333261416b626b58d8f5fc5c3fa3a694000e86db42dd82"
    )]
    #[case(
        b"test",
        b"c6f7ec9507f4b11837b4678908331bbc",
        b"9b4b1d7fa9e0",
        "39623462316437666139653086bc5dd3e046447303fe6ced204059556f0e64f0"
    )]
    #[case(
        b"test",
        b"17f06699ff05df6c42754cfa30b69966",
        b"204a6743e0a6",
        "3230346136373433653061368de44afd99f13f5df63732301fb6b847c4ca6ac5"
    )]

    fn chacha20poly1305_encrypt_test(
        #[case] data: &[u8], #[case] key: &[u8], #[case] nonce: &[u8], #[case] expected: &str,
    ) {
        let cipher = ChaCha20Poly1305::new(key);

        assert_eq!(hex::encode(cipher.encrypt_raw(Nonce::Input(nonce), data)), expected);
    }

    #[rstest]
    #[case(
        "323562376536333333333261416b626b58d8f5fc5c3fa3a694000e86db42dd82",
        b"9d03f80d079908f21015baec59ae7943",
        b"test"
    )]
    #[case(
        "39623462316437666139653086bc5dd3e046447303fe6ced204059556f0e64f0",
        b"c6f7ec9507f4b11837b4678908331bbc",
        b"test"
    )]
    #[case(
        "3230346136373433653061368de44afd99f13f5df63732301fb6b847c4ca6ac5",
        b"17f06699ff05df6c42754cfa30b69966",
        b"test"
    )]

    fn chacha20poly1305_decrypt_test(#[case] data: &str, #[case] key: &[u8], #[case] expected: &[u8]) {
        let cipher = ChaCha20Poly1305::new(key);

        assert_eq!(cipher.decrypt_raw(&hex::decode(data).unwrap()), expected);
    }
}
