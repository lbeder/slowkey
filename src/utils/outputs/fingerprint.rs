use crate::color_hash;
use crate::log;
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::slowkey::SlowKeyOptions;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Fingerprint {
    pub hash: [u8; 32],
}

impl Fingerprint {
    pub fn from_data(options: &SlowKeyOptions, salt: &[u8], password: &[u8]) -> Self {
        let mut data = serde_json::to_string(&options).unwrap().as_bytes().to_vec();
        data.extend_from_slice(salt);
        data.extend_from_slice(password);

        let mut sha256 = Sha256::new();
        sha256.update(data);

        Self {
            hash: sha256.finalize().into(),
        }
    }

    pub fn print(&self) {
        log!(
            "Fingerprint: {}\n",
            hex::encode(&self.hash[0..8])
                .to_uppercase()
                .with(color_hash(&self.hash))
        );
    }
}
