use crate::color_hash;
use crate::log;
use crate::slowkey::SlowKeyOptions;
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Fingerprint {
    pub hash: [u8; 32],
}

impl Fingerprint {
    pub fn from_data(options: &SlowKeyOptions, salt: &[u8], password: &[u8]) -> Self {
        let json_str = Self::build_options_json(options);
        let mut data = json_str.as_bytes().to_vec();
        data.extend_from_slice(salt);
        data.extend_from_slice(password);

        let mut sha256 = Sha256::new();
        sha256.update(data);

        Self {
            hash: sha256.finalize().into(),
        }
    }

    /// Build JSON representation of SlowKeyOptions in struct field order,
    /// excluding the scrypt implementation field to ensure fingerprint consistency.
    fn build_options_json(options: &SlowKeyOptions) -> String {
        // Build scrypt JSON without the implementation field
        let scrypt_json = format!(
            r#"{{"log_n":{},"r":{},"p":{}}}"#,
            options.scrypt.log_n(),
            options.scrypt.r(),
            options.scrypt.p(),
        );

        // Serialize nested structs
        let argon2id_json = serde_json::to_string(&options.argon2id).unwrap();
        let balloon_hash_json = serde_json::to_string(&options.balloon_hash).unwrap();

        // Construct JSON in struct field order: iterations, length, scrypt, argon2id, balloon_hash
        // This ensures deterministic field ordering matching the original serialization format
        format!(
            r#"{{"iterations":{},"length":{},"scrypt":{},"argon2id":{},"balloon_hash":{}}}"#,
            options.iterations, options.length, scrypt_json, argon2id_json, balloon_hash_json,
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slowkey::SlowKeyOptions;
    use crate::utils::algorithms::{
        argon2id::Argon2idOptions,
        balloon_hash::BalloonHashOptions,
        scrypt::{ScryptImplementation, ScryptOptions},
    };
    use rstest::rstest;

    #[rstest]
    // Default parameters
    #[case(
        SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::default(),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        ),
        b"saltsaltsaltsalt",
        b"password",
        "438AD0BD7EF347F5"
    )]
    // Different iterations
    #[case(
        SlowKeyOptions::new(
            1,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::default(),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        ),
        b"saltsaltsaltsalt",
        b"password",
        "461888E142FF6A1F"
    )]
    // Different length
    #[case(
        SlowKeyOptions::new(
            10,
            64,
            &ScryptOptions::default(),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        ),
        b"saltsaltsaltsalt",
        b"password",
        "7525EE9EC43555AB"
    )]
    // Different scrypt parameters
    #[case(
        SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::new(15, 16, 2),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        ),
        b"saltsaltsaltsalt",
        b"password",
        "F20172DE0FBE021A"
    )]
    // Different argon2id parameters
    #[case(
        SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::default(),
            &Argon2idOptions::new(1 << 20, 3),
            &BalloonHashOptions::default(),
        ),
        b"saltsaltsaltsalt",
        b"password",
        "558B8CF9ADF7F9E1"
    )]
    // Different balloon_hash parameters
    #[case(
        SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::default(),
            &Argon2idOptions::default(),
            &BalloonHashOptions::new(1 << 16, 2),
        ),
        b"saltsaltsaltsalt",
        b"password",
        "5DA7A009CAB90E5D"
    )]
    // Different salt
    #[case(
        SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::default(),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        ),
        b"different_salt_16",
        b"password",
        "BA8A4339906FAEBB"
    )]
    // Different password
    #[case(
        SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::default(),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        ),
        b"saltsaltsaltsalt",
        b"different_password",
        "350BB43A0C831894"
    )]
    // All parameters different
    #[case(
        SlowKeyOptions::new(
            5,
            16,
            &ScryptOptions::new(12, 4, 1),
            &Argon2idOptions::new(1 << 19, 4),
            &BalloonHashOptions::new(1 << 15, 3),
        ),
        b"test_salt_16_byte",
        b"test_password",
        "05EE12FCAA5A5BFB"
    )]
    fn fingerprint_test(
        #[case] options: SlowKeyOptions, #[case] salt: &[u8], #[case] password: &[u8], #[case] expected: &str,
    ) {
        let fingerprint = Fingerprint::from_data(&options, salt, password);

        // Check first 8 bytes of hash
        let first_8_bytes = hex::encode(&fingerprint.hash[0..8]).to_uppercase();
        assert_eq!(first_8_bytes, expected, "Fingerprint hash mismatch");
    }

    #[test]
    fn fingerprint_implementation_independent() {
        // Verify that the scrypt implementation field doesn't affect the fingerprint
        let salt = b"saltsaltsaltsalt";
        let password = b"password";

        let options_libsodium = SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::new_with_implementation(
                ScryptOptions::DEFAULT_LOG_N,
                ScryptOptions::DEFAULT_R,
                ScryptOptions::DEFAULT_P,
                ScryptImplementation::Libsodium,
            ),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        );

        let options_rust_crypto = SlowKeyOptions::new(
            10,
            SlowKeyOptions::DEFAULT_OUTPUT_SIZE,
            &ScryptOptions::new_with_implementation(
                ScryptOptions::DEFAULT_LOG_N,
                ScryptOptions::DEFAULT_R,
                ScryptOptions::DEFAULT_P,
                ScryptImplementation::RustCrypto,
            ),
            &Argon2idOptions::default(),
            &BalloonHashOptions::default(),
        );

        let fingerprint_libsodium = Fingerprint::from_data(&options_libsodium, salt, password);
        let fingerprint_rust_crypto = Fingerprint::from_data(&options_rust_crypto, salt, password);

        // Both should produce the same fingerprint since implementation is excluded
        assert_eq!(
            fingerprint_libsodium.hash, fingerprint_rust_crypto.hash,
            "Fingerprint should be the same regardless of scrypt implementation"
        );
    }
}
