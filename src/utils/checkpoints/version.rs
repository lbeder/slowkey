use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Version {
    V1 = 1,
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        match value {
            1 => Version::V1,
            _ => panic!("Invalid version!"),
        }
    }
}

impl From<Version> for u8 {
    fn from(version: Version) -> u8 {
        version as u8
    }
}
