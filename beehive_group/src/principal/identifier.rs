// FIXME move to ActorId?

use super::traits::Verifiable;
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            BASE64_STANDARD.encode(&self.verifying_key.to_bytes())
        )
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifying_key
            .as_bytes()
            .partial_cmp(&other.verifying_key.as_bytes())
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifying_key
            .as_bytes()
            .cmp(&other.verifying_key.as_bytes())
    }
}

impl Verifiable for Identifier {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.verifying_key
    }
}

impl From<ed25519_dalek::VerifyingKey> for Identifier {
    fn from(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl Identifier {
    pub fn new(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self { verifying_key }
    }

    pub fn generate() -> Self {
        Self {
            verifying_key: ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
                .verifying_key(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }
}

// #[derive(Debug, Clone, Hash)]
// pub struct Identifier<T> {
//     pub verifying_key: ed25519_dalek::VerifyingKey,
//     _phantom: std::marker::PhantomData<T>,
// }
//
// impl<T> PartialEq for Identifier<T> {
//     fn eq(&self, other: &Self) -> bool {
//         self.verifying_key.as_bytes() == other.verifying_key.as_bytes()
//     }
// }
//
// impl<T> Eq for Identifier<T> {}
//
// impl<T> PartialOrd for Identifier<T> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         self.verifying_key
//             .as_bytes()
//             .partial_cmp(&other.verifying_key.as_bytes())
//     }
// }
//
// impl<T> Ord for Identifier<T> {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.verifying_key
//             .as_bytes()
//             .cmp(&other.verifying_key.as_bytes())
//     }
// }
