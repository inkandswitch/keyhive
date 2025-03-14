use std::time::Duration;

use ed25519_dalek::VerifyingKey;

use crate::loading;

pub struct Config<R> {
    pub(crate) verifying_key: VerifyingKey,
    pub(crate) rng: R,
}

impl<R: rand::Rng + rand::CryptoRng> Config<R> {
    pub fn new(rng: R, verifying_key: VerifyingKey) -> Self {
        Config {
            verifying_key,
            rng,
        }
    }
}
