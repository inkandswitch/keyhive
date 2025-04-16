use std::time::Duration;

use ed25519_dalek::VerifyingKey;


pub struct Config<R> {
    pub(crate) session_duration: Duration,
    pub(crate) verifying_key: VerifyingKey,
    pub(crate) rng: R,
}

impl<R: rand::Rng + rand::CryptoRng> Config<R> {
    pub fn new(rng: R, verifying_key: VerifyingKey) -> Self {
        Config {
            session_duration: Duration::from_secs(5 * 60),
            verifying_key,
            rng,
        }
    }

    pub fn session_duration(self, session_duration: Duration) -> Self {
        Self {
            session_duration,
            rng: self.rng,
            verifying_key: self.verifying_key,
        }
    }
}
