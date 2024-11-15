//! The high level API for pairwise channels.

use super::{
    dial::Dial,
    encrypted::Encrypted,
    hang_up::HangUp,
    session::{DecryptError, Session},
    signed::Signed,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, ReusableSecret};

pub struct Manager {
    /// The manager's verifying key.
    pub verifier: VerifyingKey,

    /// The manager's signing key.
    pub signer: SigningKey,

    /// Latest introduction public key.
    ///
    /// This value is rotated on each connection attempt.
    pub introduction_public_key: PublicKey,

    /// Latest introduction secret key.
    ///
    /// Despite how the type is named, this value is rotated on each connection attempt.
    pub introduction_secret_key: ReusableSecret,

    /// The channels managed by this manager.
    pub channels: HashMap<VerifyingKey, Session>,
}

impl Manager {
    pub fn new<R: rand::CryptoRng + rand::RngCore + Clone>(csprng: &mut R) -> Self {
        let introduction_secret_key = ReusableSecret::random_from_rng(csprng.clone());
        let signer = SigningKey::generate(csprng);

        Self {
            verifier: VerifyingKey::from(&signer),
            signer,

            introduction_public_key: PublicKey::from(&introduction_secret_key),
            introduction_secret_key,

            channels: HashMap::new(),
        }
    }

    pub fn dial<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        to: &VerifyingKey,
        csprng: &mut R,
    ) -> Result<Signed<Dial>, signature::Error> {
        let old_sk = self.refresh_introduction_key(csprng);

        let dial = Dial {
            to: *to,
            introduction_public_key: PublicKey::from(&old_sk),
        };

        Signed::try_sign(dial, &self.signer)
    }

    pub fn handshake<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        dial: &Signed<Dial>,
        csprng: &mut R,
    ) -> Result<(), HandshakeError> {
        dial.verify()
            .map_err(|_| HandshakeError::InvalidSignature)?;

        if self.channels.contains_key(&dial.verifier) {
            return Err(HandshakeError::DuplicateSession);
        }

        let old_sk = self.refresh_introduction_key(csprng);
        self.channels.insert(
            dial.verifier,
            Session::new(&old_sk, &dial.payload.introduction_public_key),
        );

        Ok(())
    }

    pub fn leave(&mut self) -> Result<Signed<HangUp>, signature::Error> {
        Signed::try_sign(HangUp, &self.signer)
    }

    pub fn remove(&mut self, verifier: &VerifyingKey) -> Option<Session> {
        self.channels.remove(verifier)
    }

    pub fn send(&mut self, to: &VerifyingKey, msg: &[u8]) -> Result<Encrypted, SendError> {
        let channel = self
            .channels
            .get_mut(to)
            .ok_or(SendError::SessionNotFound)?;

        channel
            .try_encrypt(&self.verifier, msg)
            .map_err(SendError::EncryptionFailed)
    }

    pub fn receive(
        &mut self,
        from: &VerifyingKey,
        msg: &Encrypted,
    ) -> Result<Vec<u8>, ReceiveError> {
        let channel = self
            .channels
            .get_mut(&from)
            .ok_or(ReceiveError::SessionNotFound)?;

        Ok(channel.try_decrypt(from, msg.clone())?)
    }

    pub fn refresh_introduction_key<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> ReusableSecret {
        let eph_sec = self.introduction_secret_key.clone();
        self.introduction_secret_key = ReusableSecret::random_from_rng(csprng);
        self.introduction_public_key = PublicKey::from(&self.introduction_secret_key);
        eph_sec
    }
}

#[derive(Debug, Clone, Error)]
pub enum HandshakeError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Duplicate session")]
    DuplicateSession,
}

#[derive(Debug, Clone, Error)]
pub enum SendError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Unable to encrypt message")]
    EncryptionFailed(chacha20poly1305::Error),
}

#[derive(Debug, Clone, Error)]
pub enum ReceiveError {
    #[error("Session not found")]
    SessionNotFound,

    #[error(transparent)]
    DecryptionFailed(#[from] DecryptError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup() {
        let m = Manager::new(&mut rand::thread_rng());
        assert_eq!(m.channels.len(), 0);
    }

    #[test]
    fn test_dial() {
        let mut m1 = Manager::new(&mut rand::thread_rng());
        let m2 = Manager::new(&mut rand::thread_rng());

        let intro_key = m1.introduction_public_key.clone();
        let d = m1.dial(&m2.verifier, &mut rand::thread_rng()).unwrap();

        assert!(d.verify().is_ok());
        assert_eq!(d.payload.to, m2.verifier);
        assert_eq!(d.payload.introduction_public_key, intro_key);
        assert!(m1.channels.is_empty());
    }

    #[test]
    fn test_handshake() {
        let mut m1 = Manager::new(&mut rand::thread_rng());
        let mut m2 = Manager::new(&mut rand::thread_rng());

        let d = m1.dial(&m2.verifier, &mut rand::thread_rng()).unwrap();
        m2.handshake(&d, &mut rand::thread_rng()).unwrap();

        assert!(m2.channels.contains_key(&m1.verifier));
    }
}
