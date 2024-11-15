use super::{
    channel::{Channel, DecryptError},
    dial::Dial,
    encrypted::Encrypted,
    hang_up::HangUp,
    signed::Signed,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret};

pub struct State {
    pub verifier: VerifyingKey,
    pub signer: SigningKey,

    pub introduction_public_key: PublicKey,
    pub introduction_secret_key: ReusableSecret,

    pub channels: HashMap<VerifyingKey, Channel>,
}

impl State {
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

    pub fn handshake<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        dial: &Signed<Dial>,
        csprng: &mut R,
    ) -> Result<(), ()> {
        dial.verify().map_err(|_| ())?;

        if self.channels.contains_key(&dial.verifier) {
            return Err(());
        }

        let old_sk = self.refresh_introduction_key(csprng);
        let channel_secret: SharedSecret =
            old_sk.diffie_hellman(&dial.payload.introduction_public_key);

        self.channels.insert(
            dial.verifier,
            Channel::new(channel_secret, self.verifier, dial.verifier),
        );

        Ok(())
    }

    pub fn leave(&mut self) -> Result<Signed<HangUp>, signature::Error> {
        Signed::try_sign(HangUp, &self.signer)
    }

    pub fn send(&mut self, to: &VerifyingKey, msg: &[u8]) -> Result<Encrypted, SendError> {
        let channel = self
            .channels
            .get_mut(to)
            .ok_or(SendError::ChannelNotFound)?;

        channel
            .try_encrypt(msg)
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
            .ok_or(ReceiveError::ChannelNotFound)?;

        Ok(channel.try_decrypt(msg.clone())?)
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
pub enum SendError {
    #[error("Channel not found")]
    ChannelNotFound,

    #[error("Unable to encrypt message")]
    EncryptionFailed(chacha20poly1305::Error),
}

#[derive(Debug, Clone, Error)]
pub enum ReceiveError {
    #[error("Channel not found")]
    ChannelNotFound,

    #[error(transparent)]
    DecryptionFailed(#[from] DecryptError),
}
