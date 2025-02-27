use super::sync_signer::SyncSignerBasic;
use crate::crypto::verifiable::Verifiable;
use derive_more::{From, Into};
use std::future::Future;

#[derive(Debug, From, Into)]
pub struct EphemeralSigner(ed25519_dalek::SigningKey);

impl EphemeralSigner {
    pub fn with_signer<T, R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
        f: impl FnOnce(ed25519_dalek::VerifyingKey, Box<dyn SyncSignerBasic>) -> T,
    ) -> (T, ed25519_dalek::VerifyingKey) {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        let vk = sk.verifying_key();
        (f(vk, Box::new(sk)), vk)
    }

    pub async fn with_signer_async<
        T,
        R: rand::CryptoRng + rand::RngCore,
        Fut: Future<Output = T>,
    >(
        csprng: &mut R,
        f: impl FnOnce(
            ed25519_dalek::VerifyingKey,
            Box<dyn ed25519_dalek::Signer<ed25519_dalek::Signature>>,
        ) -> Fut,
    ) -> (Fut, ed25519_dalek::VerifyingKey) {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        let vk = sk.verifying_key();
        (f(vk, Box::new(sk)), vk)
    }
}

impl ed25519_dalek::Signer<ed25519_dalek::Signature> for EphemeralSigner {
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError> {
        self.0.try_sign(msg)
    }
}

impl Verifiable for EphemeralSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
