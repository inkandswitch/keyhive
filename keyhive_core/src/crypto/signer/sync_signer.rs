use super::async_signer::AsyncSigner;
use crate::crypto::{
    signed::{Signed, SigningError},
    verifiable::Verifiable,
};
use ed25519_dalek::Signer;
use serde::Serialize;

pub trait SyncSigner: Verifiable {
    fn try_sign_bytes_sync(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError>;

    fn try_sign_sync<T: Serialize>(&self, payload: T) -> Result<Signed<T>, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            issuer: self.verifying_key(),
            signature: self.try_sign_bytes_sync(payload_bytes.as_slice())?,
        })
    }
}

impl SyncSigner for ed25519_dalek::SigningKey {
    fn try_sign_bytes_sync(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.try_sign(payload_bytes)
            .map_err(SigningError::SigningFailed)
    }
}

impl<T: SyncSigner> AsyncSigner for T {
    async fn try_sign_bytes_async(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.try_sign_bytes_sync(payload_bytes)
    }
}

pub trait SyncSignerBasic {
    fn try_sign_bytes_sync_basic(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError>;
}

impl<T: SyncSigner> SyncSignerBasic for T {
    fn try_sign_bytes_sync_basic(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        T::try_sign_bytes_sync(self, payload_bytes)
    }
}

pub fn try_sign_basic<S: SyncSignerBasic + ?Sized, T: Serialize>(
    signer: &S,
    issuer: ed25519_dalek::VerifyingKey,
    payload: T,
) -> Result<Signed<T>, SigningError> {
    let bytes = bincode::serialize(&payload)?;
    let signature = signer.try_sign_bytes_sync_basic(bytes.as_slice())?;
    Ok(Signed {
        signature,
        payload,
        issuer,
    })
}
