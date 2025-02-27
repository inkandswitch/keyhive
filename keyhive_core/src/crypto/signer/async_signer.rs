use crate::crypto::{
    signed::{Signed, SigningError},
    verifiable::Verifiable,
};
use serde::Serialize;

// NOTE: we assume single-threaded async, so this can be ignored for now
#[allow(async_fn_in_trait)]
pub trait AsyncSigner: Verifiable {
    async fn try_sign_bytes_async(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError>;

    async fn try_sign_async<T: Serialize>(&self, payload: T) -> Result<Signed<T>, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            issuer: self.verifying_key(),
            signature: self.try_sign_bytes_async(payload_bytes.as_slice()).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;

    #[tokio::test]
    async fn test_round_trip() {
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let signed = sk.try_sign_async(vec![1, 2, 3]).await.unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
