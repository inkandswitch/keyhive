use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub struct Signed<T: Clone>
where
    Vec<u8>: From<T>,
{
    pub payload: T,
    pub verifier: VerifyingKey,
    pub signature: Signature,
}

impl<T: Clone> Signed<T>
where
    Vec<u8>: From<T>,
{
    pub fn try_sign(payload: T, signer: &SigningKey) -> Result<Self, signature::Error> {
        Ok(Self {
            verifier: signer.verifying_key(),
            signature: signer.try_sign(Vec::<u8>::from(payload.clone()).as_slice())?,
            payload,
        })
    }

    pub fn verify(&self) -> Result<(), signature::Error> {
        let msg = Vec::<u8>::from(self.payload.clone());
        self.verifier.verify(msg.as_slice(), &self.signature)
    }
}
