use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed<T>
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
        let mut to_sign: Vec<u8> = payload.clone().into();
        to_sign.extend(signer.verifying_key().as_bytes());

        Ok(Self {
            verifier: signer.verifying_key(),
            signature: signer.try_sign(to_sign.as_slice())?,
            payload,
        })
    }

    pub fn verify(&self) -> Result<(), signature::Error> {
        let msg = Vec::<u8>::from(self.payload.clone());
        self.verifier.verify(msg.as_slice(), &self.signature)
    }
}

impl<T: Clone> From<Signed<T>> for Vec<u8>
where
    Vec<u8>: From<T>,
{
    fn from(signed: Signed<T>) -> Self {
        let mut bytes: Vec<u8> = signed.payload.clone().into();
        bytes.extend(signed.verifier.as_bytes());
        bytes.extend(signed.signature.to_bytes());
        bytes
    }
}

impl<T: Clone> Hash for Signed<T>
where
    Vec<u8>: From<T>,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        Vec::<u8>::from(self.payload.clone()).hash(state);
        self.verifier.as_bytes().hash(state);
        self.signature.to_bytes().hash(state);
    }
}
