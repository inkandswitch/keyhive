use ed25519_dalek::Signer;
use base64::prelude::*;
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub payload: T,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub signature: ed25519_dalek::Signature,
}

impl<T: fmt::Display> fmt::Display for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Signed {{ payload: {}, verifying_key: {}, signature: {} }}",
            self.payload,
            BASE64_STANDARD.encode(self.verifying_key.as_bytes()),
            self.signature
        )
    }
}

impl<T: Clone> Signed<T>
where
    Vec<u8>: From<T>,
{
    pub fn verify(&self) -> Result<(), signature::Error> {
        self.verifying_key
            // FIXME                            vvvvvvvv
            .verify(
                Vec::<u8>::from(self.payload.clone()).as_slice(),
                &self.signature,
            )
    }
}

impl<T> From<Signed<T>> for Vec<u8>
where
    Vec<u8>: From<T>,
{
    fn from(signed: Signed<T>) -> Self {
        let mut buf: Vec<u8> = signed.payload.into();
        buf.append(&mut signed.verifying_key.to_bytes().to_vec());
        buf.append(&mut signed.signature.to_vec());
        buf
    }
}

impl<T: PartialOrd> PartialOrd for Signed<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self
            .verifying_key
            .as_bytes()
            .partial_cmp(other.verifying_key.as_bytes())
        {
            Some(Ordering::Equal) => match self
                .signature
                .to_bytes()
                .partial_cmp(&other.signature.to_bytes())
            {
                Some(Ordering::Equal) => self.payload.partial_cmp(&other.payload),
                unequal => unequal,
            },
            unequal => unequal,
        }
    }
}

impl<T: Ord> Ord for Signed<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .verifying_key
            .as_bytes()
            .cmp(&other.verifying_key.as_bytes())
        {
            Ordering::Equal => match self.signature.to_bytes().cmp(&other.signature.to_bytes()) {
                Ordering::Equal => self.payload.cmp(&other.payload),
                unequal => unequal,
            },
            unequal => unequal,
        }
    }
}

// FIXME might need to be Vec<u8>: From<T>
impl<T: Hash> Hash for Signed<T> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.payload.hash(state);
        self.verifying_key.hash(state);
        self.signature.to_vec().hash(state);
    }
}

// FIXME also put this on Active
// FIXME move to Active
impl<T: Clone + Into<Vec<u8>>> Signed<T> {
    pub fn sign(payload: T, signer: &ed25519_dalek::SigningKey) -> Self {
        let payload_bytes: Vec<u8> = payload.clone().into();

        Signed {
            payload,
            verifying_key: signer.verifying_key(),
            signature: signer.sign(payload_bytes.as_slice()),
        }
    }

    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            verifying_key: self.verifying_key,
            signature: self.signature,
        }
    }
}

// impl<T: PartialOrd> PartialOrd for Signed<T> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {}
// }
