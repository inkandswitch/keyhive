use ed25519_dalek::Signer;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    pub payload: T,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub signature: ed25519_dalek::Signature,
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

// FIXME move to Active
impl<T: Clone + Into<Vec<u8>>> Signed<T> {
    pub fn sign(payload: &T, signer: &ed25519_dalek::SigningKey) -> Self {
        let payload_bytes: Vec<u8> = payload.clone().into();

        Signed {
            payload: payload.clone(), // FIXME weird clone
            verifying_key: signer.verifying_key(),
            signature: signer.sign(payload_bytes.as_slice()),
        }
    }
}

// impl<T: PartialOrd> PartialOrd for Signed<T> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {}
// }

pub struct Encrypted<T> {
    pub nonce: [u8; 24],
    // FIXME pub additional_data
    pub ciphertext: Vec<u8>,
    pub _phantom: PhantomData<T>, // FIXME not public
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SharingPublicKey {
    pub key: x25519_dalek::PublicKey,
}

impl PartialOrd for SharingPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.key.as_bytes().partial_cmp(other.key.as_bytes())
    }
}

impl Ord for SharingPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.as_bytes().cmp(other.key.as_bytes())
    }
}
