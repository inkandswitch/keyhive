use std::cmp::Ordering;
use std::marker::PhantomData;

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
