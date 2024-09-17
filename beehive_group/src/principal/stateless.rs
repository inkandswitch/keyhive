use super::traits::Verifiable;
use crate::crypto::hash::Hash;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeSet;
// FIXME make sure Signed

// FIXME rename actor?

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stateless {
    pub verifier: VerifyingKey,
}

impl Stateless {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.verifier.to_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.verifier.as_bytes().as_slice()
    }
}

impl From<VerifyingKey> for Stateless {
    fn from(verifier: VerifyingKey) -> Self {
        Stateless { verifier }
    }
}

pub struct StatelessOp {
    pub verifier: VerifyingKey,
    pub op: ReadKeyOp, // FIXME I assume that prekeys are better than using the verifier key as a Montgomery
    pub pred: BTreeSet<Hash<Stateless>>,
}

// FIXME move to each Doc
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReadKeyOp {
    Add(AddReadKey),
    Remove(VerifyingKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddReadKey {
    pub group: VerifyingKey,
    pub key: x25519_dalek::PublicKey,
}

pub enum PrekeyOp {
    Add(VerifyingKey),
    Remove(VerifyingKey),
}

impl PartialOrd for Stateless {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

impl Ord for Stateless {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}

impl Verifiable for Stateless {
    fn verifying_key(&self) -> VerifyingKey {
        self.verifier
    }
}

// FIXME Read key ops
