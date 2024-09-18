use super::identifier::Identifier;
use super::traits::Verifiable;
use crate::crypto::hash::Hash;
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Individual {
    pub id: Identifier,
}

impl std::fmt::Display for Individual {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.id.to_bytes()))
    }
}

impl Individual {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.id.to_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.id.as_bytes().as_slice()
    }
}

impl From<VerifyingKey> for Individual {
    fn from(verifier: VerifyingKey) -> Self {
        Individual {
            id: verifier.into(),
        }
    }
}

impl From<Identifier> for Individual {
    fn from(id: Identifier) -> Self {
        Individual { id }
    }
}

pub struct IndividualOp {
    pub verifier: VerifyingKey,
    pub op: ReadKeyOp, // FIXME I assume that prekeys are better than using the verifier key as a Montgomery
    pub pred: BTreeSet<Hash<Individual>>,
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

impl PartialOrd for Individual {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.id.to_bytes().partial_cmp(&other.id.to_bytes())
    }
}

impl Ord for Individual {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.to_bytes().cmp(&other.id.to_bytes())
    }
}

impl Verifiable for Individual {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.verifying_key
    }
}
