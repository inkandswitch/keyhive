pub mod state;

use super::identifier::Identifier;
use super::traits::Verifiable;
use crate::crypto::hash::Hash;
use crate::crypto::share_key::ShareKey;
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use state::PrekeyState;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Individual {
    pub id: Identifier,
    pub prekeys: BTreeSet<ShareKey>,
    pub prekey_state: PrekeyState,
}

impl std::fmt::Display for Individual {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.id.to_bytes()))
    }
}

impl From<VerifyingKey> for Individual {
    fn from(verifier: VerifyingKey) -> Self {
        Individual {
            id: verifier.into(),
            prekeys: BTreeSet::new(),
            prekey_state: PrekeyState::new(),
        }
    }
}

impl From<Identifier> for Individual {
    fn from(id: Identifier) -> Self {
        Individual {
            id,
            prekeys: BTreeSet::new(),
            prekey_state: PrekeyState::new(),
        }
    }
}

pub struct IndividualOp {
    pub verifier: VerifyingKey,
    pub op: ReadKeyOp,
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

#[cfg(test)]
mod tests {
    use super::*;

    // FIXME proptest

    #[test]
    fn test_to_bytes() {
        let id = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();

        let individual: Individual = id.into();
        assert_eq!(individual.id.to_bytes(), id.to_bytes());
    }
}
