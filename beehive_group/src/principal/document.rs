use super::traits::Identifiable;
use crate::hash::Hash;
use crate::operation::Operation;
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Document {
    pub verifier: VerifyingKey,
    pub auth_ops: BTreeMap<Hash<Operation>, Operation>,
    pub content_ops: BTreeSet<u8>, // FIXME automerge content
                                   // FIXME just cache view directly on the object?
}

impl PartialOrd for Document {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self
            .verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
        {
            Some(std::cmp::Ordering::Equal) => {
                if self.auth_ops == other.auth_ops && self.content_ops == other.content_ops {
                    Some(std::cmp::Ordering::Equal)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Identifiable for Document {
    fn id(&self) -> [u8; 32] {
        self.verifier.to_bytes()
    }
}
