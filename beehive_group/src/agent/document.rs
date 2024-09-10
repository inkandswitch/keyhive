use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Op;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Document {
    pub verifier: VerifyingKey,
    pub state_ops: BTreeMap<Hash, Op>,
    pub content_ops: BTreeSet<u8>, // FIXME automerge content
}

impl PartialOrd for Document {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self
            .verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
        {
            Some(std::cmp::Ordering::Equal) => {
                if self.state_ops == other.state_ops && self.content_ops == other.content_ops {
                    Some(std::cmp::Ordering::Equal)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
