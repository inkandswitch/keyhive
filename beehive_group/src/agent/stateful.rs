use blake3::Hash;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Op();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stateful {
    verifier: VerifyingKey,
    state: BTreeMap<Hash, Op>,
}

impl PartialOrd for Stateful {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}
