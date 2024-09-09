use blake3::Hash;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Op;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub verifier: VerifyingKey,
    pub state: BTreeMap<Hash, Op>,
    pub content: Vec<u8>, // FIXME automerge content
}
