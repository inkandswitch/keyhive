use super::traits::Verifiable;
use crate::hash::Hash;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmptySet<T> {
    pub head: T,
    pub rest: BTreeSet<T>,
}

impl<T> NonEmptySet<T> {
    pub fn len(&self) -> usize {
        self.rest.len() + 1
    }
}

impl<T: Ord> IntoIterator for NonEmptySet<T> {
    type Item = T;
    type IntoIter = <BTreeSet<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        BTreeSet::from(self).into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WrappedPk(pub x25519_dalek::PublicKey);

impl PartialOrd for WrappedPk {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.as_bytes().partial_cmp(&other.0.as_bytes())
    }
}

impl Ord for WrappedPk {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(&other.0.as_bytes())
    }
}

impl<T: Ord> From<NonEmptySet<T>> for BTreeSet<T> {
    fn from(ne_set: NonEmptySet<T>) -> Self {
        let mut set = ne_set.rest;
        set.insert(ne_set.head);
        set
    }
}

// FIXME make sure Signed

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stateless {
    pub verifier: VerifyingKey,
    pub sharing_prekeys: NonEmptySet<WrappedPk>,
}

// impl From<VerifyingKey> for Stateless {
//     fn from(verifier: VerifyingKey) -> Self {
//         Stateless {
//             verifier,
//             sharing_prekeys: BTreeSet::new(),
//         }
//     }
// }

impl Stateless {
    pub fn prekey_for(&self, requestor: VerifyingKey) -> Option<WrappedPk> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.verifier.as_bytes());
        hasher.update(requestor.as_bytes());
        let hash = hasher.finalize();

        let pre_index = u64::from_be_bytes(hash.as_bytes()[0..8].try_into().expect("FIXME"));
        let index = pre_index % self.sharing_prekeys.len() as u64;

        self.sharing_prekeys.clone().into_iter().nth(index as usize)
    }
}

// FIXME pub type SignedStateless = Signed<Stateless>;

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
