// FIXME move to Group

use super::delegation::Delegation;
use crate::crypto::hash::Hash;
use crate::crypto::signed::Signed;
use crate::util::content_addressed_map::CaMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revocation<'a, T: std::hash::Hash + Clone> {
    pub revoke: &'a Signed<Delegation<'a, T>>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: &'a Signed<Delegation<'a, T>>,
}

impl<'a, T: std::hash::Hash + Clone> Revocation<'a, T> {
    pub fn into_static(self) -> StaticRevocation<'a, T> {
        StaticRevocation::from(self)
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Revocation<'a, T>> for Vec<u8> {
    fn from(revocation: Revocation<'a, T>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Vec::<u8>::from(revocation.revoke.clone()).as_slice());
        bytes.extend_from_slice(Vec::<u8>::from(revocation.proof.clone()).as_slice());
        bytes
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticRevocation<'a, T: std::hash::Hash + Clone> {
    pub revoke: Hash<Signed<Delegation<'a, T>>>,
    pub proof: Hash<Signed<Delegation<'a, T>>>,
}

impl<'a, T: std::hash::Hash + Clone> StaticRevocation<'a, T> {
    pub fn resolve(
        &self,
        delegations: &'a CaMap<Signed<Delegation<'a, T>>>,
    ) -> Result<Revocation<'a, T>, ()> {
        let revoke = delegations.get(&self.revoke).ok_or(())?;
        let proof = delegations.get(&self.proof).ok_or(())?;
        Ok(Revocation { revoke, proof })
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Revocation<'a, T>> for StaticRevocation<'a, T> {
    fn from(revocation: Revocation<'a, T>) -> StaticRevocation<'a, T> {
        StaticRevocation {
            revoke: Hash::hash(revocation.revoke.clone()),
            proof: Hash::hash(revocation.proof.clone()),
        }
    }
}

impl<'a, T: std::hash::Hash + Clone> From<StaticRevocation<'a, T>> for Vec<u8> {
    fn from(revocation: StaticRevocation<'a, T>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Vec::<u8>::from(revocation.revoke).as_slice());
        bytes.extend_from_slice(Vec::<u8>::from(revocation.proof).as_slice());
        bytes
    }
}
