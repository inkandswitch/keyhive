// FIXME move to Group

use super::delegation::Delegation;
use crate::{
    crypto::{digest::Digest, signed::Signed},
    util::content_addressed_map::CaMap,
};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Revocation<'a, T: Clone + Ord + Serialize> {
    pub revoke: &'a Signed<Delegation<'a, T>>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: &'a Signed<Delegation<'a, T>>,
}

impl<'a, T: Clone + Ord + Serialize> Revocation<'a, T> {
    pub fn into_static(self) -> StaticRevocation<'a, T> {
        StaticRevocation::from(self)
    }
}

// FIXME test
impl<'a, T: Clone + Ord + Serialize> Hash for Revocation<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Digest::hash(self.revoke).hash(state);
        Digest::hash(self.proof).hash(state);
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StaticRevocation<'a, T: Clone + Ord + Serialize> {
    pub revoke: Digest<Signed<Delegation<'a, T>>>,
    pub proof: Digest<Signed<Delegation<'a, T>>>,
}

impl<'a, T: Clone + Ord + Serialize> StaticRevocation<'a, T> {
    pub fn resolve(
        &self,
        delegations: &'a CaMap<Signed<Delegation<'a, T>>>,
    ) -> Result<Revocation<'a, T>, ()> {
        let revoke = delegations.get(&self.revoke).ok_or(())?;
        let proof = delegations.get(&self.proof).ok_or(())?;
        Ok(Revocation { revoke, proof })
    }
}

impl<'a, T: Clone + Ord + Serialize> From<Revocation<'a, T>> for StaticRevocation<'a, T> {
    fn from(revocation: Revocation<'a, T>) -> StaticRevocation<'a, T> {
        StaticRevocation {
            revoke: Digest::hash(revocation.revoke),
            proof: Digest::hash(revocation.proof),
        }
    }
}
