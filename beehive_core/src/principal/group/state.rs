use super::operation::{delegation::Delegation, revocation::Revocation};
use crate::{
    access::Access,
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::Agent, identifier::Identifier, traits::Verifiable},
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::{cmp::Ordering, collections::BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState<'a, T: Clone + Ord + Serialize> {
    pub id: Identifier,

    pub delegation_heads: BTreeSet<&'a Signed<Delegation<'a, T>>>,
    pub delegations: CaMap<Signed<Delegation<'a, T>>>,

    pub revocation_heads: BTreeSet<&'a Signed<Revocation<'a, T>>>,
    pub revocations: CaMap<Signed<Revocation<'a, T>>>,
}

impl<'a, T: Eq + Clone + Ord + Serialize> GroupState<'a, T> {
    pub fn new(parent: &'a Agent<'a, T>) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Signed::sign(
            Delegation {
                delegate: &parent,
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: vec![],
            },
            &signing_key,
        );

        let hash = Digest::hash(&init);
        let delegations = CaMap::from_iter([init]);
        let head = delegations.get(&hash).unwrap();

        GroupState {
            id: verifier.into(),

            delegation_heads: BTreeSet::from_iter([head]),
            delegations,

            revocation_heads: BTreeSet::new(),
            revocations: CaMap::new(),
        }
    }

    // FIXME split
    pub fn add_delegation(
        &'a mut self,
        delegation: Signed<Delegation<'a, T>>,
    ) -> Result<Digest<Signed<Delegation<'a, T>>>, AddError> {
        if delegation.subject() != self.id.into() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        if delegation.verify().is_err() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSignature);
        }

        // FIXME also check if this op needs to go into the quarantine/buffer

        let hash = self.delegations.insert(delegation);
        let newly_owned = self.delegations.get(&hash).unwrap();

        if let Some(proof) = newly_owned.payload.proof {
            if self.delegation_heads.contains(proof) {
                self.delegation_heads.insert(newly_owned);
                self.delegation_heads.remove(proof);
            }
        }

        Ok(hash)
    }

    pub fn delegations_for(&self, agent: &Agent<'a, T>) -> Vec<&Signed<Delegation<'a, T>>> {
        self.delegations
            .iter()
            .filter_map(|(_, delegation)| {
                if delegation.payload.delegate == agent {
                    Some(delegation)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_capability(&self) {
        todo!()
    }
}

impl<'a, T: Clone + Ord + Serialize> From<VerifyingKey> for GroupState<'a, T> {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            delegation_heads: BTreeSet::new(),
            delegations: CaMap::new(),
            revocation_heads: BTreeSet::new(),
            revocations: CaMap::new(),
        }
    }
}

impl<'a, T: Eq + Clone + Ord + Serialize> PartialOrd for GroupState<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // FIXME use all fields
        match self.id.to_bytes().partial_cmp(&other.id.to_bytes()) {
            Some(Ordering::Equal) => self.ops.len().partial_cmp(&other.ops.len()),
            other => other,
        }
    }
}

impl<'a, T: Clone + Ord + Serialize> Verifiable for GroupState<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject")]
    InvalidSubject,

    #[error("Invalid signature")]
    InvalidSignature(#[from] signature::Error),
}
