use super::operation::{delegation::Delegation, revocation::Revocation, Operation};
use crate::{
    access::Access,
    crypto::{hash::Hash, signed::Signed},
    principal::{
        agent::Agent, identifier::Identifier, individual::Individual, membered::MemberedId,
        traits::Verifiable,
    },
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use std::{cmp::Ordering, collections::BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupState<'a, T: std::hash::Hash + Clone> {
    pub id: Identifier,

    pub delegation_heads: BTreeSet<&'a Signed<Delegation<'a, T>>>, // FIXME nonempty
    pub delegations: CaMap<Signed<Delegation<'a, T>>>,

    pub revocation_heads: BTreeSet<&'a Signed<Revocation<'a, T>>>,
    pub revocations: CaMap<Signed<Revocation<'a, T>>>,
}

impl<'a, T: Eq + std::hash::Hash + Clone> GroupState<'a, T> {
    pub fn new(parent: Individual) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Signed::sign(Delegation {
            subject: MemberedId::GroupId(verifier.into()),

            from: verifier.into(),
            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        });

        GroupState {
            id: verifier.into(),

            heads: BTreeSet::from_iter([&init]),
            delegations: CaMap::from_iter([init]),

            revocation_heads: BTreeSet::new(),
            revocations: CaMap::new(),
        }
    }

    // FIXME split
    pub fn add_op(
        &mut self,
        op: Signed<Operation<'a, T>>,
    ) -> Result<Hash<Signed<Operation<'a, T>>>, AddError> {
        if *op.payload.subject() != MemberedId::GroupId(self.id.into()) {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        if op.verify().is_err() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSignature);
        }

        // FIXME also check if this op needs to go into the quarantine/buffer

        let is_head = op
            .payload
            .after_auth()
            .iter()
            .any(|dep| self.heads.remove(dep));

        if is_head {
            self.heads.insert(Hash::hash(op.clone()));
        }

        Ok(self.ops.insert(op))
    }

    pub fn delegations_for(&self, agent: &Agent<'a, T>) -> Vec<&Signed<Delegation<'a, T>>> {
        self.ops
            .iter()
            .filter_map(|(_, op)| {
                if let Operation::Delegation(delegation) = &op.payload {
                    if delegation.to == *agent {
                        return Some(op.clone().map(|_| delegation.clone()));
                    }
                }
                None
            })
            .collect()
    }

    pub fn get_capability(&self) {
        todo!()
    }
}

impl<'a, T: std::hash::Hash + Clone> From<VerifyingKey> for GroupState<'a, T> {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            heads: BTreeSet::new(),
            ops: CaMap::new(),
        }
    }
}

impl<'a, T: Eq + std::hash::Hash + Clone> PartialOrd for GroupState<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // FIXME use all fields
        match self.id.to_bytes().partial_cmp(&other.id.to_bytes()) {
            Some(Ordering::Equal) => self.ops.len().partial_cmp(&other.ops.len()),
            other => other,
        }
    }
}

impl<'a, T: Eq + std::hash::Hash + Clone> Ord for GroupState<'a, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // FIXME use all fields
        match self.id.to_bytes().cmp(&other.id.to_bytes()) {
            Ordering::Equal => self.ops.len().cmp(&other.ops.len()),
            other => other,
        }
    }
}

impl<'a, T: std::hash::Hash + Clone> Verifiable for GroupState<'a, T> {
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
