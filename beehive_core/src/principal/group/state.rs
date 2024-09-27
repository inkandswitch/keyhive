use super::super::agent::Agent;
use super::operation::Operation;
use super::operation::{delegation::Delegation, revocation::Revocation};
use crate::principal::{
    identifier::Identifier, individual::Individual, membered::MemberedId, traits::Verifiable,
};
use crate::util::content_addressed_map::CaMap;
use crate::{
    access::Access,
    crypto::{hash::Hash, signed::Signed},
};
use ed25519_dalek::VerifyingKey;
use std::cmp::Ordering;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupState {
    pub id: Identifier,
    pub heads: BTreeSet<Hash<Signed<Operation>>>, // FIXME nonempty
    pub ops: CaMap<Signed<Operation>>,            // FIXME nonempty
}

impl From<VerifyingKey> for GroupState {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            heads: BTreeSet::new(),
            ops: CaMap::new(),
        }
    }
}

impl PartialOrd for GroupState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // FIXME use all fields
        match self.id.to_bytes().partial_cmp(&other.id.to_bytes()) {
            Some(Ordering::Equal) => self.ops.len().partial_cmp(&other.ops.len()),
            other => other,
        }
    }
}

impl Ord for GroupState {
    fn cmp(&self, other: &Self) -> Ordering {
        // FIXME use all fields
        match self.id.to_bytes().cmp(&other.id.to_bytes()) {
            Ordering::Equal => self.ops.len().cmp(&other.ops.len()),
            other => other,
        }
    }
}

impl GroupState {
    pub fn new(parent: Individual) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Delegation {
            subject: MemberedId::GroupId(verifier.into()),

            from: verifier.into(),
            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        }
        .into();

        let signed_init: Signed<Operation> = Signed::sign(init, &signing_key);

        // FIXME zeroize signing key

        GroupState {
            id: verifier.into(),
            heads: BTreeSet::from_iter([Hash::hash(signed_init.clone())]),
            ops: CaMap::from_iter([signed_init]),
        }
    }

    pub fn add_op(&mut self, op: Signed<Operation>) -> Result<Hash<Signed<Operation>>, AddError> {
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

    pub fn delegations_for(&self, agent: &Agent) -> Vec<Signed<Delegation>> {
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

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject")]
    InvalidSubject,

    #[error("Invalid signature")]
    InvalidSignature(#[from] signature::Error),
}

impl Verifiable for GroupState {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}
