use super::super::agent::Agent;
use super::operation::delegation::Delegation;
use super::operation::revocation::Revocation;
use super::operation::{self, Operation};
use crate::principal::auth_state::AuthState;
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
    pub ops: CaMap<Signed<Operation>>, // FIXME nonempty
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
        // let mut rng = rand::rngs::OsRng;
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let group_id = signing_key.verifying_key().into();

        let init = Delegation {
            subject: MemberedId::GroupId(group_id),

            delegator: group_id,
            delegate: parent.into(),
            can: Access::Admin,

            delegator_proof: None,
            after_revocations: vec![],
        }
        .into();

        let signed_init: Signed<Delegation> = Signed::sign(init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id: group_id,
            heads: BTreeSet::from_iter([Hash::hash(signed_init.clone().map(|delegation| delegation.into()))]),
            ops: CaMap::from_iter([signed_init.map(|delegation| delegation.into())]),
        }
    }

    pub fn add_op(&mut self, op: Signed<Operation>) -> Result<Hash<Signed<Operation>>, AddError> {
        if *op.payload.subject() != MemberedId::GroupId(self.id) {
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
            .after_revocations()
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
                    if delegation.delegate == *agent {
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

impl AuthState for GroupState {
    fn id(&self) -> Identifier {
        self.id
    }

    fn auth_heads(&self) -> &BTreeSet<Hash<Signed<Operation>>> {
        &self.heads
    }

    fn auth_heads_mut(&mut self) -> &mut BTreeSet<Hash<Signed<Operation>>> {
        &mut self.heads
    }

    fn auth_ops(&self) -> &CaMap<Signed<Operation>> {
        &self.ops
    }

    fn auth_ops_mut(&mut self) -> &mut CaMap<Signed<Operation>> {
        &mut self.ops
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("{0}")]
    Ancestor(#[from] operation::AncestorError),

    #[error("Invalid delegation")]
    InvalidDelegation,

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
