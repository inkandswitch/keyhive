use super::operation::{delegation::Delegation, revocation::Revocation};
use crate::{
    access::Access,
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::Agent, identifier::Identifier, verifiable::Verifiable},
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupState<T: Serialize> {
    pub id: Identifier,

    pub delegation_heads: BTreeSet<Digest<Signed<Delegation<T>>>>,
    pub delegations: CaMap<Signed<Delegation<T>>>,

    pub revocation_heads: BTreeSet<Digest<Signed<Revocation<T>>>>,
    pub revocations: CaMap<Signed<Revocation<T>>>,
}

impl<T: Serialize> GroupState<T> {
    pub fn new(parent: &Agent<T>) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Signed::sign(
            Delegation {
                delegate: parent,
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: vec![],
            },
            &signing_key,
        );

        GroupState {
            id: verifier.into(),

            delegation_heads: BTreeSet::from_iter([Digest::hash(&init)]),
            delegations: CaMap::from_iter([init]),

            revocation_heads: BTreeSet::new(),
            revocations: CaMap::new(),
        }
    }

    // FIXME split
    pub fn add_delegation(
        &mut self,
        delegation: Signed<Delegation<T>>,
    ) -> Result<Digest<Signed<Delegation<T>>>, AddError> {
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

    pub fn delegations_for(&self, agent: &Agent<T>) -> Vec<&Signed<Delegation<T>>>
    where
        T: Ord,
    {
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

impl<T: Serialize> From<VerifyingKey> for GroupState<T> {
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

impl<T: Serialize> Verifiable for GroupState<T> {
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
