use super::{
    id::GroupId,
    operation::{
        delegation::{Delegation, StaticDelegation},
        revocation::{Revocation, StaticRevocation},
    },
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{
        agent::{Agent, AgentId},
        identifier::Identifier,
        verifiable::Verifiable,
    },
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GroupState<'a, T: ContentRef> {
    pub id: GroupId,

    pub delegation_heads: BTreeSet<&'a Box<Signed<Delegation<'a, T>>>>,
    pub delegations: CaMap<Box<Signed<Delegation<'a, T>>>>,
    pub delegation_quarantine: CaMap<Signed<StaticDelegation<T>>>,

    pub revocation_heads: BTreeSet<&'a Box<Signed<Revocation<'a, T>>>>,
    pub revocations: CaMap<Box<Signed<Revocation<'a, T>>>>,
    pub revocation_quarantine: CaMap<Signed<StaticRevocation<T>>>,
}

impl<'a, T: ContentRef> GroupState<'a, T> {
    pub fn new(parent: &Agent<'a, T>) -> Self {
        let mut rng = rand::random();
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Box::new(Signed::sign(
            Delegation {
                delegate: parent,
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            },
            &signing_key,
        ));

        GroupState {
            id: verifier.into(),

            delegation_heads: BTreeSet::from_iter([&init]), // FIXME consider just using CaMap since it doens't need Ord
            delegations: CaMap::from_iter([init]),

            revocation_heads: BTreeSet::new(),
            revocations: CaMap::new(),
        }
    }

    // FIXME split
    pub fn add_delegation(
        &mut self,
        delegation: Signed<Delegation<'a, T>>,
    ) -> Result<&'a Signed<Delegation<'a, T>>, AddError> {
        if delegation.subject() != self.id.into() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        if delegation.verify().is_err() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSignature);
        }

        // FIXME also check if this op needs to go into the quarantine/buffer

        let boxed = Box::new(delegation);

        // FIXME retrun &ref
        let hash = self.delegations.insert(boxed);
        let newly_owned = self
            .delegations
            .get(&hash)
            .expect("Value that was just inserted to be available");

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

impl<'a, T: ContentRef> From<VerifyingKey> for GroupState<'a, T> {
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

impl<'a, T: ContentRef> Verifiable for GroupState<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.0.verifying_key()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject")]
    InvalidSubject,

    #[error("Invalid signature")]
    InvalidSignature(#[from] signature::Error),
}
