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
    principal::{agent::Agent, verifiable::Verifiable},
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupState<'a, T: ContentRef> {
    pub(super) id: GroupId,

    pub(super) delegation_heads: HashSet<Digest<Signed<Delegation<'a, T>>>>,
    pub delegations: CaMap<Signed<Delegation<'a, T>>>,
    pub delegation_quarantine: CaMap<Signed<StaticDelegation<T>>>,

    pub(super) revocation_heads: HashSet<Digest<Signed<Revocation<'a, T>>>>,
    pub revocations: CaMap<Signed<Revocation<'a, T>>>,
    pub revocation_quarantine: CaMap<Signed<StaticRevocation<T>>>,
}

impl<'a, T: ContentRef> GroupState<'a, T> {
    pub fn new(parent: &'a Agent<'a, T>) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Signed::sign(
            Delegation {
                delegate: parent,
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            },
            &signing_key,
        );

        let mut delegations = CaMap::new();
        let hash = delegations.insert(init);

        GroupState {
            id: GroupId(verifier.into()),

            delegation_heads: HashSet::from_iter([hash]),
            delegations,
            delegation_quarantine: CaMap::new(),

            revocation_heads: HashSet::new(),
            revocations: CaMap::new(),
            revocation_quarantine: CaMap::new(),
        }
    }

    pub fn id(&self) -> &GroupId {
        &self.id
    }

    pub fn delegation_heads(&'a self) -> Vec<&'a Signed<Delegation<'a, T>>> {
        let mut refs = vec![];

        for head in self.delegation_heads.iter() {
            let dlg = self
                .delegations
                .get(head)
                .expect("corresponding head was missing");

            refs.push(dlg);
        }

        refs
    }

    pub fn revocation_heads(&'a self) -> Vec<&'a Signed<Revocation<'a, T>>> {
        let mut refs = vec![];

        for head in self.revocation_heads.iter() {
            let rev = self
                .revocations
                .get(head)
                .expect("corresponding head was missing");

            refs.push(rev);
        }

        refs
    }

    pub fn add_delegation(
        &mut self,
        delegation: Signed<Delegation<'a, T>>,
    ) -> Result<(), AddError> {
        if delegation.subject() != self.id.into() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        if delegation.verify().is_err() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSignature);
        }

        // FIXME also check if this op needs to go into the quarantine/buffer

        // FIXME retrun &ref
        let opt_proof = delegation.payload.proof;
        let hash = self.delegations.insert(delegation);

        if let Some(proof) = opt_proof {
            if self.delegation_heads.contains(&Digest::hash(proof)) {
                self.delegation_heads.insert(hash);
                self.delegation_heads.remove(&Digest::hash(proof));
            }
        }

        Ok(())
    }

    pub fn add_revocation(
        &mut self,
        revocation: Signed<Revocation<'a, T>>,
    ) -> Result<(), AddError> {
        if revocation.subject() != self.id.into() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        if revocation.verify().is_err() {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSignature);
        }

        // FIXME also check if this op needs to go into the quarantine/buffer

        // FIXME retrun &ref
        self.revocations.insert(revocation);

        Ok(())
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

impl<'a, T: ContentRef> std::hash::Hash for GroupState<'a, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);

        for dh in self.delegation_heads.iter() {
            dh.hash(state);
        }

        self.delegations.hash(state);
        self.delegation_quarantine.hash(state);

        for rh in self.revocation_heads.iter() {
            rh.hash(state);
        }

        self.revocations.hash(state);
        self.revocation_quarantine.hash(state);
    }
}

impl<'a, T: ContentRef> From<VerifyingKey> for GroupState<'a, T> {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: GroupId(verifier.into()),

            delegation_heads: HashSet::new(),
            delegations: CaMap::new(),
            delegation_quarantine: CaMap::new(),

            revocation_heads: HashSet::new(),
            revocations: CaMap::new(),
            revocation_quarantine: CaMap::new(),
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
