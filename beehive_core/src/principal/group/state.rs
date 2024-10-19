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
    principal::{agent::Agent, identifier::Identifier, verifiable::Verifiable},
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupState<'a, T: ContentRef> {
    pub(crate) id: GroupId,

    pub(crate) delegation_heads: HashSet<Digest<Signed<Delegation<'a, T>>>>,
    pub(crate) delegations: CaMap<Signed<Delegation<'a, T>>>,
    pub delegation_quarantine: CaMap<Signed<StaticDelegation<T>>>,

    pub(crate) revocation_heads: HashSet<Digest<Signed<Revocation<'a, T>>>>,
    pub(crate) revocations: CaMap<Signed<Revocation<'a, T>>>,
    pub revocation_quarantine: CaMap<Signed<StaticRevocation<T>>>,
}

impl<'a, T: ContentRef> GroupState<'a, T> {
    pub fn generate(parents: Vec<&'a Agent<'a, T>>) -> Self {
        let mut rng = rand::thread_rng();
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let group_id = signing_key.verifying_key().into();

        let mut group = GroupState {
            id: GroupId(group_id),

            delegation_heads: HashSet::new(),
            delegations: CaMap::new(),
            delegation_quarantine: CaMap::new(),

            revocation_heads: HashSet::new(),
            revocations: CaMap::new(),
            revocation_quarantine: CaMap::new(),
        };

        for parent in parents.iter() {
            let dlg = Signed::sign(
                Delegation {
                    delegate: *parent,
                    can: Access::Admin,

                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &signing_key,
            );

            let hash = group.delegations.insert(dlg);
            group.delegation_heads.insert(hash);
        }

        group
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn group_id(&self) -> GroupId {
        self.id
    }

    pub fn delegation_heads(&self) -> &HashSet<Digest<Signed<Delegation<'a, T>>>> {
        &self.delegation_heads
    }

    pub fn delegation_head_refs(&'a self) -> Vec<&'a Signed<Delegation<'a, T>>> {
        self.delegation_heads
            .iter()
            .map(|digest| self.delegations.get(digest).unwrap())
            .collect()
    }

    pub fn revocation_heads(&self) -> &HashSet<Digest<Signed<Revocation<'a, T>>>> {
        &self.revocation_heads
    }

    pub fn revocation_head_refs(&'a self) -> Vec<&'a Signed<Delegation<'a, T>>> {
        self.delegation_heads
            .iter()
            .map(|digest| self.delegations.get(digest).unwrap())
            .collect()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<'a, T>>> {
        &self.delegations
    }

    pub fn revocations(&self) -> &CaMap<Signed<Revocation<'a, T>>> {
        &self.revocations
    }

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

        let hash = self.delegations.insert(delegation);
        let dlg_ref = self.delegations.get(&hash).unwrap();

        if let Some(proof) = dlg_ref.payload().proof {
            let proof_hash = Digest::hash(proof);

            if self.delegation_heads.contains(&proof_hash) {
                self.delegation_heads.insert(hash);
                self.delegation_heads.remove(&proof_hash);
            }
        }

        Ok(hash)
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
                if delegation.payload().delegate == agent {
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
