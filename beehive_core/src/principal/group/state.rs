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
    crypto::{
        digest::Digest,
        signed::{Signed, VerificationError},
        signing_key::SigningKey,
        verifiable::Verifiable,
        verifying_key::VerifyingKey,
    },
    principal::{
        agent::Agent, group::operation::delegation::DelegationError, identifier::Identifier,
    },
    util::{content_addressed_map::CaMap, rc::WrappedRc},
};
use dupe::Dupe;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupState<T: ContentRef> {
    pub(crate) id: GroupId,

    pub(crate) delegation_heads: HashSet<WrappedRc<Signed<Delegation<T>>>>,
    pub(crate) delegations: CaMap<Signed<Delegation<T>>>,
    pub delegation_quarantine: CaMap<Signed<StaticDelegation<T>>>,

    pub(crate) revocation_heads: HashSet<WrappedRc<Signed<Revocation<T>>>>,
    pub(crate) revocations: CaMap<Signed<Revocation<T>>>,
    pub revocation_quarantine: CaMap<Signed<StaticRevocation<T>>>,
}

impl<T: ContentRef> GroupState<T> {
    pub fn generate(parents: Vec<Agent<T>>) -> Result<Self, DelegationError> {
        let mut rng = rand::thread_rng();
        let signing_key: SigningKey = ed25519_dalek::SigningKey::generate(&mut rng).into();
        let group_id = signing_key.verifying_key();

        let group = GroupState {
            id: GroupId(group_id.into()),

            delegation_heads: HashSet::new(),
            delegations: CaMap::new(),
            delegation_quarantine: CaMap::new(),

            revocation_heads: HashSet::new(),
            revocations: CaMap::new(),
            revocation_quarantine: CaMap::new(),
        };

        parents.iter().try_fold(group, |mut acc, parent| {
            let dlg = Signed::try_sign(
                Delegation {
                    delegate: parent.dupe(),
                    can: Access::Admin,

                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &signing_key,
            )?;

            let wrc = WrappedRc::new(dlg);
            acc.delegations.insert(wrc.dupe().0);
            acc.delegation_heads.insert(wrc);

            Ok(acc)
        })
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn group_id(&self) -> GroupId {
        self.id
    }

    pub fn delegation_heads(&self) -> &HashSet<WrappedRc<Signed<Delegation<T>>>> {
        &self.delegation_heads
    }

    pub fn revocation_heads(&self) -> &HashSet<WrappedRc<Signed<Revocation<T>>>> {
        &self.revocation_heads
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<T>>> {
        &self.delegations
    }

    pub fn revocations(&self) -> &CaMap<Signed<Revocation<T>>> {
        &self.revocations
    }

    pub fn add_delegation(
        &mut self,
        delegation: Signed<Delegation<T>>,
    ) -> Result<Digest<Signed<Delegation<T>>>, AddError> {
        if delegation.subject() != self.id.into() {
            return Err(AddError::InvalidSubject(delegation.subject()));
        }

        delegation.try_verify()?;

        let wrc = WrappedRc::new(delegation);
        let hash = self.delegations.insert(wrc.dupe().0);

        if let Some(proof) = &wrc.payload().proof {
            if self.delegations.remove_by_value(proof).is_some() {
                self.delegation_heads.insert(wrc);
            }
        }

        Ok(hash)
    }

    pub fn add_revocation(&mut self, revocation: Signed<Revocation<T>>) -> Result<(), AddError> {
        if revocation.subject() != self.id.into() {
            return Err(AddError::InvalidSubject(revocation.subject()));
        }

        revocation.try_verify()?;

        // FIXME also check if this op needs to go into the quarantine/buffer

        // FIXME retrun &ref
        self.revocations.insert(Rc::new(revocation));

        Ok(())
    }

    pub fn delegations_for(&self, agent: Agent<T>) -> Vec<&Rc<Signed<Delegation<T>>>> {
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

impl<T: ContentRef> std::hash::Hash for GroupState<T> {
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

impl<T: ContentRef> From<VerifyingKey> for GroupState<T> {
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

impl<T: ContentRef> Verifiable for GroupState<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.0.verifying_key()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject {0}")]
    InvalidSubject(Identifier),

    #[error("Invalid signature")]
    InvalidSignature(#[from] VerificationError),
}
