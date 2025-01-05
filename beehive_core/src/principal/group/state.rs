use super::{
    id::GroupId,
    operation::{delegation::Delegation, revocation::Revocation},
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        signed::{Signed, VerificationError},
    },
    principal::{
        agent::Agent, group::operation::delegation::DelegationError, identifier::Identifier,
        verifiable::Verifiable,
    },
    util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState<T: ContentRef> {
    pub(crate) id: GroupId,

    pub(crate) delegation_heads: CaMap<Signed<Delegation<T>>>,
    pub(crate) delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,

    pub(crate) revocation_heads: CaMap<Signed<Revocation<T>>>,
    pub(crate) revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
}

impl<T: ContentRef> GroupState<T> {
    pub fn new(
        delegation_head: Signed<Delegation<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
    ) -> Self {
        let id = GroupId(delegation_head.verifying_key().into());
        let rc = Rc::new(delegation_head);
        let mut heads = vec![rc.dupe()];

        while let Some(head) = heads.pop() {
            if delegations.borrow().contains_value(head.as_ref()) {
                continue;
            }

            let mut dlg_store_mut = delegations.borrow_mut();
            dlg_store_mut.insert(head.dupe());

            for dlg in head.payload().proof_lineage() {
                dlg_store_mut.insert(dlg.dupe());

                for rev in dlg.payload().after_revocations.as_slice() {
                    revocations.borrow_mut().insert(rev.dupe());

                    if let Some(proof) = &rev.payload().proof {
                        heads.push(proof.dupe());
                    }
                }
            }
        }

        let mut delegation_heads = CaMap::new();
        delegation_heads.insert(rc);

        Self {
            id,

            delegation_heads,
            delegations,

            // NOTE revocation_heads are guaranteed to be blank at this stage
            // because they can only come before the delegation passed in.
            revocation_heads: CaMap::new(),
            revocations,
        }
    }

    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: Vec<Agent<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let group_id = signing_key.verifying_key().into();

        let group = GroupState {
            id: GroupId(group_id),

            delegation_heads: CaMap::new(),
            delegations,

            revocation_heads: CaMap::new(),
            revocations,
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

            acc.delegation_heads.insert(Rc::new(dlg));
            Ok(acc)
        })
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn group_id(&self) -> GroupId {
        self.id
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T>>> {
        &self.delegation_heads
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<T>>> {
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
        delegation.try_verify()?;
        if *delegation.verifying_key() != self.id.0.verifying_key() {
            return Err(AddError::InvalidSubject(delegation.subject()));
        }

        let rc = Rc::new(delegation);

        for (head_digest, head) in self.delegation_heads.clone().iter() {
            if head.payload().is_ancestor_of(&rc) {
                self.delegation_heads.insert(rc.dupe());
                self.delegation_heads.remove_by_hash(head_digest);
            }
        }

        let hash = self.delegations.borrow_mut().insert(rc);
        Ok(hash)
    }

    pub fn add_revocation(&mut self, revocation: Signed<Revocation<T>>) -> Result<(), AddError> {
        if revocation.subject() != self.id.into() {
            return Err(AddError::InvalidSubject(revocation.subject()));
        }

        todo!("FIXME");

        revocation.try_verify()?;
        self.revocation_heads.assume(revocation);
        // FIXME check that this is actually a head
        Ok(())
    }

    pub fn delegations_for(&self, agent: Agent<T>) -> Vec<&Rc<Signed<Delegation<T>>>> {
        self.delegations()
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
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
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

// FIXME test
impl<T: ContentRef> Serialize for GroupState<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GroupState", 6)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field(
            "delegation_heads",
            &self
                .delegation_heads
                .iter()
                .map(|d| d.as_ref())
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("delegation_quarantine", &self.delegation_quarantine)?;
        state.serialize_field(
            "revocation_heads",
            &self
                .revocation_heads
                .iter()
                .map(|r| r.as_ref())
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("revocation_quarantine", &self.revocation_quarantine)?;

        state.end()
    }
}
