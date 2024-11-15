use super::{
    error::AddError,
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
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
        agent::Agent, group::operation::delegation::DelegationError, identifier::Identifier,
        verifiable::Verifiable,
    },
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Clone, Eq)]
#[derive_where(PartialEq, Hash; T)]
pub struct GroupState<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) id: GroupId,

    #[derive_where(skip)]
    pub(crate) delegations: Rc<RefCell<CaMap<Signed<Delegation<T, L>>>>>,
    pub(crate) delegation_heads: CaMap<Signed<Delegation<T, L>>>,

    #[derive_where(skip)]
    pub(crate) revocations: Rc<RefCell<CaMap<Signed<Revocation<T, L>>>>>,
    pub(crate) revocation_heads: CaMap<Signed<Revocation<T, L>>>,
}

impl<T: ContentRef, L: MembershipListener<T>> GroupState<T, L> {
    pub fn new(
        delegation_head: Rc<Signed<Delegation<T, L>>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T, L>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T, L>>>>>,
    ) -> Self {
        let id = GroupId(delegation_head.verifying_key().into());
        let mut heads = vec![delegation_head.dupe()];

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
        delegation_heads.insert(delegation_head);

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
        parents: Vec<Agent<T, L>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T, L>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T, L>>>>>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let signing_key = ed25519_dalek::SigningKey::generate(csprng);
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

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T, L>>> {
        &self.delegation_heads
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<T, L>>> {
        &self.revocation_heads
    }

    pub fn add_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<T, L>>>,
    ) -> Result<Digest<Signed<Delegation<T, L>>>, AddError> {
        if delegation.subject_id() != self.id.into() {
            return Err(AddError::InvalidSubject(Box::new(delegation.subject_id())));
        }

        if delegation.payload().proof.is_none() && delegation.issuer != self.verifying_key() {
            return Err(AddError::InvalidProofChain);
        }

        delegation.payload.proof_lineage().iter().try_fold(
            delegation.as_ref(),
            |head, proof| {
                if delegation.payload.can > proof.payload.can {
                    return Err(AddError::Escelation {
                        claimed: delegation.payload.can,
                        proof: proof.payload.can,
                    });
                }

                if head.verifying_key() != proof.payload.delegate.verifying_key() {
                    return Err(AddError::InvalidProofChain);
                }

                Ok(proof.as_ref())
            },
        )?;

        for (head_digest, head) in self.delegation_heads.clone().iter() {
            if !delegation.payload.is_ancestor_of(head) {
                self.delegation_heads.insert(delegation.dupe());
            }

            if head.payload.is_ancestor_of(&delegation) {
                self.delegation_heads.remove_by_hash(head_digest);
            }
        }

        for (head_digest, head) in self.revocation_heads.clone().iter() {
            if delegation.payload.after_revocations.contains(head) {
                self.revocation_heads.remove_by_hash(head_digest);
            }
        }

        let hash = self.delegations.borrow_mut().insert(delegation);
        Ok(hash)
    }

    pub fn add_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<T, L>>>,
    ) -> Result<Digest<Signed<Revocation<T, L>>>, AddError> {
        if revocation.subject_id() != self.id.into() {
            return Err(AddError::InvalidSubject(Box::new(revocation.subject_id())));
        }

        if let Some(proof) = &revocation.payload.proof {
            if !revocation.payload.revoke.payload.is_descendant_of(proof) {
                return Err(AddError::InvalidProofChain);
            }

            proof
                .payload
                .proof_lineage()
                .iter()
                .try_fold(proof.as_ref(), |head, next_proof| {
                    if proof.payload.can.cmp(&next_proof.payload.can) == Ordering::Greater {
                        return Err(AddError::Escelation {
                            claimed: proof.payload.can,
                            proof: next_proof.payload.can,
                        });
                    }

                    if head.verifying_key() != next_proof.payload.delegate.verifying_key() {
                        return Err(AddError::InvalidProofChain);
                    }

                    Ok(proof.as_ref())
                })?;
        } else if revocation.issuer != self.verifying_key() {
            return Err(AddError::InvalidProofChain);
        }

        let mut inserted = false;
        for (head_digest, head) in self.delegation_heads.clone().iter() {
            if revocation.payload.revoke == *head || revocation.payload.proof == Some(head.dupe()) {
                self.delegation_heads.remove_by_hash(head_digest);

                if !inserted {
                    self.revocation_heads.insert(revocation.dupe());
                    inserted = true;
                }
            }
        }

        let hash = self.revocations.borrow_mut().insert(revocation);
        Ok(hash)
    }

    pub fn delegations_for(&self, agent: Agent<T, L>) -> Vec<Rc<Signed<Delegation<T, L>>>> {
        self.delegations
            .borrow()
            .values()
            .filter_map(|delegation| {
                if delegation.payload().delegate == agent {
                    Some(delegation.dupe())
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn dummy_from_archive(
        archive: GroupStateArchive<T>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T, L>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T, L>>>>>,
    ) -> Self {
        Self {
            id: archive.id,

            delegation_heads: CaMap::new(),
            delegations,

            revocation_heads: CaMap::new(),
            revocations,
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<VerifyingKey> for GroupState<T, L> {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: GroupId(verifier.into()),

            delegation_heads: CaMap::new(),
            delegations: Rc::new(RefCell::new(CaMap::new())),

            revocation_heads: CaMap::new(),
            revocations: Rc::new(RefCell::new(CaMap::new())),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Verifiable for GroupState<T, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.0.verifying_key()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GroupStateArchive<T: ContentRef> {
    pub(crate) id: GroupId,
    pub(crate) delegation_heads: HashSet<Digest<Signed<StaticDelegation<T>>>>,
    pub(crate) revocation_heads: HashSet<Digest<Signed<StaticRevocation<T>>>>,
}

impl<T: ContentRef, L: MembershipListener<T>> From<&GroupState<T, L>> for GroupStateArchive<T> {
    fn from(state: &GroupState<T, L>) -> Self {
        GroupStateArchive {
            id: state.id,
            delegation_heads: state.delegation_heads.keys().map(Into::into).collect(),
            revocation_heads: state.revocation_heads.keys().map(Into::into).collect(),
        }
    }
}
