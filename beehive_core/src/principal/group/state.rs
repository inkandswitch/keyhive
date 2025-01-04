use super::{
    error::AddError,
    id::GroupId,
    operation::{delegation::Delegation, revocation::Revocation},
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{
        agent::Agent, group::operation::delegation::DelegationError, identifier::Identifier,
        verifiable::Verifiable,
    },
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

// FIXME validate admin on ingest & buld

#[derive(Clone, Eq, Derivative)]
#[derivative(Debug, PartialEq, Hash)]
pub struct GroupState<T: ContentRef> {
    pub(crate) id: GroupId,

    #[derivative(Debug = "ignore", PartialEq = "ignore", Hash = "ignore")]
    pub(crate) delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
    pub(crate) delegation_heads: CaMap<Signed<Delegation<T>>>,

    #[derivative(Debug = "ignore", PartialEq = "ignore", Hash = "ignore")]
    pub(crate) revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
    pub(crate) revocation_heads: CaMap<Signed<Revocation<T>>>,
}

impl<T: ContentRef> GroupState<T> {
    pub fn new(
        delegation_head: Rc<Signed<Delegation<T>>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
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
        parents: Vec<Agent<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
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

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T>>> {
        &self.delegation_heads
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<T>>> {
        &self.revocation_heads
    }

    pub fn add_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<T>>>,
    ) -> Result<Digest<Signed<Delegation<T>>>, AddError> {
        if delegation.subject() != self.id.0.verifying_key().into() {
            return Err(AddError::InvalidSubject(delegation.subject()));
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

        let mut inserted = false;
        for (head_digest, head) in self.delegation_heads.clone().iter() {
            if head.payload().is_ancestor_of(&delegation) {
                self.delegation_heads.remove_by_hash(head_digest);

                if !inserted {
                    self.delegation_heads.insert(delegation.dupe());
                    inserted = true;
                }
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
        revocation: Rc<Signed<Revocation<T>>>,
    ) -> Result<Digest<Signed<Revocation<T>>>, AddError> {
        if revocation.subject() != self.id.into() {
            return Err(AddError::InvalidSubject(revocation.subject()));
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
                    if proof.payload.can > proof.payload.can {
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

    pub fn delegations_for(&self, agent: Agent<T>) -> Vec<Rc<Signed<Delegation<T>>>> {
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
}

impl<T: ContentRef> From<VerifyingKey> for GroupState<T> {
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

impl<T: ContentRef> Verifiable for GroupState<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.0.verifying_key()
    }
}

// FIXME test
impl<T: ContentRef> Serialize for GroupState<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GroupState", 3)?;

        state.serialize_field("id", &self.id)?;
        state.serialize_field(
            "delegation_heads",
            &self
                .delegation_heads
                .values()
                .collect::<Vec<_>>()
                .sort_by_key(|dlg| Digest::hash(dlg.as_ref())),
        )?;
        state.serialize_field(
            "revocation_heads",
            &self
                .revocation_heads
                .values()
                .collect::<Vec<_>>()
                .sort_by_key(|rev| Digest::hash(rev.as_ref())),
        )?;

        state.end()
    }
}
