pub mod archive;

use self::archive::GroupStateArchive;
use super::{delegation::Delegation, error::AddError, id::GroupId, revocation::Revocation};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        signed::Signed,
        signer::{async_signer::AsyncSigner, memory::MemorySigner, sync_signer::SyncSigner},
        verifiable::Verifiable,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{agent::Agent, group::delegation::DelegationError, identifier::Identifier},
    store::{
        delegation::DelegationStore, revocation::RevocationStore,
        secret_key::traits::ShareSecretStore,
    },
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use std::{cmp::Ordering, collections::BTreeMap, rc::Rc};

#[derive(Clone, Eq)]
#[derive_where(Debug, PartialEq, Hash; T)]
pub struct GroupState<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    pub(crate) id: GroupId,

    #[derive_where(skip)]
    pub(crate) delegations: DelegationStore<S, K, T, L>,
    pub(crate) delegation_heads: CaMap<Signed<Delegation<S, K, T, L>>>,

    #[derive_where(skip)]
    pub(crate) revocations: RevocationStore<S, K, T, L>,
    pub(crate) revocation_heads: CaMap<Signed<Revocation<S, K, T, L>>>,
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    GroupState<S, K, T, L>
{
    pub fn new(
        delegation_head: Rc<Signed<Delegation<S, K, T, L>>>,
        delegations: DelegationStore<S, K, T, L>,
        revocations: RevocationStore<S, K, T, L>,
    ) -> Self {
        let id = GroupId(delegation_head.verifying_key().into());
        let mut heads = vec![delegation_head.dupe()];

        while let Some(head) = heads.pop() {
            if delegations.contains_value(head.as_ref()) {
                continue;
            }

            delegations.insert(head.dupe());

            for dlg in head.payload().proof_lineage() {
                delegations.insert(dlg.dupe());

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
        parents: Vec<Agent<S, K, T, L>>,
        delegations: DelegationStore<S, K, T, L>,
        revocations: RevocationStore<S, K, T, L>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let signer = MemorySigner::generate(csprng);
        let group_id = signer.verifying_key().into();

        let group = GroupState {
            id: GroupId(group_id),

            delegation_heads: CaMap::new(),
            delegations,

            revocation_heads: CaMap::new(),
            revocations,
        };

        parents.iter().try_fold(group, |mut acc, parent| {
            let dlg = signer.try_sign_sync(Delegation {
                delegate: parent.dupe(),
                can: Access::Admin,

                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            })?;

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

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<S, K, T, L>>> {
        &self.delegation_heads
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<S, K, T, L>>> {
        &self.revocation_heads
    }

    #[allow(clippy::type_complexity)]
    pub fn add_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<S, K, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, K, T, L>>>, AddError> {
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

        let hash = self.delegations.insert(delegation);
        Ok(hash)
    }

    #[allow(clippy::type_complexity)]
    pub fn add_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<S, K, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, K, T, L>>>, AddError> {
        if revocation.subject_id() != self.id.into() {
            return Err(AddError::InvalidSubject(Box::new(revocation.subject_id())));
        }

        if let Some(proof) = &revocation.payload.proof {
            if revocation.payload.revoke != *proof
                && !revocation.payload.revoke.payload.is_descendant_of(proof)
            {
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

        self.revocation_heads.insert(revocation.dupe());

        let hash = self.revocations.borrow_mut().insert(revocation);
        Ok(hash)
    }

    pub fn delegations_for(
        &self,
        agent: Agent<S, K, T, L>,
    ) -> Vec<Rc<Signed<Delegation<S, K, T, L>>>> {
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
        delegations: DelegationStore<S, K, T, L>,
        revocations: RevocationStore<S, K, T, L>,
    ) -> Self {
        Self {
            id: archive.id,

            delegation_heads: CaMap::new(),
            delegations,

            revocation_heads: CaMap::new(),
            revocations,
        }
    }

    pub fn into_archive(&self) -> GroupStateArchive<T> {
        GroupStateArchive {
            id: self.id,
            delegation_heads: self.delegation_heads.keys().map(Into::into).collect(),
            revocation_heads: self.revocation_heads.keys().map(Into::into).collect(),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Verifiable
    for GroupState<S, K, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.0.verifying_key()
    }
}
