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
    store::{delegation::DelegationStore, revocation::RevocationStore},
};
use derive_where::derive_where;
use dupe::Dupe;
use futures::lock::Mutex;
use std::{cmp::Ordering, collections::BTreeMap, sync::Arc};

#[derive(Clone)]
#[derive_where(Debug, Hash; T)]
pub struct GroupState<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) id: GroupId,

    #[derive_where(skip)]
    pub(crate) delegations: Arc<Mutex<DelegationStore<S, T, L>>>,
    pub(crate) delegation_heads: DelegationStore<S, T, L>,

    #[derive_where(skip)]
    pub(crate) revocations: Arc<Mutex<RevocationStore<S, T, L>>>,
    pub(crate) revocation_heads: RevocationStore<S, T, L>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> GroupState<S, T, L> {
    pub async fn new(
        delegation_head: Arc<Signed<Delegation<S, T, L>>>,
        delegations: Arc<Mutex<DelegationStore<S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<S, T, L>>>,
    ) -> Self {
        let id = GroupId(delegation_head.verifying_key().into());
        let mut heads = vec![delegation_head.dupe()];

        while let Some(head) = heads.pop() {
            if delegations.lock().await.contains_value(head.as_ref()) {
                continue;
            }

            delegations.lock().await.insert(head.dupe());

            for dlg in head.payload().proof_lineage() {
                delegations.lock().await.insert(dlg.dupe());

                for rev in dlg.payload().after_revocations.as_slice() {
                    revocations.lock().await.insert(rev.dupe());

                    if let Some(proof) = &rev.payload().proof {
                        heads.push(proof.dupe());
                    }
                }
            }
        }

        let mut delegation_heads = DelegationStore::new();
        delegation_heads.insert(delegation_head);

        Self {
            id,

            delegation_heads,
            delegations,

            // NOTE revocation_heads are guaranteed to be blank at this stage
            // because they can only come before the delegation passed in.
            revocation_heads: RevocationStore::new(),
            revocations,
        }
    }

    /// Create a new GroupState, inserting proof chain into global stores
    /// using memoized digests instead of fresh serialization.
    /// Used during deferred-rebuild ingestion.
    pub async fn new_with_memoized_digest(
        delegation_head: Arc<Signed<Delegation<S, T, L>>>,
        delegations: Arc<Mutex<DelegationStore<S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<S, T, L>>>,
    ) -> Self {
        let id = GroupId(delegation_head.verifying_key().into());
        let mut heads = vec![delegation_head.dupe()];

        while let Some(head) = heads.pop() {
            if delegations
                .lock()
                .await
                .contains_key(&head.digest().into())
            {
                continue;
            }

            delegations.lock().await.insert(head.dupe());

            for dlg in head.payload().proof_lineage() {
                delegations.lock().await.insert(dlg.dupe());

                for rev in dlg.payload().after_revocations.as_slice() {
                    revocations.lock().await.insert(rev.dupe());

                    if let Some(proof) = &rev.payload().proof {
                        heads.push(proof.dupe());
                    }
                }
            }
        }

        let mut delegation_heads = DelegationStore::new();
        delegation_heads.insert(delegation_head);

        Self {
            id,
            delegation_heads,
            delegations,
            revocation_heads: RevocationStore::new(),
            revocations,
        }
    }

    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: Vec<Agent<S, T, L>>,
        delegations: Arc<Mutex<DelegationStore<S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<S, T, L>>>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let signer = MemorySigner::generate(csprng);
        let group_id = signer.verifying_key().into();

        let group = GroupState {
            id: GroupId(group_id),

            delegation_heads: DelegationStore::new(),
            delegations,

            revocation_heads: RevocationStore::new(),
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

            acc.delegation_heads.insert(Arc::new(dlg));
            Ok(acc)
        })
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn group_id(&self) -> GroupId {
        self.id
    }

    pub fn delegation_heads(&self) -> &DelegationStore<S, T, L> {
        &self.delegation_heads
    }

    pub fn revocation_heads(&self) -> &RevocationStore<S, T, L> {
        &self.revocation_heads
    }

    #[allow(clippy::type_complexity)]
    pub async fn add_delegation(
        &mut self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, T, L>>>, AddError> {
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

        let hash = self.delegations.lock().await.insert(delegation);
        Ok(hash)
    }

    #[allow(clippy::type_complexity)]
    pub async fn add_revocation(
        &mut self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, T, L>>>, AddError> {
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

        let hash = self.revocations.lock().await.insert(revocation);
        Ok(hash)
    }

    /// Insert a delegation with only validation and global store insertion.
    /// Skips delegation_heads/revocation_heads maintenance for batch performance.
    /// Call `recalculate_heads()` before rebuild after using this method.
    #[allow(clippy::type_complexity)]
    pub async fn add_delegation_bare(
        &mut self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, T, L>>>, AddError> {
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

        let hash = self.delegations.lock().await.insert(delegation);
        Ok(hash)
    }

    /// Insert a revocation with only validation and global store insertion.
    /// Skips heads maintenance for batch performance.
    /// Call `recalculate_heads()` before rebuild after using this method.
    #[allow(clippy::type_complexity)]
    pub async fn add_revocation_bare(
        &mut self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, T, L>>>, AddError> {
        #[cfg(not(target_arch = "wasm32"))]
        let arb_t0 = std::time::Instant::now();

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

        #[cfg(not(target_arch = "wasm32"))]
        let arb_t1 = std::time::Instant::now();

        let hash = self.revocations.lock().await.insert(revocation);

        #[cfg(not(target_arch = "wasm32"))]
        {
            let arb_t2 = std::time::Instant::now();
            let total = arb_t2 - arb_t0;
            if total.as_millis() > 50 {
                eprintln!(
                    "SLOW ADD_REV_BARE: total={:?} validate={:?} store={:?}",
                    total,
                    arb_t1 - arb_t0,
                    arb_t2 - arb_t1,
                );
            }
        }

        Ok(hash)
    }

    /// Recalculate delegation_heads and revocation_heads from the global stores.
    /// Must be called before rebuild after using `add_delegation_bare`/`add_revocation_bare`.
    pub async fn recalculate_heads(&mut self) {
        // A delegation is a head if no other delegation in this group uses it as a proof
        // (i.e., it's not an ancestor of any other delegation).
        let all_dlgs: Vec<Arc<Signed<Delegation<S, T, L>>>> = {
            let locked = self.delegations.lock().await;
            locked
                .values()
                .filter(|d| d.subject_id() == self.id.into())
                .map(|d| d.dupe())
                .collect()
        };

        // Collect all proof hashes (delegations that are ancestors of others)
        use std::collections::HashSet;
        let mut non_heads: HashSet<Digest<Signed<Delegation<S, T, L>>>> = HashSet::new();
        for dlg in &all_dlgs {
            for ancestor in dlg.payload.proof_lineage() {
                non_heads.insert(Digest::hash(ancestor.as_ref()));
            }
        }

        self.delegation_heads = DelegationStore::new();
        for dlg in &all_dlgs {
            let hash = Digest::hash(dlg.as_ref());
            if !non_heads.contains(&hash) {
                self.delegation_heads.insert(dlg.dupe());
            }
        }

        // For revocation heads: a revocation is a head if it's not superseded
        // For simplicity, include all revocations for this group as heads
        // (rebuild handles the full dependency analysis)
        let all_revs: Vec<Arc<Signed<Revocation<S, T, L>>>> = {
            let locked = self.revocations.lock().await;
            locked
                .values()
                .filter(|r| r.subject_id() == self.id.into())
                .map(|r| r.dupe())
                .collect()
        };

        self.revocation_heads = RevocationStore::new();
        for rev in all_revs {
            self.revocation_heads.insert(rev);
        }
    }

    pub async fn delegations_for(
        &self,
        agent: Agent<S, T, L>,
    ) -> Vec<Arc<Signed<Delegation<S, T, L>>>> {
        let mut dlgs = Vec::new();
        for delegation in self.delegations.lock().await.values() {
            if agent == delegation.payload().delegate {
                dlgs.push(delegation.dupe());
            }
        }
        dlgs
    }

    pub(crate) fn dummy_from_archive(
        archive: GroupStateArchive<T>,
        delegations: Arc<Mutex<DelegationStore<S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<S, T, L>>>,
    ) -> Self {
        Self {
            id: archive.id,

            delegation_heads: DelegationStore::new(),
            delegations,

            revocation_heads: RevocationStore::new(),
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

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable
    for GroupState<S, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.0.verifying_key()
    }
}
