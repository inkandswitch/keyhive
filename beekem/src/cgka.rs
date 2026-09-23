//! Exposes CGKA (Continuous Group Key Agreement) operations like deriving
//! a new application secret, rotating keys, and adding and removing members
//! from the group.
//!
//! A CGKA protocol is responsible for maintaining a stream of shared group keys
//! updated over time. We are using a variant of the TreeKEM protocol (which
//! we call BeeKEM) adapted for local-first contexts.
//!
//! We assume that all operations are received in causal order (a property
//! guaranteed by Keyhive as a whole).

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    encrypted::{encrypt_secret_with, EncryptedContent, PairedKey},
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{LeafKeyPair, NodeKey, ShareKeyMap},
    operation::{
        CgkaEpoch, CgkaOperation, CgkaOperationGraph, Invitation, InvitationSecret,
        PredecessorSecret,
    },
    pcs_key::{ApplicationSecret, PcsKey},
    transact::{Fork, Merge},
    tree::BeeKem,
};
use alloc::{boxed::Box, collections::BTreeSet, sync::Arc, vec::Vec};
use core::hash::{Hash, Hasher};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::async_signer::{self, AsyncSigner},
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

/// Exposes CGKA (Continuous Group Key Agreement) operations like deriving
/// a new application secret, rotating keys, and adding and removing members
/// from the group.
///
/// A CGKA protocol is responsible for maintaining a stream of shared group keys
/// updated over time. We are using a variant of the TreeKEM protocol (which
/// we call BeeKEM) adapted for local-first contexts.
///
/// We assume that all operations are received in causal order (a property
/// guaranteed by Keyhive as a whole).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cgka {
    doc_id: TreeId,
    /// The id of the member who owns this tree.
    pub owner_id: MemberId,
    /// The secret keys of the member who owns this tree.
    pub owner_sks: ShareKeyMap,
    pub(crate) tree: BeeKem,
    /// Graph of all operations seen (but not necessarily applied) so far.
    ops_graph: CgkaOperationGraph,
    /// Whether there are ops in the graph that have not been applied to the
    /// tree due to a structural change.
    pending_ops_for_structural_change: bool,
    // TODO: Enable policies to evict older entries.
    pcs_keys: CaMap<PcsKey>,

    /// The root secret each update operation produced, for the ones we can reach.
    pcs_keys_by_update: Map<Digest<Signed<CgkaOperation>>, PcsKey>,

    original_member: (MemberId, ShareKey),
    init_add_op: Signed<CgkaOperation>,
}

impl Hash for Cgka {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.doc_id.hash(state);
        self.owner_id.hash(state);
        self.owner_sks.hash(state);
        self.tree.hash(state);
        self.ops_graph.hash(state);
        self.pending_ops_for_structural_change.hash(state);
        self.pcs_keys.keys().collect::<BTreeSet<_>>().hash(state);
        self.pcs_keys_by_update
            .keys()
            .map(|k| k.as_slice())
            .collect::<BTreeSet<_>>()
            .hash(state);
        self.original_member.hash(state);
        self.init_add_op.hash(state);
    }
}

impl Cgka {
    pub async fn new<F: FutureForm, S: AsyncSigner<F>>(
        doc_id: TreeId,
        owner_id: MemberId,
        owner_pk: ShareKey,
        signer: &S,
    ) -> Result<Self, CgkaError> {
        let init_add_op = CgkaOperation::init_add(doc_id, owner_id, owner_pk);
        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, init_add_op).await?;
        Self::new_from_init_add(doc_id, owner_id, owner_pk, signed_op)
    }

    #[instrument(skip_all)]
    pub fn new_from_init_add(
        doc_id: TreeId,
        owner_id: MemberId,
        owner_pk: ShareKey,
        init_add_op: Signed<CgkaOperation>,
    ) -> Result<Self, CgkaError> {
        let tree = BeeKem::new(doc_id, owner_id, owner_pk)?;
        let mut cgka = Self {
            doc_id,
            owner_id,
            owner_sks: ShareKeyMap::new(),
            tree,
            ops_graph: CgkaOperationGraph::new(),
            pending_ops_for_structural_change: false,
            pcs_keys: CaMap::new(),
            pcs_keys_by_update: Map::new(),
            original_member: (owner_id, owner_pk),
            init_add_op: init_add_op.clone(),
        };
        cgka.ops_graph.add_local_op(&init_add_op);
        Ok(cgka)
    }

    #[instrument(skip_all)]
    pub fn with_new_owner(
        &self,
        my_id: MemberId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_sks = owner_sks;
        // Since the owner is changing, we need to find any invitations for the
        // new owner and record their secrets.
        cgka.record_secrets_from_invitations_for_owner();
        Ok(cgka)
    }

    pub fn init_add_op(&self) -> Signed<CgkaOperation> {
        self.init_add_op.clone()
    }

    /// Get the count of CGKA operations in the graph.
    pub fn ops_count(&self) -> usize {
        self.ops_graph.cgka_ops.len()
    }

    /// Derive an [`ApplicationSecret`] from our current [`PcsKey`] for new content
    /// to encrypt.
    ///
    /// If the tree does not currently contain a root key, then we must first
    /// perform a leaf key rotation. The new key pair is returned as the third element,
    /// which is `None` when there was no rotation.
    ///
    /// Returns a [`CgkaError::NoMembers`] error if the group is empty.
    ///
    /// # Security
    ///
    /// The returned key pair contains unencrypted secret key material.
    #[instrument(skip_all)]
    #[allow(clippy::type_complexity)]
    pub async fn new_app_secret_for<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef,
        R: rand::CryptoRng + rand::RngCore,
    >(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<
        (
            ApplicationSecret<T>,
            Option<Signed<CgkaOperation>>,
            Option<LeafKeyPair>,
        ),
        CgkaError,
    > {
        let mut op = None;
        let mut new_key_pair = None;
        let (current_pcs_key, current_op_hash) = if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            let (pcs_key, update_op, sampled_key_pair) = self
                .update::<F, S, R>(new_share_key, new_share_secret_key, signer, csprng)
                .await?;
            new_key_pair = sampled_key_pair;
            let op_hash = Digest::hash(&update_op);
            self.insert_pcs_key(&pcs_key, op_hash);
            op = Some(update_op);
            (pcs_key, op_hash)
        } else {
            // `has_pcs_key()` above guarantees a single head.
            debug_assert!(self.ops_graph.has_single_head());
            match self.record_tree_root_secret() {
                Some((op_hash, pcs_key)) => (pcs_key, op_hash),
                None => {
                    let pcs_key = self.pcs_key_from_tree_root()?;
                    let head = self
                        .ops_graph
                        .cgka_op_heads
                        .iter()
                        .next()
                        .copied()
                        .ok_or(CgkaError::UnknownPcsKey)?;
                    self.insert_pcs_key(&pcs_key, head);
                    (pcs_key, head)
                }
            }
        };
        let nonce = Siv::new(&current_pcs_key.into(), content, self.doc_id.as_bytes());
        Ok((
            current_pcs_key.derive_application_secret(
                &nonce,
                content_ref,
                &Digest::hash(pred_refs),
                &current_op_hash,
            ),
            op,
            new_key_pair,
        ))
    }

    /// Derive a decryption key for encrypted data.
    ///
    /// We must first derive a [`PcsKey`] for the encrypted data's associated
    /// hashes. Then we use that [`PcsKey`] to derive an [`ApplicationSecret`].
    #[instrument(skip_all)]
    pub fn decryption_key_for<T, Cr: ContentRef>(
        &mut self,
        encrypted: &EncryptedContent<T, Cr>,
    ) -> Result<SymmetricKey, CgkaError> {
        let pcs_key =
            self.pcs_key_from_hashes(&encrypted.pcs_key_hash, &encrypted.pcs_update_op_hash)?;
        self.insert_pcs_key(&pcs_key, encrypted.pcs_update_op_hash);
        let app_secret = pcs_key.derive_application_secret(
            &encrypted.nonce,
            &encrypted.content_ref,
            &encrypted.pred_refs,
            &encrypted.pcs_update_op_hash,
        );
        Ok(app_secret.key())
    }

    pub fn has_pcs_key(&self) -> bool {
        self.tree.has_root_key()
            && self.ops_graph.has_single_head()
            && self.ops_graph.add_heads.len() < 2
    }

    /// Add a member to the group. Returns the add operation or `None` if the
    /// member is already in the tree.
    #[instrument(skip_all)]
    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        pk: ShareKey,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        // Check after replay since a concurrent add of the same member might
        // have been pending.
        if self.tree.contains_id(&id) {
            return Ok(None);
        }
        // Find the update heads before the new leaf blanks the root so we can
        // put them in an invitation.
        let heads = self.ops_graph.cgka_op_heads.clone();
        let ancestors = self.reachable_ancestor_secrets(&heads);
        let invitation = self.invitation_for(pk, &ancestors);
        if invitation.is_none() {
            debug!(
                "no invitation root secret derived for {:?}; it can only read content written from now on",
                id
            );
        }
        let leaf_index = self.tree.push_leaf(id, pk.into());
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let add_predecessors = Vec::from_iter(self.ops_graph.add_heads.iter().cloned());
        let op = CgkaOperation::Add {
            added_id: id,
            pk,
            leaf_index,
            invitation: invitation.map(Box::new),
            predecessors,
            add_predecessors,
            doc_id: self.doc_id,
        };

        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.ops_graph.add_local_op(&signed_op);
        Ok(Some(signed_op))
    }

    /// Add multiple members to group.
    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(MemberId, ShareKey)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let mut ops = Vec::new();
        for m in members {
            ops.push(self.add::<F, S>(m.0, m.1, signer).await?);
        }
        Ok(ops.into_iter().flatten().collect())
    }

    /// Build an invitation for a member we are adding, wrapping each of
    /// `ancestor_secrets` for it. Returns `None` if none of `ancestor_secrets`
    /// could be encrypted to the invitee.
    #[instrument(skip_all)]
    fn invitation_for(
        &self,
        invitee_pk: ShareKey,
        ancestor_secrets: &[(Digest<Signed<CgkaOperation>>, PcsKey)],
    ) -> Option<Invitation> {
        let (inviter_pk, inviter_sk) = self.inviter_key_pair()?;
        let key = PairedKey::new(&inviter_sk, &invitee_pk);
        let head_secrets: Vec<InvitationSecret> = ancestor_secrets
            .iter()
            .filter_map(|(update_op_hash, secret)| {
                match encrypt_secret_with(&key, self.doc_id.as_bytes(), secret.0) {
                    Ok(encrypted_root_secret) => Some(InvitationSecret {
                        update_op_hash: *update_op_hash,
                        encrypted_root_secret,
                    }),
                    Err(e) => {
                        warn!(
                            ?e,
                            ?update_op_hash,
                            "could not encrypt a root secret to an invitee"
                        );
                        None
                    }
                }
            })
            .collect();
        if head_secrets.is_empty() {
            return None;
        }
        Some(Invitation {
            inviter_pk,
            head_secrets,
        })
    }

    /// A key pair at our own leaf, for the Diffie-Hellman exchange that
    /// encrypts an invitation.
    ///
    /// Falls back to Public's leaf if we are not in the tree but it is, just
    /// as [`Self::update`] does. Returns `None` if neither has access.
    fn inviter_key_pair(&self) -> Option<(ShareKey, ShareSecretKey)> {
        let id = if self.tree.contains_id(&self.owner_id) {
            self.owner_id
        } else {
            MemberId::public()
        };
        self.tree
            .node_key_for_id(id)
            .ok()?
            .keys()
            .into_iter()
            .find_map(|pk| self.owner_sks.get(&pk).map(|sk| (pk, *sk)))
    }

    /// Record the root secrets of `op`'s invitation, if it is addressed to us.
    fn record_secret_from_invitation(&mut self, op: &Signed<CgkaOperation>) {
        let CgkaOperation::Add {
            added_id,
            invitation: Some(invitation),
            ..
        } = &op.payload
        else {
            return;
        };
        if *added_id != self.owner_id && *added_id != MemberId::public() {
            return;
        }
        let inviter_pk = invitation.inviter_pk;
        let opened: Vec<_> = invitation
            .head_secrets
            .iter()
            .filter_map(|invited| {
                if self
                    .pcs_keys_by_update
                    .contains_key(&invited.update_op_hash)
                {
                    return None;
                }
                let pcs_key = self.derive_invitation_secret(inviter_pk, invited)?;
                Some((invited.update_op_hash, pcs_key))
            })
            .collect();
        for (update_op_hash, pcs_key) in opened {
            self.insert_pcs_key(&pcs_key, update_op_hash);
        }
    }

    /// Record the invitations addressed to the owner of this [`Cgka`].
    ///
    /// Call after a change of owner.
    fn record_secrets_from_invitations_for_owner(&mut self) {
        let ops: Vec<_> = self.ops_graph.cgka_ops.values().cloned().collect();
        for op in ops {
            self.record_secret_from_invitation(&op);
        }
    }

    /// Decrypt one invited root secret, if we hold the key it was encrypted to.
    fn derive_invitation_secret(
        &self,
        inviter_pk: ShareKey,
        invitation_secret: &InvitationSecret,
    ) -> Option<PcsKey> {
        let plaintext = self
            .owner_sks
            .try_decrypt_encryption(inviter_pk, &invitation_secret.encrypted_root_secret)
            .ok()?;
        let bytes = <[u8; 32]>::try_from(plaintext).ok()?;
        Some(PcsKey::new(ShareSecretKey::force_from_bytes(bytes)))
    }

    /// Remove member from group.
    ///
    /// Returns `Ok(None)` if the member is not in the group.
    #[instrument(skip_all)]
    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        // Check after replay since a concurrent add of the same member might
        // have been pending.
        if !self.tree.contains_id(&id) {
            return Ok(None);
        }
        let (leaf_idx, removed_keys) = self.tree.remove_id(id)?;
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let op = CgkaOperation::Remove {
            id,
            leaf_idx,
            removed_keys,
            predecessors,
            doc_id: self.doc_id,
        };
        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.ops_graph.add_local_op(&signed_op);
        Ok(Some(signed_op))
    }

    /// Update leaf key pair for this Identifier.
    /// This also triggers a tree path update for that leaf.
    /// If the owner is not in the tree but Public is, falls back to
    /// encrypting from Public's leaf using Public's well-known keys.
    ///
    /// Returns a [`CgkaError::NoMembers`] error if the group is empty.
    #[instrument(skip_all)]
    pub async fn update<F: FutureForm, S: AsyncSigner<F>, R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, Signed<CgkaOperation>, Option<LeafKeyPair>), CgkaError> {
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        if self.group_size() == 0 {
            return Err(CgkaError::NoMembers);
        }
        let mut is_public = false;
        let (update_id, update_pk, update_sk) = if self.tree.contains_id(&self.owner_id) {
            (self.owner_id, new_pk, new_sk)
        } else {
            let public_id = MemberId::public();
            let NodeKey::ShareKey(pk) = self
                .tree
                .node_key_for_id(public_id)
                .map_err(|_| CgkaError::IdentifierNotFound)?
            else {
                return Err(CgkaError::ShareKeyNotFound);
            };
            let sk = *self.owner_sks.get(&pk).ok_or(CgkaError::ShareKeyNotFound)?;
            is_public = true;
            (public_id, pk, sk)
        };
        self.owner_sks.insert(update_pk, update_sk);
        let maybe_key_and_path =
            self.tree
                .encrypt_path(update_id, update_pk, &mut self.owner_sks, csprng)?;
        if let Some((pcs_key, new_path)) = maybe_key_and_path {
            let heads = self.ops_graph.cgka_op_heads.clone();
            let predecessors = Vec::from_iter(heads.iter().cloned());
            let ancestors = self.reachable_ancestor_secrets(&heads);
            let predecessor_secrets = self.predecessor_secrets(&pcs_key, &ancestors);
            let op = CgkaOperation::Update {
                id: update_id,
                new_path: Box::new(new_path),
                predecessor_secrets,
                predecessors,
                doc_id: self.doc_id,
            };

            let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
            self.ops_graph.add_local_op(&signed_op);
            self.insert_pcs_key(&pcs_key, Digest::hash(&signed_op));
            let new_key_pair = if is_public {
                None
            } else {
                Some((update_pk, update_sk))
            };
            Ok((pcs_key, signed_op, new_key_pair))
        } else {
            Err(CgkaError::IdentifierNotFound)
        }
    }

    /// The [`ShareKey`] currently at the owner's leaf.
    ///
    /// Returns [`None`] when the owner is not in the tree.
    pub fn owner_leaf_key(&self) -> Option<ShareKey> {
        match self.tree.node_key_for_id(self.owner_id).ok()? {
            NodeKey::ShareKey(pk) => Some(pk),
            // `insert_leaf_at` keeps only the lowest key per leaf so this is purely defensive.
            NodeKey::ConflictKeys(keys) => Some(keys.iter().copied().min()?),
        }
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// The members currently in the tree.
    pub fn member_ids(&self) -> impl Iterator<Item = MemberId> + '_ {
        self.tree.member_ids()
    }

    /// Merges concurrent [`CgkaOperation`]. Returns `Ok(true)` if merge is successful.
    ///
    /// If we receive a concurrent membership change (i.e., add or remove), then
    /// we add it to our ops graph but don't apply it yet. If there are no outstanding
    /// membership changes and we receive a concurrent update, we can apply it
    /// immediately.
    #[instrument(skip_all)]
    pub fn merge_concurrent_operation(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(false);
        }
        let predecessors = op.payload.predecessors();
        if !self.ops_graph.contains_predecessors(&predecessors) {
            return Err(CgkaError::OutOfOrderOperation);
        }
        self.record_secret_from_invitation(&op);
        let is_concurrent = !self.ops_graph.heads_contained_in(&predecessors);
        if is_concurrent {
            if self.pending_ops_for_structural_change {
                self.ops_graph.add_op(&op, &predecessors);
            } else if matches!(
                op.payload,
                CgkaOperation::Add { .. } | CgkaOperation::Remove { .. }
            ) {
                self.pending_ops_for_structural_change = true;
                self.ops_graph.add_op(&op, &predecessors);
            } else {
                self.apply_operation_and_record_root_secret(op)?;
            }
        } else {
            if self.should_replay() {
                self.replay_ops_graph()?;
            }
            self.apply_operation_and_record_root_secret(op)?;
        }
        Ok(true)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.ops_graph.topsort_graph()
    }

    pub fn contains_predecessors(&self, preds: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.ops_graph.contains_predecessors(preds)
    }

    // Apply `op`. If it's a [`CgkaOperation::Update`], record the corresponding
    // root secret.
    #[instrument(skip_all)]
    fn apply_operation_and_record_root_secret(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<(), CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(());
        }
        let is_update = matches!(op.payload, CgkaOperation::Update { .. });
        self.apply_operation_to_tree(op)?;
        if is_update {
            // Record while the tree has the root secret this update produced.
            // Otherwise, a later update would need to replay history to derive
            // it again.
            self.record_tree_root_secret();
        }
        Ok(())
    }

    /// Apply a [`CgkaOperation`] without recording a root secret.
    ///
    /// A replay applies the whole history. Always recording per update would
    /// derive a root secret for every update when only the last one is needed.
    #[instrument(skip_all)]
    fn apply_operation_to_tree(&mut self, op: Arc<Signed<CgkaOperation>>) -> Result<(), CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(());
        }
        match op.payload {
            CgkaOperation::Add { added_id, pk, .. } => {
                // A concurrent history might have added the same member.
                if !self.tree.contains_id(&added_id) {
                    self.tree.push_leaf(added_id, pk.into());
                }
            }
            CgkaOperation::Remove { id, .. } => {
                match self.tree.remove_id(id) {
                    Ok(_) => {}
                    // A concurrent history might have removed the same member.
                    Err(CgkaError::IdentifierNotFound) => {}
                    Err(e) => return Err(e),
                }
            }
            CgkaOperation::Update { ref new_path, .. } => {
                self.tree.apply_path(new_path);
            }
        }
        self.ops_graph.add_op(&op, &op.payload.predecessors());
        self.record_secret_from_invitation(&op);
        Ok(())
    }

    /// Apply operations grouped into "epochs", where each epoch contains an ordered
    /// set of concurrent operations.
    #[instrument(skip_all)]
    fn apply_epochs(&mut self, epochs: &NonEmpty<CgkaEpoch>) -> Result<(), CgkaError> {
        for epoch in epochs {
            if epoch.len() == 1 {
                self.apply_operation_to_tree(epoch[0].clone())?;
            } else {
                // If all operations in this epoch are updates, we can apply them
                // directly and move on to the next epoch.
                if epoch
                    .iter()
                    .all(|op| matches!(op.payload, CgkaOperation::Update { .. }))
                {
                    for op in epoch.iter() {
                        self.apply_operation_to_tree(op.clone())?;
                    }
                    continue;
                }

                // An epoch with at least one membership change requires blanking
                // removed paths and sorting added leaves after all ops are applied.
                let mut added_ids = Set::new();
                let mut removed_ids = Set::new();
                for op in epoch.iter() {
                    match op.payload {
                        CgkaOperation::Add { added_id, .. } => {
                            added_ids.insert(added_id);
                        }
                        CgkaOperation::Remove { id, leaf_idx, .. } => {
                            removed_ids.insert((id, leaf_idx));
                        }
                        _ => {}
                    }
                    self.apply_operation_to_tree(op.clone())?;
                }
                self.tree
                    .sort_leaves_and_blank_paths_for_concurrent_membership_changes(
                        added_ids,
                        removed_ids,
                    );
            }
        }
        Ok(())
    }

    /// Decrypt tree secret to derive [`PcsKey`].
    pub fn pcs_key_from_tree_root(&mut self) -> Result<PcsKey, CgkaError> {
        let key = match self
            .tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
        {
            Ok(k) => k,
            Err(e) => {
                // When deriving as the owner fails and Public is a member, read as
                // Public instead.
                let public = MemberId::public();
                if self.owner_id != public && self.tree.contains_id(&public) {
                    self.tree.decrypt_tree_secret(public, &mut self.owner_sks)?
                } else {
                    return Err(e);
                }
            }
        };
        Ok(PcsKey::new(key))
    }

    /// Derive [`PcsKey`] for provided hashes.
    ///
    /// If we have not seen this [`PcsKey`] before, we look for it in an invitation
    /// and then along the predecessor secret chain, and rebuild the tree state for
    /// `update_op_hash` only if neither has it.
    #[instrument(skip_all)]
    fn pcs_key_from_hashes(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        if let Some(pcs_key) = self.pcs_keys.get(pcs_key_hash) {
            return Ok(*pcs_key.clone());
        }
        if self.has_pcs_key() {
            if let Ok(pcs_key) = self.pcs_key_from_tree_root() {
                if &Digest::hash(&pcs_key) == pcs_key_hash {
                    return Ok(pcs_key);
                }
            }
        }
        // Record the root secret so we can traverse its predecessors.
        self.record_tree_root_secret();
        if let Some((predecessor_op_hash, pcs_key)) =
            self.pcs_key_from_predecessor_secrets(pcs_key_hash)
        {
            self.insert_pcs_key(&pcs_key, predecessor_op_hash);
            return Ok(pcs_key);
        }
        self.derive_pcs_key_for_op(update_op_hash)
    }

    /// The root secrets we can derive, for the nearest update ancestors of
    /// `heads` and for every update recorded as outside of the predecessor
    /// secrets chain.
    #[instrument(skip_all)]
    fn reachable_ancestor_secrets(
        &mut self,
        heads: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let mut targets = self.ops_graph.nearest_update_ancestors(heads);
        targets.extend(self.ops_graph.unchained_updates.iter().copied());

        let mut found = Vec::new();
        for op_hash in targets {
            let secret = self.root_secret_for(&op_hash).or_else(|| {
                // Failing to derive is expected for a root secret from before
                // we joined the tree.
                self.derive_pcs_key_for_op(&op_hash).ok()?;
                self.root_secret_for(&op_hash)
            });
            if let Some(secret) = secret {
                found.push((op_hash, secret));
            }
        }
        // The ancestors are an unordered set, so sort to keep the bytes of the
        // operation these are included in stable.
        found.sort_unstable_by_key(|(op_hash, _)| *op_hash);
        found
    }

    /// Encrypt each of `ancestor_secrets` under a key derived from `pcs_key` so that
    /// a member who can derive `pcs_key` can derive those too. A secret that fails
    /// to encrypt is dropped from this operation. A later update by a member that
    /// can derive it can put it in the chain instead.
    #[instrument(skip_all)]
    fn predecessor_secrets(
        &self,
        pcs_key: &PcsKey,
        ancestor_secrets: &[(Digest<Signed<CgkaOperation>>, PcsKey)],
    ) -> Vec<PredecessorSecret> {
        let key = pcs_key.derive_predecessor_secrets_key();
        ancestor_secrets
            .iter()
            .filter_map(|(op_hash, secret)| {
                match key.try_seal(secret.0.as_slice(), self.doc_id.as_bytes()) {
                    Ok(encrypted_root_secret) => Some(PredecessorSecret {
                        update_op_hash: *op_hash,
                        encrypted_root_secret,
                    }),
                    Err(e) => {
                        warn!(?e, ?op_hash, "could not encrypt a predecessor root secret");
                        None
                    }
                }
            })
            .collect()
    }

    /// Derive the current root secret and record it for the update that
    /// produced it.
    ///
    /// Returns `None` unless the tree has a root key, the current heads have
    /// exactly one nearest update ancestor, and the secret corresponds with that
    /// update's own path.
    #[instrument(skip_all)]
    fn record_tree_root_secret(&mut self) -> Option<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        if !self.has_pcs_key() {
            return None;
        }
        let mut ancestors = self
            .ops_graph
            .nearest_update_ancestors(&self.ops_graph.cgka_op_heads)
            .into_iter();
        let (Some(op_hash), None) = (ancestors.next(), ancestors.next()) else {
            return None;
        };
        if let Some(pcs_key) = self.pcs_keys_by_update.get(&op_hash).copied() {
            return Some((op_hash, pcs_key));
        }
        let pcs_key = self.pcs_key_from_tree_root().ok()?;
        self.insert_pcs_key(&pcs_key, op_hash);
        // `insert_pcs_key` will only record the secret if it actually corresponds with
        // `op_hash`. Return what we recorded.
        self.pcs_keys_by_update
            .get(&op_hash)
            .map(|pcs_key| (op_hash, *pcs_key))
    }

    /// The root secret `op_hash` produced, if we can reach it without a rebuild.
    fn root_secret_for(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> Option<PcsKey> {
        self.pcs_keys_by_update.get(op_hash).copied()
    }

    /// Every root secret we can reach without a rebuild, paired with the update it
    /// came from.
    fn known_root_secrets(
        &self,
    ) -> impl Iterator<Item = (Digest<Signed<CgkaOperation>>, PcsKey)> + '_ {
        self.pcs_keys_by_update
            .iter()
            .map(|(op_hash, key)| (*op_hash, *key))
    }

    /// Return the requested PCS key, if we can reach it by decrypting predecessor
    /// secrets starting from a root secret we already have access to.
    #[instrument(skip_all)]
    fn pcs_key_from_predecessor_secrets(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
    ) -> Option<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let mut frontier: Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> =
            self.known_root_secrets().collect();
        let mut seen: Set<(Digest<Signed<CgkaOperation>>, Digest<PcsKey>)> = Set::new();
        while let Some((op_hash, pcs_key)) = frontier.pop() {
            if !seen.insert((op_hash, Digest::hash(&pcs_key))) {
                continue;
            }
            let Some(op) = self.ops_graph.cgka_ops.get(&op_hash).cloned() else {
                continue;
            };
            let CgkaOperation::Update {
                predecessor_secrets,
                ..
            } = &op.payload
            else {
                continue;
            };
            let key = pcs_key.derive_predecessor_secrets_key();
            for predecessor in predecessor_secrets {
                let Some(found) = Self::decrypt_predecessor_secret(&key, predecessor) else {
                    continue;
                };
                // Record every secret we derive to prevent later requests from
                // requiring redundant traversals.
                self.insert_pcs_key(&found, predecessor.update_op_hash);
                if Digest::hash(&found) == *pcs_key_hash {
                    return Some((predecessor.update_op_hash, found));
                }
                frontier.push((predecessor.update_op_hash, found));
            }
        }
        None
    }

    /// Decrypt the provided predecessor secret using `key`. Returns `None` if it
    /// fails to decrypt or is not 32 bytes.
    fn decrypt_predecessor_secret(
        key: &SymmetricKey,
        predecessor: &PredecessorSecret,
    ) -> Option<PcsKey> {
        let plaintext = key.try_open(&predecessor.encrypted_root_secret).ok()?;
        let bytes = <[u8; 32]>::try_from(plaintext).ok()?;
        Some(PcsKey::new(ShareSecretKey::force_from_bytes(bytes)))
    }

    /// Derive [`PcsKey`] for this operation hash.
    #[instrument(skip_all)]
    fn derive_pcs_key_for_op(
        &mut self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        if !self.ops_graph.contains_op_hash(op_hash) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let mut heads = Set::new();
        heads.insert(*op_hash);
        let ops = self.ops_graph.topsort_for_heads(&heads)?;
        self.rebuild_pcs_key(ops)
    }

    /// Whether we have unresolved concurrency that requires a replay to resolve.
    fn should_replay(&self) -> bool {
        !self.ops_graph.cgka_op_heads.is_empty()
            && (self.pending_ops_for_structural_change || !self.ops_graph.has_single_head())
    }

    /// Replay all ops in our graph in a deterministic order.
    #[instrument(skip_all)]
    fn replay_ops_graph(&mut self) -> Result<(), CgkaError> {
        let ordered_ops = self.ops_graph.topsort_graph()?;
        let rebuilt_cgka = self.rebuild_cgka(ordered_ops)?;
        self.update_cgka_from(&rebuilt_cgka);
        self.pending_ops_for_structural_change = false;
        Ok(())
    }

    /// Build a new [`Cgka`] for the provided non-empty list of [`CgkaEpoch`]s.
    #[instrument(skip_all)]
    fn rebuild_cgka(&mut self, epochs: NonEmpty<CgkaEpoch>) -> Result<Cgka, CgkaError> {
        let mut rebuilt_cgka = Cgka::new_from_init_add(
            self.doc_id,
            self.original_member.0,
            self.original_member.1,
            self.init_add_op.clone(),
        )?
        .with_new_owner(self.owner_id, self.owner_sks.clone())?;
        rebuilt_cgka.apply_epochs(&epochs)?;
        if rebuilt_cgka.has_pcs_key() {
            let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
            rebuilt_cgka.insert_pcs_key(&pcs_key, Digest::hash(&epochs.last()[0]));
        }
        Ok(rebuilt_cgka)
    }

    /// Derive a [`PcsKey`] by rebuilding a [`Cgka`] from the provided non-empty
    /// list of [`CgkaEpoch`]s.
    #[instrument(skip_all)]
    fn rebuild_pcs_key(&mut self, epochs: NonEmpty<CgkaEpoch>) -> Result<PcsKey, CgkaError> {
        if !matches!(epochs.last()[0].payload, CgkaOperation::Update { .. }) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let mut rebuilt_cgka = Cgka::new_from_init_add(
            self.doc_id,
            self.original_member.0,
            self.original_member.1,
            self.init_add_op.clone(),
        )?
        .with_new_owner(self.owner_id, self.owner_sks.clone())?;
        rebuilt_cgka.apply_epochs(&epochs)?;
        let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
        self.insert_pcs_key(&pcs_key, Digest::hash(&epochs.last()[0]));
        Ok(pcs_key)
    }

    /// Cache a root secret and record it for `op_hash` if that was the update
    /// that produced it.
    #[instrument(skip_all)]
    fn insert_pcs_key(&mut self, pcs_key: &PcsKey, op_hash: Digest<Signed<CgkaOperation>>) {
        self.pcs_keys.insert((*pcs_key).into());
        if self.pcs_keys_by_update.contains_key(&op_hash) {
            return;
        }
        let Some(root_pk) = self.root_share_key_for(&op_hash) else {
            return;
        };
        if pcs_key.0.share_key() != root_pk {
            debug!(
                ?op_hash,
                "a root secret does not match the update it was paired with"
            );
            return;
        }
        self.pcs_keys_by_update.insert(op_hash, *pcs_key);
    }

    /// The share key at the root of the tree when `op_hash` is applied.
    ///
    /// Returns `None` if we do not have the operation, if it is not an update, or if
    /// its path does not end in a single root share key.
    fn root_share_key_for(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> Option<ShareKey> {
        let Some(CgkaOperation::Update { new_path, .. }) =
            self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload)
        else {
            return None;
        };
        let (_, root_node) = new_path.path.last()?;
        match root_node.node_key() {
            NodeKey::ShareKey(pk) => Some(pk),
            NodeKey::ConflictKeys(_) => None,
        }
    }

    /// Extend our state with that of the provided [`Cgka`].
    #[instrument(skip_all)]
    fn update_cgka_from(&mut self, other: &Self) {
        self.tree = other.tree.clone();
        self.owner_sks.extend(&other.owner_sks);
        self.pcs_keys.extend(
            other
                .pcs_keys
                .iter()
                .map(|(hash, key)| (*hash, key.clone())),
        );
        self.pcs_keys_by_update
            .extend(other.pcs_keys_by_update.iter());
        self.pending_ops_for_structural_change = other.pending_ops_for_structural_change;
    }
}

impl Fork for Cgka {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for Cgka {
    fn merge(&mut self, fork: Self::Forked) {
        self.owner_sks.merge(fork.owner_sks);
        self.ops_graph.merge(fork.ops_graph);
        self.pcs_keys.merge(fork.pcs_keys);
        self.pcs_keys_by_update
            .extend(fork.pcs_keys_by_update.iter());
        self.replay_ops_graph()
            .expect("two valid graphs should always merge causal consistency");
    }
}

#[cfg(feature = "test_utils")]
impl Cgka {
    pub fn secret_from_root(&mut self) -> Result<PcsKey, CgkaError> {
        self.pcs_key_from_tree_root()
    }

    pub fn secret(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        self.pcs_key_from_hashes(pcs_key_hash, update_op_hash)
    }
}
