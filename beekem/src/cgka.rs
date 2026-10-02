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
    encrypted::{encrypt_secret_with, EncryptedContent, PairedKey},
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{LeafKeyPair, NodeKey, ShareKeyMap},
    operation::{
        CgkaAuthorization, CgkaBatch, CgkaOperation, CgkaOperationGraph, Invitation,
        InvitationSecret, PredecessorSecret,
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
    pub(crate) doc_id: TreeId,
    /// The id of the member who owns this tree.
    pub owner_id: MemberId,
    /// The secret keys of the member who owns this tree.
    pub owner_sks: ShareKeyMap,
    pub(crate) tree: BeeKem,
    /// Graph of all operations seen (but not necessarily applied) so far.
    pub(crate) ops_graph: CgkaOperationGraph,
    /// Whether operations were recorded in the graph but not applied to the
    /// tree.
    pending_replay: bool,

    /// The root secret each update operation produced, for the updates whose
    /// secret we have recorded.
    // TODO: Enable policies to evict older entries.
    pub(crate) pcs_keys_by_update: Map<Digest<Signed<CgkaOperation>>, PcsKey>,

    /// Updates whose corresponding root secrets we've seen another update wrap correctly.
    pub(crate) chained_updates: Set<Digest<Signed<CgkaOperation>>>,
}

impl Hash for Cgka {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.doc_id.hash(state);
        self.owner_id.hash(state);
        self.owner_sks.hash(state);
        self.tree.hash(state);
        self.ops_graph.hash(state);
        self.pending_replay.hash(state);
        self.pcs_keys_by_update
            .keys()
            .map(|k| k.as_slice())
            .collect::<BTreeSet<_>>()
            .hash(state);
        self.chained_updates
            .iter()
            .collect::<BTreeSet<_>>()
            .hash(state);
    }
}

impl Cgka {
    pub fn new(doc_id: TreeId, owner_id: MemberId, owner_sks: ShareKeyMap) -> Self {
        Self {
            doc_id,
            owner_id,
            owner_sks,
            tree: BeeKem::new(doc_id),
            ops_graph: CgkaOperationGraph::new(),
            pending_replay: false,
            pcs_keys_by_update: Map::new(),
            chained_updates: Set::new(),
        }
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
    /// Returns a [`CgkaError::NoMembers`] error if the group is empty and a
    /// [`CgkaError::UnknownPcsKey`] error if the tree's root secret cannot be
    /// recorded for the update that produced it.
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
            op = Some(update_op);
            (pcs_key, op_hash)
        } else {
            // `has_pcs_key()` above guarantees a single head.
            debug_assert!(self.ops_graph.has_single_head());
            match self.record_secret_from_tree() {
                Some((op_hash, pcs_key)) => (pcs_key, op_hash),
                None => {
                    // If there is a decryption error, return it. Otherwise, return
                    // `UnknownPcsKey`.
                    self.pcs_key_from_tree_root()?;
                    return Err(CgkaError::UnknownPcsKey);
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
        self.record_root_secret_for(&pcs_key, encrypted.pcs_update_op_hash);
        let app_secret = pcs_key.derive_application_secret(
            &encrypted.nonce,
            &encrypted.content_ref,
            &encrypted.pred_refs,
            &encrypted.pcs_update_op_hash,
        );
        Ok(app_secret.key())
    }

    pub fn has_pcs_key(&self) -> bool {
        self.tree.has_root_key() && self.ops_graph.has_single_head()
    }

    /// Add a member to the group. Returns the add operation or `None` if the
    /// member is already in the tree.
    ///
    /// `authorization` refers to the membership delegation that generated this add.
    #[instrument(skip_all)]
    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        pk: ShareKey,
        authorization: CgkaAuthorization,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.replay_if_pending()?;
        let ancestors = if self.inviter_key_pair().is_some() {
            self.reachable_ancestor_secrets()
        } else {
            Vec::new()
        };
        self.add_with_ancestors::<F, S>(id, pk, authorization, &ancestors, signer)
            .await
    }

    /// Add multiple members to group.
    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(MemberId, ShareKey, CgkaAuthorization)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        self.replay_if_pending()?;
        let mut ancestors = None;
        let mut ops = Vec::new();
        for (id, pk, authorization) in members {
            let ancestor_secrets: &[_] = if self.inviter_key_pair().is_some() {
                ancestors.get_or_insert_with(|| self.reachable_ancestor_secrets())
            } else {
                &[]
            };
            ops.extend(
                self.add_with_ancestors::<F, S>(id, pk, authorization, ancestor_secrets, signer)
                    .await?,
            );
        }
        Ok(ops)
    }

    /// Add a member whose invitation wraps `ancestor_secrets`. Call only once
    /// any pending replay is done.
    async fn add_with_ancestors<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        pk: ShareKey,
        authorization: CgkaAuthorization,
        ancestor_secrets: &[(Digest<Signed<CgkaOperation>>, PcsKey)],
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if self.tree.contains_id(&id) {
            return Ok(None);
        }
        let invitation = self.invitation_for(pk, ancestor_secrets);
        if invitation.is_none() {
            debug!(
                "no invitation root secret derived for {:?}, so it cannot read content encrypted before this add",
                id
            );
        }
        let leaf_index = self.tree.push_leaf(id, pk.into());
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().copied());
        let op = CgkaOperation::Add {
            added_id: id,
            pk,
            leaf_index,
            invitation: invitation.map(Box::new),
            predecessors,
            doc_id: self.doc_id,
            authorization,
        };

        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.record_op(&signed_op)?;
        Ok(Some(signed_op))
    }

    /// Build an invitation for a member we are adding, wrapping each of
    /// `ancestor_secrets` for it. Returns `None` if [`Self::inviter_key_pair`]
    /// finds no key pair or if none of `ancestor_secrets` could be encrypted to
    /// the invitee.
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
    fn inviter_key_pair(&self) -> Option<(ShareKey, ShareSecretKey)> {
        if !self.tree.contains_id(&self.owner_id) {
            return None;
        }
        self.tree
            .node_key_for_id(self.owner_id)
            .ok()?
            .keys()
            .into_iter()
            .find_map(|pk| self.owner_sks.get(&pk).map(|sk| (pk, *sk)))
    }

    /// Record the root secrets of `op`'s invitation if it is addressed to us or
    /// to Public.
    pub(crate) fn record_secrets_from_invitation(&mut self, op: &Signed<CgkaOperation>) {
        let CgkaOperation::Add {
            added_id,
            invitation: Some(invitation),
            ..
        } = &op.payload
        else {
            return;
        };
        if *added_id != self.owner_id && !added_id.is_public() {
            return;
        }

        for invited in &invitation.head_secrets {
            if self
                .pcs_keys_by_update
                .contains_key(&invited.update_op_hash)
            {
                continue;
            }
            if let Some(pcs_key) = self.derive_invitation_secret(invitation.inviter_pk, invited) {
                self.record_root_secret_for(&pcs_key, invited.update_op_hash);
            }
        }
    }

    /// Add `op` to the operation graph and, if it includes an invitation for us,
    /// record those root secrets.
    fn record_op(&mut self, op: &Signed<CgkaOperation>) -> Result<(), CgkaError> {
        self.ops_graph.add_op(op)?;
        self.record_secrets_from_invitation(op);
        Ok(())
    }

    /// Record the root secrets from every invitation addressed to the owner of
    /// this [`Cgka`].
    ///
    /// Call after a change of owner.
    fn record_secrets_from_invitations_for_owner(&mut self) {
        let owner_id = self.owner_id;
        let invited: Vec<_> = self
            .ops_graph
            .cgka_ops
            .values()
            .filter(|op| {
                matches!(
                    op.payload,
                    CgkaOperation::Add { added_id, invitation: Some(_), .. }
                        if added_id == owner_id || added_id.is_public()
                )
            })
            .cloned()
            .collect();
        for op in invited {
            self.record_secrets_from_invitation(&op);
        }
    }

    /// Decrypt one invited root secret if we have the key it was encrypted to.
    fn derive_invitation_secret(
        &self,
        inviter_pk: ShareKey,
        invitation_secret: &InvitationSecret,
    ) -> Option<PcsKey> {
        let plaintext = self
            .owner_sks
            .try_decrypt_encryption(inviter_pk, &invitation_secret.encrypted_root_secret)
            .ok()?;
        PcsKey::from_plaintext(plaintext)
    }

    /// Remove member from group.
    ///
    /// `authorization` refers to the membership revocation that generated this removal.
    ///
    /// Returns `Ok(None)` if the member is not in the group.
    #[instrument(skip_all)]
    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        authorization: CgkaAuthorization,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.replay_if_pending()?;
        // Check after replay since a concurrent add of the same member might
        // have been pending.
        if !self.tree.contains_id(&id) {
            return Ok(None);
        }
        let (leaf_idx, removed_keys) = self.tree.remove_id(id)?;
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().copied());
        let op = CgkaOperation::Remove {
            id,
            leaf_idx,
            removed_keys,
            predecessors,
            doc_id: self.doc_id,
            authorization,
        };
        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.record_op(&signed_op)?;
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
        self.replay_if_pending()?;
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
            let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().copied());
            let ancestors = self.reachable_ancestor_secrets();
            let predecessor_secrets = self.predecessor_secrets(&pcs_key, &ancestors);
            let op = CgkaOperation::Update {
                id: update_id,
                new_path: Box::new(new_path),
                predecessor_secrets,
                predecessors,
                doc_id: self.doc_id,
            };

            let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
            self.record_op(&signed_op)?;
            self.record_root_secret_for(&pcs_key, Digest::hash(&signed_op));
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

    /// Replay the operation graph to rebuild the tree if operations were
    /// recorded but not applied.
    fn replay_if_pending(&mut self) -> Result<(), CgkaError> {
        if self.pending_replay {
            self.replay_ops_graph()?;
        }
        Ok(())
    }

    /// The members currently in the tree.
    ///
    /// Resolves any outstanding concurrent membership change first so the
    /// answer reflects every operation received rather than only those already
    /// applied.
    pub fn member_ids(&mut self) -> Result<impl Iterator<Item = MemberId> + '_, CgkaError> {
        self.replay_if_pending()?;
        Ok(self.tree.member_ids())
    }

    /// Merges concurrent [`CgkaOperation`]. Returns `Ok(true)` if merge is successful.
    ///
    /// If we receive a concurrent add or remove, or a concurrent update that a
    /// replay would place in the same batch as one, we add it to our ops graph
    /// but don't apply it yet. Once anything is recorded this way, every later
    /// concurrent operation is recorded too until the next replay. Any other
    /// concurrent update is merged into the tree immediately.
    ///
    /// Returns [`CgkaError::WrongDocument`] if `op` is for a different document.
    #[instrument(skip_all)]
    pub fn merge_concurrent_operation(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        if *op.payload.doc_id() != self.doc_id {
            return Err(CgkaError::WrongDocument);
        }
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(false);
        }
        self.ops_graph.check_can_add(&op.payload)?;
        let predecessors = op.payload.predecessors();
        let is_concurrent = !self.ops_graph.heads_contained_in(&predecessors);
        if is_concurrent {
            self.pending_replay = self.pending_replay
                || op.payload.is_membership_change()
                || self.ops_graph.batch_has_membership_change(&predecessors)?;
            if self.pending_replay {
                self.record_op(&op)?;
            } else {
                self.apply_operation_and_record_root_secret(op)?;
            }
        } else {
            self.replay_if_pending()?;
            self.apply_operation_and_record_root_secret(op)?;
        }
        Ok(true)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaBatch>, CgkaError> {
        self.ops_graph.batches()
    }

    pub fn contains_predecessors(&self, preds: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.ops_graph.contains_predecessors(preds)
    }

    /// Apply `op`. If it is a [`CgkaOperation::Update`], record the
    /// corresponding root secret.
    #[instrument(skip_all)]
    pub(crate) fn apply_operation_and_record_root_secret(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<(), CgkaError> {
        if !self.apply_operation_to_tree(op.clone())? {
            return Ok(());
        }
        if matches!(op.payload, CgkaOperation::Update { .. }) {
            // Record it while the tree still has it. Deriving it later would
            // mean rebuilding the tree from history.
            self.record_secret_from_tree();
        }
        Ok(())
    }

    /// Apply a [`CgkaOperation`] without deriving the tree's root secret.
    /// Returns `false` if the operation was already in the graph.
    ///
    /// A replay applies the whole history. Always recording per update would
    /// derive a root secret for every update when only the last one is needed.
    #[instrument(skip_all)]
    fn apply_operation_to_tree(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(false);
        }
        match op.payload {
            CgkaOperation::Add { added_id, pk, .. } => {
                // A concurrent history might have added the same member.
                if !self.tree.contains_id(&added_id) {
                    self.tree.push_leaf(added_id, pk.into());
                }
            }
            CgkaOperation::Remove { id, .. } => {
                // A concurrent history may have removed this member already.
                if self.tree.contains_id(&id) {
                    self.tree.remove_id(id)?;
                }
            }
            CgkaOperation::Update { ref new_path, .. } => {
                self.tree.apply_path(new_path);
            }
        }
        self.record_op(&op)?;
        Ok(true)
    }

    /// Apply operations grouped into [`CgkaBatch`]s in order.
    #[instrument(skip_all)]
    pub(crate) fn apply_batches(&mut self, batches: &NonEmpty<CgkaBatch>) -> Result<(), CgkaError> {
        for batch in batches {
            if batch.len() == 1 {
                self.apply_operation_to_tree(batch[0].clone())?;
            } else {
                // If all operations in this batch are updates, we can apply them
                // directly and move on to the next batch.
                if batch
                    .iter()
                    .all(|op| matches!(op.payload, CgkaOperation::Update { .. }))
                {
                    for op in batch.iter() {
                        self.apply_operation_to_tree(op.clone())?;
                    }
                    continue;
                }

                // A batch with at least one membership change requires blanking
                // removed paths and sorting added leaves after all ops are applied.
                let mut added_ids = Set::new();
                let mut removed_ids = Set::new();
                for op in batch.iter() {
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
    /// Returns the secret recorded for `update_op_hash` if its hash is
    /// `pcs_key_hash`. Otherwise tries the current tree root and then the
    /// predecessor secret chain, and rebuilds the tree state for `update_op_hash`
    /// only if neither produces it.
    ///
    /// Returns [`CgkaError::UnknownPcsKey`] if none of these produces a secret with
    /// that hash.
    #[instrument(skip_all)]
    fn pcs_key_from_hashes(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        if let Some(pcs_key) = self
            .root_secret_for(update_op_hash)
            .filter(|pcs_key| &Digest::hash(pcs_key) == pcs_key_hash)
        {
            return Ok(pcs_key);
        }
        if self.has_pcs_key() {
            if let Ok(pcs_key) = self.pcs_key_from_tree_root() {
                if &Digest::hash(&pcs_key) == pcs_key_hash {
                    return Ok(pcs_key);
                }
            }
        }
        // Record the root secret so we can traverse its predecessors.
        self.record_secret_from_tree();
        if let Some(pcs_key) = self.pcs_key_from_predecessor_secrets(pcs_key_hash) {
            return Ok(pcs_key);
        }
        let pcs_key = self.derive_pcs_key_for_op(update_op_hash)?;
        if &Digest::hash(&pcs_key) != pcs_key_hash {
            return Err(CgkaError::UnknownPcsKey);
        }
        Ok(pcs_key)
    }

    /// The root secrets of the nearest update ancestors of the current heads,
    /// and of every update that [`Self::is_unchained`] reports, sorted by
    /// operation hash.
    #[instrument(skip_all)]
    fn reachable_ancestor_secrets(&mut self) -> Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let mut targets = self
            .ops_graph
            .nearest_update_ancestors(&self.ops_graph.cgka_op_heads);
        targets.extend(
            self.ops_graph
                .chainable_updates
                .iter()
                .copied()
                .filter(|op_hash| self.is_unchained(op_hash)),
        );

        let mut found = Vec::new();
        let mut to_rebuild = Vec::new();
        for op_hash in targets {
            match self.root_secret_for(&op_hash) {
                Some(pcs_key) => found.push((op_hash, pcs_key)),
                None => to_rebuild.push(op_hash),
            }
        }
        if !to_rebuild.is_empty() {
            let can_rebuild = self
                .ops_graph
                .targets_with_add_for(self.owner_id, &to_rebuild);
            for op_hash in can_rebuild {
                if let Ok(pcs_key) = self.derive_pcs_key_for_op(&op_hash) {
                    found.push((op_hash, pcs_key));
                }
            }
        }
        // The ancestors are an unordered set, so sort them to keep the
        // serialized add operation stable.
        found.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        found
    }

    /// Encrypt each of `ancestor_secrets` under a key derived from `pcs_key` so that
    /// a member who can derive `pcs_key` can derive those too.
    ///
    /// A secret that fails to encrypt is dropped from this operation. A later update
    /// by a member that can derive it can put it in the chain instead.
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

    /// Derive the current root secret from the tree and record it for the update
    /// that produced it. Returns `None` if we can't derive it from the current
    /// tree state or if the heads do not have exactly one nearest update
    /// ancestor.
    #[instrument(skip_all)]
    fn record_secret_from_tree(&mut self) -> Option<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        if !self.has_pcs_key() {
            return None;
        }
        let ancestors = self
            .ops_graph
            .nearest_update_ancestors(&self.ops_graph.cgka_op_heads);
        if ancestors.len() != 1 {
            return None;
        }
        let op_hash = *ancestors.iter().next()?;
        if let Some(pcs_key) = self.pcs_keys_by_update.get(&op_hash).copied() {
            return Some((op_hash, pcs_key));
        }
        let pcs_key = self.pcs_key_from_tree_root().ok()?;
        self.record_root_secret_for(&pcs_key, op_hash)
            .then_some((op_hash, pcs_key))
    }

    /// Mark as chained each update in `entries` whose secret is the one that
    /// update produced.
    ///
    /// `entries` are the decrypted chain entries of an update whose own secret is
    /// verified.
    fn mark_chained(&mut self, entries: &[(Digest<Signed<CgkaOperation>>, PcsKey)]) {
        let chained: Vec<_> = entries
            .iter()
            .filter(|(update, secret)| {
                !self.chained_updates.contains(update) && self.corresponds_to_update(secret, update)
            })
            .map(|(update, _)| *update)
            .collect();
        self.chained_updates.extend(chained);
    }

    /// Each predecessor of the update `op_hash` that decrypts under the key
    /// derived from `pcs_key`, with the update it refers to and the secret it
    /// contains.
    fn decrypt_predecessor_secrets(
        &self,
        op_hash: &Digest<Signed<CgkaOperation>>,
        pcs_key: &PcsKey,
    ) -> Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let Some(CgkaOperation::Update {
            predecessor_secrets,
            ..
        }) = self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload)
        else {
            return Vec::new();
        };
        if predecessor_secrets.is_empty() {
            return Vec::new();
        }
        let key = pcs_key.derive_predecessor_secrets_key();
        predecessor_secrets
            .iter()
            .filter_map(|entry| {
                Self::decrypt_predecessor_secret(&key, entry)
                    .map(|secret| (entry.update_op_hash, secret))
            })
            .collect()
    }

    /// Whether a later update was in a position to add `op_hash` to the chain
    /// and we have not seen one do so.
    pub(crate) fn is_unchained(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> bool {
        self.ops_graph.chainable_updates.contains(op_hash)
            && !self.chained_updates.contains(op_hash)
    }

    /// The root secret `op_hash` produced, if we can reach it without a rebuild.
    pub(crate) fn root_secret_for(
        &self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Option<PcsKey> {
        self.pcs_keys_by_update.get(op_hash).copied()
    }

    /// The root secret whose hash is `pcs_key_hash`, found by following predecessor
    /// secrets from every root secret we have recorded. Records each secret it
    /// derives (as long as the secret corresponds to the update its entry refers to).
    #[instrument(skip_all)]
    pub(crate) fn pcs_key_from_predecessor_secrets(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
    ) -> Option<PcsKey> {
        let recorded: Vec<_> = self
            .pcs_keys_by_update
            .iter()
            .map(|(op_hash, key)| (*op_hash, *key))
            .collect();
        let mut seen: Set<(Digest<Signed<CgkaOperation>>, Digest<PcsKey>)> = recorded
            .iter()
            .map(|(op_hash, key)| (*op_hash, Digest::hash(key)))
            .collect();
        let mut frontier: Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> = Vec::new();
        for (op_hash, key) in &recorded {
            frontier.extend(self.decrypt_predecessor_secrets(op_hash, key));
        }
        while let Some((op_hash, found)) = frontier.pop() {
            if !seen.insert((op_hash, Digest::hash(&found))) {
                continue;
            }
            // Record it so a later request finds it without following the chain.
            // `accept_root_secret` drops it if it is not the secret corresponding to
            // the update the entry refers to.
            let decrypted = (self.pcs_keys_by_update.get(&op_hash) != Some(&found)
                && self.accept_root_secret(&found, op_hash))
            .then(|| {
                let entries = self.decrypt_predecessor_secrets(&op_hash, &found);
                self.mark_chained(&entries);
                entries
            });
            if Digest::hash(&found) == *pcs_key_hash {
                return Some(found);
            }
            frontier.extend(
                decrypted.unwrap_or_else(|| self.decrypt_predecessor_secrets(&op_hash, &found)),
            );
        }
        None
    }

    /// Decrypt the provided predecessor secret using `key`. Returns `None` if it
    /// fails to decrypt or is not 32 bytes.
    pub(crate) fn decrypt_predecessor_secret(
        key: &SymmetricKey,
        predecessor: &PredecessorSecret,
    ) -> Option<PcsKey> {
        PcsKey::from_plaintext(key.try_open(&predecessor.encrypted_root_secret).ok()?)
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
        let heads = Set::from_iter([*op_hash]);
        let ops = self.ops_graph.batches_for_heads(&heads)?;
        self.rebuild_pcs_key(ops)
    }

    /// Replay all ops in our graph in a deterministic order.
    #[instrument(skip_all)]
    fn replay_ops_graph(&mut self) -> Result<(), CgkaError> {
        let ordered_ops = self.ops_graph.batches()?;
        let rebuilt_cgka = self.rebuild_cgka(ordered_ops)?;
        self.update_cgka_from(&rebuilt_cgka);
        self.pending_replay = false;
        Ok(())
    }

    /// Build a new [`Cgka`] for the provided non-empty list of [`CgkaBatch`]s.
    #[instrument(skip_all)]
    fn rebuild_cgka(&mut self, batches: NonEmpty<CgkaBatch>) -> Result<Cgka, CgkaError> {
        let mut rebuilt_cgka = Cgka::new(self.doc_id, self.owner_id, self.owner_sks.clone());
        rebuilt_cgka.apply_batches(&batches)?;
        if rebuilt_cgka.tree.contains_id(&self.owner_id) && rebuilt_cgka.has_pcs_key() {
            let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
            rebuilt_cgka.record_root_secret_for(&pcs_key, Digest::hash(&batches.last()[0]));
        }
        Ok(rebuilt_cgka)
    }

    /// Derive a [`PcsKey`] by rebuilding a [`Cgka`] from the provided non-empty
    /// list of [`CgkaBatch`]s and record it for the last operation.
    ///
    /// Returns [`CgkaError::UnknownPcsKey`] if that operation is not an update or
    /// the rebuilt root secret is not the one it produced.
    #[instrument(skip_all)]
    fn rebuild_pcs_key(&mut self, batches: NonEmpty<CgkaBatch>) -> Result<PcsKey, CgkaError> {
        if !matches!(batches.last()[0].payload, CgkaOperation::Update { .. }) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let mut rebuilt_cgka = Cgka::new(self.doc_id, self.owner_id, self.owner_sks.clone());
        rebuilt_cgka.apply_batches(&batches)?;
        let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
        if !self.record_root_secret_for(&pcs_key, Digest::hash(&batches.last()[0])) {
            return Err(CgkaError::UnknownPcsKey);
        }
        Ok(pcs_key)
    }

    /// Record `pcs_key` as the root secret the update `op_hash` produced, and mark
    /// as chained each update its chain entries verify.
    ///
    /// Returns whether `pcs_key` is recorded for `op_hash`. Nothing is written if
    /// it is not the secret that update produced.
    #[instrument(skip_all)]
    fn record_root_secret_for(
        &mut self,
        pcs_key: &PcsKey,
        op_hash: Digest<Signed<CgkaOperation>>,
    ) -> bool {
        if self.pcs_keys_by_update.get(&op_hash) == Some(pcs_key) {
            return true;
        }
        if !self.accept_root_secret(pcs_key, op_hash) {
            return false;
        }
        let entries = self.decrypt_predecessor_secrets(&op_hash, pcs_key);
        self.mark_chained(&entries);
        true
    }

    /// Write `pcs_key` as the root secret of `op_hash` if it is the secret that
    /// update produced. Returns whether it was written.
    fn accept_root_secret(
        &mut self,
        pcs_key: &PcsKey,
        op_hash: Digest<Signed<CgkaOperation>>,
    ) -> bool {
        if !self.corresponds_to_update(pcs_key, &op_hash) {
            debug!(
                ?op_hash,
                "a root secret does not match the update it was paired with"
            );
            return false;
        }
        self.pcs_keys_by_update.insert(op_hash, *pcs_key);
        true
    }

    /// Whether `pcs_key` is the root secret that `op_hash` produced.
    ///
    /// Returns `false` when we do not have the operation or it is not an update.
    fn corresponds_to_update(
        &self,
        pcs_key: &PcsKey,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> bool {
        self.root_share_key_for(op_hash)
            .is_some_and(|root_pk| pcs_key.0.share_key() == root_pk)
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
        self.pcs_keys_by_update
            .extend(other.pcs_keys_by_update.iter());
        self.chained_updates.extend(other.chained_updates.iter());
        self.pending_replay = other.pending_replay;
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
        self.pcs_keys_by_update
            .extend(fork.pcs_keys_by_update.iter());
        self.chained_updates.extend(fork.chained_updates);
        if !self.ops_graph.cgka_op_heads.is_empty() {
            self.replay_ops_graph()
                .expect("two valid graphs should always merge causal consistency");
        }
    }
}

#[cfg(any(test, feature = "test_utils"))]
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
