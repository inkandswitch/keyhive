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
    collections::Set,
    encrypted::{encrypt_secret_with, EncryptedContent, PairedKey},
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{LeafKeyPair, NodeKey, ShareKeyMap},
    operation::{
        CgkaAuthorization, CgkaBatch, CgkaOperation, CgkaOperationGraph, Invitation,
        InvitationSecret, PredecessorSecret,
    },
    pcs_key::{ApplicationSecret, PcsKey},
    root_secrets::{RootSecrets, VerifiedRootSecret},
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
    pub(crate) root_secrets: RootSecrets,

    /// Chainable updates that we have not detected as verified secrets on the
    /// predecessor secrets chain.
    pub(crate) unchained_updates: Set<Digest<Signed<CgkaOperation>>>,
}

impl Hash for Cgka {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.doc_id.hash(state);
        self.owner_id.hash(state);
        self.owner_sks.hash(state);
        self.tree.hash(state);
        self.ops_graph.hash(state);
        self.pending_replay.hash(state);
        self.root_secrets
            .iter()
            .map(|(op_hash, _)| op_hash)
            .collect::<BTreeSet<_>>()
            .hash(state);
        self.unchained_updates
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
            root_secrets: RootSecrets::default(),
            unchained_updates: Set::new(),
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
        let (current_pcs_key, current_op_hash) = if !self.has_tree_root_secret() {
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
            // `has_tree_root_secret()` above guarantees a single head.
            debug_assert!(self.ops_graph.has_single_head());
            match self.record_tree_root_secret() {
                Some((op_hash, pcs_key)) => (pcs_key, op_hash),
                None => {
                    // If there is a decryption error, return it. Otherwise, return
                    // `UnknownPcsKey`.
                    self.decrypt_tree_root_secret()?;
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
            self.root_secret_from_hashes(&encrypted.pcs_key_hash, &encrypted.pcs_update_op_hash)?;
        let app_secret = pcs_key.derive_application_secret(
            &encrypted.nonce,
            &encrypted.content_ref,
            &encrypted.pred_refs,
            &encrypted.pcs_update_op_hash,
        );
        Ok(app_secret.key())
    }

    /// Whether the tree has a root key and the graph a single head, meaning there is
    /// a current root secret. Does not check if we can decrypt it.
    pub fn has_tree_root_secret(&self) -> bool {
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
                "no invitation root secret derived for {:?}, so it cannot read content encrypted before this add until a later update wraps those secrets",
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
        let invitation_secrets: Vec<InvitationSecret> = ancestor_secrets
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
        if invitation_secrets.is_empty() {
            return None;
        }
        Some(Invitation {
            inviter_pk,
            ancestor_secrets: invitation_secrets,
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

        for invited in &invitation.ancestor_secrets {
            if self.root_secrets.get(&invited.update_op_hash).is_some() {
                continue;
            }
            if let Some(pcs_key) = self.decrypt_invitation_secret(invitation.inviter_pk, invited) {
                self.record_root_secret_for(pcs_key, invited.update_op_hash);
            }
        }
    }

    /// Add `op` to the operation graph and, if it includes an invitation for us,
    /// record those root secrets.
    fn record_op(&mut self, op: &Signed<CgkaOperation>) -> Result<(), CgkaError> {
        self.unchained_updates.extend(self.ops_graph.add_op(op)?);
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
    fn decrypt_invitation_secret(
        &self,
        inviter_pk: ShareKey,
        invitation_secret: &InvitationSecret,
    ) -> Option<PcsKey> {
        let plaintext = self
            .owner_sks
            .try_decrypt_encryption(inviter_pk, &invitation_secret.encrypted_root_secret)
            .ok()?;
        PcsKey::from_decrypted_secret(plaintext)
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
        // Get our reachable ancestors before `encrypt_path` changes the tree so the
        // tree's root still corresponds to the current heads.
        let ancestors = self.reachable_ancestor_secrets();
        let maybe_key_and_path =
            self.tree
                .encrypt_path(update_id, update_pk, &mut self.owner_sks, csprng)?;
        if let Some((pcs_key, new_path)) = maybe_key_and_path {
            let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().copied());
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
            self.record_root_secret_for(pcs_key, Digest::hash(&signed_op));
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
        let is_update = matches!(op.payload, CgkaOperation::Update { .. });
        if !self.apply_operation_to_tree(op)? {
            return Ok(());
        }
        if is_update {
            // Record it while the tree still has it. Deriving it later would
            // mean rebuilding the tree from history.
            self.record_tree_root_secret();
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

    /// Decrypt the current tree's root secret as the owner or as Public if
    /// that fails and Public is a member.
    pub fn decrypt_tree_root_secret(&mut self) -> Result<PcsKey, CgkaError> {
        let key = match self
            .tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
        {
            Ok(k) => k,
            Err(e) => {
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

    /// The root secret `update_op_hash` produced if that secret's hash is `pcs_key_hash`.
    ///
    /// Returns [`CgkaError::UnknownPcsKey`] if the secret for that update
    /// has a different hash or cannot be found, or the error from rebuilding the
    /// tree if it is tried and fails.
    #[instrument(skip_all)]
    pub(crate) fn root_secret_from_hashes(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        let pcs_key = self.find_or_derive_root_secret(update_op_hash)?;
        if &Digest::hash(&pcs_key) != pcs_key_hash {
            return Err(CgkaError::UnknownPcsKey);
        }
        Ok(pcs_key)
    }

    /// The root secret the update `op_hash` produced, recording it if it has to
    /// be derived.
    fn find_or_derive_root_secret(
        &mut self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        if let Some(pcs_key) = self.root_secrets.get(op_hash) {
            return Ok(pcs_key);
        }

        if let Some((_, pcs_key)) = self
            .record_tree_root_secret()
            .filter(|(head, _)| head == op_hash)
        {
            return Ok(pcs_key);
        }
        if let Some(pcs_key) = self.root_secret_from_update_path(op_hash) {
            return Ok(pcs_key);
        }
        if let Some(pcs_key) = self.root_secret_from_chain(op_hash) {
            return Ok(pcs_key);
        }
        self.rebuild_root_secret(op_hash)
    }

    /// The root secret the update `op_hash` produced, decrypted directly from that
    /// update's wrapped path and recorded.
    ///
    /// Returns `None` if `op_hash` is not an update, we don't have the secret we need
    /// to decrypt to the path's root, or the decrypted secret is not the one the update
    /// produced.
    pub(crate) fn root_secret_from_update_path(
        &mut self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Option<PcsKey> {
        let Some(CgkaOperation::Update { new_path, .. }) =
            self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload)
        else {
            return None;
        };
        let pcs_key = PcsKey::new(new_path.decrypt_root_secret(&self.owner_sks)?);
        self.record_root_secret_for(pcs_key, *op_hash)
            .then_some(pcs_key)
    }

    /// The root secrets of the nearest update ancestors of the current heads
    /// and of every update in [`Self::unchained_updates`], sorted by
    /// operation hash.
    #[instrument(skip_all)]
    fn reachable_ancestor_secrets(&mut self) -> Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let nearest = self
            .ops_graph
            .nearest_update_ancestors(&self.ops_graph.cgka_op_heads);
        let mut targets = nearest.clone();
        targets.extend(self.unchained_updates.iter().copied());

        let mut found = Vec::new();
        for op_hash in targets {
            if let Ok(pcs_key) = self.find_or_derive_root_secret(&op_hash) {
                found.push((op_hash, pcs_key));
            }
        }
        found.retain(|(op_hash, _)| {
            nearest.contains(op_hash) || self.unchained_updates.contains(op_hash)
        });
        // `targets` is an unordered set, so sort the result to keep the
        // serialized add or update operation stable.
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
    fn record_tree_root_secret(&mut self) -> Option<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        if !self.has_tree_root_secret() {
            return None;
        }
        let ancestors = self
            .ops_graph
            .nearest_update_ancestors(&self.ops_graph.cgka_op_heads);
        if ancestors.len() != 1 {
            return None;
        }
        let op_hash = *ancestors.iter().next()?;
        if let Some(pcs_key) = self.root_secrets.get(&op_hash) {
            return Some((op_hash, pcs_key));
        }
        let pcs_key = self.decrypt_tree_root_secret().ok()?;

        self.record_root_secret_for(pcs_key, op_hash)
            .then_some((op_hash, pcs_key))
    }

    /// Remove from the unchained updates each update in `entries` whose secret
    /// is verified.
    ///
    /// `entries` are the decrypted chain entries of an update whose own secret is
    /// verified.
    fn mark_chained(&mut self, entries: &[(Digest<Signed<CgkaOperation>>, PcsKey)]) {
        for (update, secret) in entries {
            if self.unchained_updates.contains(update)
                && VerifiedRootSecret::verify(&self.ops_graph, *update, *secret).is_some()
            {
                self.unchained_updates.remove(update);
            }
        }
    }

    /// Record each root secret in `other` that is not recorded here and remove
    /// from [`Self::unchained_updates`] each update whose root secret a newly
    /// recorded update's predecessor secrets contain.
    ///
    /// Only entries for updates that are still unchained are decrypted.
    fn merge_root_secrets(&mut self, other: &RootSecrets) {
        for (op_hash, secret) in self.root_secrets.merge_from(other) {
            let entries = self.decrypt_predecessor_secrets(&op_hash, &secret, |update| {
                self.unchained_updates.contains(update)
            });
            self.mark_chained(&entries);
        }
    }

    /// Each predecessor secret in the update `op_hash` that decrypts under the key
    /// derived from `pcs_key` (but only those secrets for which `should_decrypt` returns
    /// true). Each secret is returned along with its corresponding update.
    /// The returned secrets are not verified.
    pub(crate) fn decrypt_predecessor_secrets(
        &self,
        op_hash: &Digest<Signed<CgkaOperation>>,
        pcs_key: &PcsKey,
        should_decrypt: impl Fn(&Digest<Signed<CgkaOperation>>) -> bool,
    ) -> Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let Some(CgkaOperation::Update {
            predecessor_secrets,
            ..
        }) = self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload)
        else {
            return Vec::new();
        };
        // Derived only once an entry should be decrypted.
        let mut key = None;
        predecessor_secrets
            .iter()
            .filter(|entry| should_decrypt(&entry.update_op_hash))
            .filter_map(|entry| {
                let key = key.get_or_insert_with(|| pcs_key.derive_predecessor_secrets_key());
                let plaintext = key.try_open(&entry.encrypted_root_secret).ok()?;
                Some((
                    entry.update_op_hash,
                    PcsKey::from_decrypted_secret(plaintext)?,
                ))
            })
            .collect()
    }

    /// The root secret the update `target` produced, found by following
    /// predecessor secrets from every root secret we have recorded. Records each
    /// verified secret it derives and stops once `target`'s secret is recorded.
    ///
    /// Returns `target`'s secret if it is already recorded and `None` if
    /// we can't derive the secret or `target` is not currently chainable.
    #[instrument(skip_all)]
    pub(crate) fn root_secret_from_chain(
        &mut self,
        target: &Digest<Signed<CgkaOperation>>,
    ) -> Option<PcsKey> {
        if let Some(pcs_key) = self.root_secrets.get(target) {
            return Some(pcs_key);
        }
        if !self.ops_graph.is_chainable(target) {
            return None;
        }
        let mut frontier: Vec<_> = self
            .root_secrets
            .iter()
            .flat_map(|(op_hash, key)| {
                self.decrypt_predecessor_secrets(&op_hash, &key, |entry| {
                    self.root_secrets.get(entry).is_none()
                })
            })
            .collect();
        while let Some((op_hash, found)) = frontier.pop() {
            if self.root_secrets.get(&op_hash).is_some() {
                continue;
            }
            // A secret that is not the update's cannot open that update's own
            // entries, so it is not followed.
            let Some(verified) = VerifiedRootSecret::verify(&self.ops_graph, op_hash, found) else {
                continue;
            };
            self.root_secrets.insert(verified);
            let entries = self.decrypt_predecessor_secrets(&op_hash, &found, |_| true);
            self.mark_chained(&entries);
            if op_hash == *target {
                return Some(found);
            }
            frontier.extend(entries);
        }
        None
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

    /// Build a new [`Cgka`] from the provided non-empty list of [`CgkaBatch`]s,
    /// with the root secret of its final tree state recorded if we can derive it.
    #[instrument(skip_all)]
    fn rebuild_cgka(&self, batches: NonEmpty<CgkaBatch>) -> Result<Cgka, CgkaError> {
        let mut rebuilt_cgka = Cgka::new(self.doc_id, self.owner_id, self.owner_sks.clone());
        rebuilt_cgka.apply_batches(&batches)?;
        rebuilt_cgka.record_tree_root_secret();
        Ok(rebuilt_cgka)
    }

    /// Derive the root secret the update `op_hash` produced by rebuilding the
    /// tree as it was after that update, and record it.
    ///
    /// Returns [`CgkaError::UnknownPcsKey`] if `op_hash` is not an update we
    /// have, neither our add nor Public's precedes it, or we cannot derive the
    /// rebuilt tree's root secret.
    #[instrument(skip_all)]
    pub(crate) fn rebuild_root_secret(
        &mut self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        let Some(CgkaOperation::Update { .. }) =
            self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload)
        else {
            return Err(CgkaError::UnknownPcsKey);
        };
        // Check there is an add of the owner or of Public before this update,
        // since otherwise the rebuilt tree has no leaf we can decrypt from.
        if !self.ops_graph.has_add_before(self.owner_id, *op_hash) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let batches = self
            .ops_graph
            .batches_for_heads(&Set::from_iter([*op_hash]))?;
        let rebuilt_cgka = self.rebuild_cgka(batches)?;
        self.merge_root_secrets(&rebuilt_cgka.root_secrets);
        self.root_secrets
            .get(op_hash)
            .ok_or(CgkaError::UnknownPcsKey)
    }

    /// Record `pcs_key` as the root secret the update `op_hash` produced and mark
    /// as chained each update whose root secret this update's predecessor
    /// secrets contain.
    ///
    /// Returns whether `pcs_key` is recorded for `op_hash`. Nothing is written if
    /// it is not the secret that update produced.
    #[instrument(skip_all)]
    fn record_root_secret_for(
        &mut self,
        pcs_key: PcsKey,
        op_hash: Digest<Signed<CgkaOperation>>,
    ) -> bool {
        if self.root_secrets.get(&op_hash) == Some(pcs_key) {
            return true;
        }
        let Some(verified) = VerifiedRootSecret::verify(&self.ops_graph, op_hash, pcs_key) else {
            debug!(
                ?op_hash,
                "a root secret does not match the update it was paired with"
            );
            return false;
        };
        self.root_secrets.insert(verified);
        let entries = self.decrypt_predecessor_secrets(&op_hash, &pcs_key, |update| {
            self.unchained_updates.contains(update)
        });
        self.mark_chained(&entries);
        true
    }

    /// Extend our state with that of the provided [`Cgka`].
    #[instrument(skip_all)]
    fn update_cgka_from(&mut self, other: &Self) {
        self.tree = other.tree.clone();
        self.owner_sks.extend(&other.owner_sks);
        self.merge_root_secrets(&other.root_secrets);
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
        // Extend with the fork's unchained updates that are not chainable here.
        self.unchained_updates.extend(
            fork.unchained_updates
                .iter()
                .filter(|update| !self.ops_graph.is_chainable(update))
                .copied(),
        );
        self.owner_sks.merge(fork.owner_sks);
        self.ops_graph.merge(fork.ops_graph);
        self.merge_root_secrets(&fork.root_secrets);
        if !self.ops_graph.cgka_op_heads.is_empty() {
            self.replay_ops_graph()
                .expect("two valid graphs should always merge causal consistency");
        }
    }
}
