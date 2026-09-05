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
    encrypted::{encrypt_secret, EncryptedContent},
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{NodeKey, ShareKeyMap},
    operation::{
        CgkaEpoch, CgkaOperation, CgkaOperationGraph, Invitation, InvitationSecret,
        PredecessorSecret,
    },
    pcs_key::{ApplicationSecret, PcsKey},
    transact::{Fork, Merge},
    tree::BeeKem,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
    vec::Vec,
};
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
use tracing::{debug, info, instrument, warn};

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
    tree: BeeKem,
    /// Graph of all operations seen (but not necessarily applied) so far.
    ops_graph: CgkaOperationGraph,
    /// Whether there are ops in the graph that have not been applied to the
    /// tree due to a structural change.
    pending_ops_for_structural_change: bool,
    // TODO: Enable policies to evict older entries.
    pcs_keys: CaMap<PcsKey>,

    /// The root secret each update operation produced, for the ones we can reach.
    pcs_keys_by_update: Map<Digest<Signed<CgkaOperation>>, PcsKey>,

    /// Invitations for new members.
    invitations: Map<MemberId, Vec<Invitation>>,

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
        self.invitations
            .iter()
            .collect::<BTreeMap<_, _>>()
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
            invitations: Map::new(),
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
        cgka.pcs_keys = self.pcs_keys.clone();
        cgka.pcs_keys_by_update = self.pcs_keys_by_update.clone();
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
    /// perform a leaf key rotation.
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
    ) -> Result<(ApplicationSecret<T>, Option<Signed<CgkaOperation>>), CgkaError> {
        let mut op = None;
        let (current_pcs_key, current_op_hash) = if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            let (pcs_key, update_op) = self
                .update::<F, S, R>(new_share_key, new_share_secret_key, signer, csprng)
                .await?;
            let op_hash = Digest::hash(&update_op);
            self.insert_pcs_key(&pcs_key, op_hash);
            op = Some(update_op);
            (pcs_key, op_hash)
        } else {
            // `has_pcs_key()` above guarantees a single head.
            debug_assert!(self.ops_graph.has_single_head());
            let pcs_key = self.pcs_key_from_tree_root()?;
            let op_hash = match self.record_tree_root_secret() {
                Some((op_hash, _)) => op_hash,
                None => {
                    let head = self
                        .ops_graph
                        .cgka_op_heads
                        .iter()
                        .next()
                        .copied()
                        .ok_or(CgkaError::UnknownPcsKey)?;
                    self.insert_pcs_key(&pcs_key, head);
                    head
                }
            };
            (pcs_key, op_hash)
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

    /// Add member to group.
    ///
    /// Returns the add operation and an [`CgkaOperation::Invite`].
    /// Empty if the member is already in the tree.
    #[instrument(skip_all)]
    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        pk: ShareKey,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        if self.tree.contains_id(&id) {
            return Ok(Vec::new());
        }
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        // Find the update heads before the new leaf blanks the root so we can
        // put them in an invitation.
        let heads = self.ops_graph.cgka_op_heads.clone();
        self.record_tree_root_secret();
        self.derive_missing_ancestor_secrets(&heads);
        let invitation = self.invitation_for(id, pk);
        let leaf_index = self.tree.push_leaf(id, pk.into());
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let add_predecessors = Vec::from_iter(self.ops_graph.add_heads.iter().cloned());
        let op = CgkaOperation::Add {
            added_id: id,
            pk,
            leaf_index,
            predecessors,
            add_predecessors,
            doc_id: self.doc_id,
        };

        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.ops_graph.add_local_op(&signed_op);
        let mut ops = vec![signed_op];

        if let Some(invitation) = invitation {
            let op = CgkaOperation::Invite {
                invitation: Box::new(invitation),
                predecessors: Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned()),
                doc_id: self.doc_id,
            };
            let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
            self.record_invitation(&signed_op);
            self.ops_graph.add_local_op(&signed_op);
            ops.push(signed_op);
        } else {
            debug!(
                "no root secret to invite {:?} with; it can only read content written from now on",
                id
            );
        }
        Ok(ops)
    }

    /// Add multiple members to group.
    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(MemberId, ShareKey)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let mut ops = Vec::new();
        for m in members {
            ops.extend(self.add::<F, S>(m.0, m.1, signer).await?);
        }
        Ok(ops)
    }

    /// Build an invitation for a member we are adding.
    ///
    /// Returns `None` if we don't have access to any root secret.
    #[instrument(skip_all)]
    fn invitation_for(&self, invitee_id: MemberId, invitee_pk: ShareKey) -> Option<Invitation> {
        let (inviter_pk, inviter_sk) = self.inviter_key_pair()?;
        let wanted = self
            .ops_graph
            .nearest_update_ancestors(&self.ops_graph.cgka_op_heads);
        let mut head_secrets: Vec<InvitationSecret> = wanted
            .iter()
            .filter_map(|op_hash| Some((*op_hash, self.root_secret_for(op_hash)?)))
            .filter_map(|(update_op_hash, secret)| {
                Some(InvitationSecret {
                    update_op_hash,
                    encrypted_root_secret: encrypt_secret(
                        self.doc_id.as_bytes(),
                        secret.0,
                        &inviter_sk,
                        &invitee_pk,
                    )
                    .ok()?,
                })
            })
            .collect();
        head_secrets.sort_by_key(|invited| invited.update_op_hash);
        head_secrets.dedup_by_key(|invited| invited.update_op_hash);
        if head_secrets.is_empty() {
            return None;
        }
        Some(Invitation {
            invitee_id,
            invitee_pk,
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

    /// If there is an invitation, record it for the id it targets.
    fn record_invitation(&mut self, op: &Signed<CgkaOperation>) {
        let CgkaOperation::Invite { invitation, .. } = &op.payload else {
            return;
        };
        let invitation = invitation.as_ref();
        let stored = self.invitations.entry(invitation.invitee_id).or_default();
        if !stored.contains(invitation) {
            stored.push(invitation.clone());
        }
    }

    /// Remove member from group.
    #[instrument(skip_all)]
    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if !self.tree.contains_id(&id) {
            return Ok(None);
        }
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        if self.group_size() == 1 {
            return Err(CgkaError::RemoveLastMember);
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
    #[instrument(skip_all)]
    pub async fn update<F: FutureForm, S: AsyncSigner<F>, R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, Signed<CgkaOperation>), CgkaError> {
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
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
            (public_id, pk, sk)
        };
        self.owner_sks.insert(update_pk, update_sk);
        let maybe_key_and_path =
            self.tree
                .encrypt_path(update_id, update_pk, &mut self.owner_sks, csprng)?;
        if let Some((pcs_key, new_path)) = maybe_key_and_path {
            let heads = self.ops_graph.cgka_op_heads.clone();
            let predecessors = Vec::from_iter(heads.iter().cloned());
            self.derive_missing_ancestor_secrets(&heads);
            let predecessor_secrets = self.predecessor_secrets(&pcs_key, &heads);
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
            Ok((pcs_key, signed_op))
        } else {
            Err(CgkaError::IdentifierNotFound)
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
        self.record_invitation(&op);
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
                self.apply_operation(op)?;
            }
        } else {
            if self.should_replay() {
                self.replay_ops_graph()?;
            }
            self.apply_operation(op)?;
        }
        Ok(true)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.ops_graph.topsort_graph()
    }

    pub fn contains_predecessors(&self, preds: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.ops_graph.contains_predecessors(preds)
    }

    /// Apply a [`CgkaOperation`].
    #[instrument(skip_all)]
    fn apply_operation(&mut self, op: Arc<Signed<CgkaOperation>>) -> Result<(), CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(());
        }
        match op.payload {
            CgkaOperation::Add { added_id, pk, .. } => {
                self.tree.push_leaf(added_id, pk.into());
            }
            CgkaOperation::Remove { id, .. } => {
                self.tree.remove_id(id)?;
            }
            CgkaOperation::Update { ref new_path, .. } => {
                self.tree.apply_path(new_path);
            }
            CgkaOperation::Invite { .. } => self.record_invitation(&op),
        }
        self.ops_graph.add_op(&op, &op.payload.predecessors());
        Ok(())
    }

    /// Apply operations grouped into "epochs", where each epoch contains an ordered
    /// set of concurrent operations.
    #[instrument(skip_all)]
    fn apply_epochs(&mut self, epochs: &NonEmpty<CgkaEpoch>) -> Result<(), CgkaError> {
        for epoch in epochs {
            if epoch.len() == 1 {
                self.apply_operation(epoch[0].clone())?;
            } else {
                // If no operation in this epoch changes the tree's structure, we can
                // apply them directly and move on to the next epoch.
                if epoch.iter().all(|op| {
                    matches!(
                        op.payload,
                        CgkaOperation::Update { .. } | CgkaOperation::Invite { .. }
                    )
                }) {
                    for op in epoch.iter() {
                        self.apply_operation(op.clone())?;
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
                    self.apply_operation(op.clone())?;
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
    /// If we have not seen this [`PcsKey`] before, we'll need to rebuild
    /// the tree state for its corresponding update operation.
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
        // An invitation may already contain this key, in which case we don't require
        // a rebuild.
        if let Some((invited_op_hash, pcs_key)) = self.pcs_key_from_invitation(pcs_key_hash) {
            self.insert_pcs_key(&pcs_key, invited_op_hash);
            return Ok(pcs_key);
        }
        if let Some((predecessor_op_hash, pcs_key)) =
            self.pcs_key_from_predecessor_secrets(pcs_key_hash)
        {
            self.insert_pcs_key(&pcs_key, predecessor_op_hash);
            return Ok(pcs_key);
        }
        self.derive_pcs_key_for_op(update_op_hash)
    }

    /// Derive and record the root secret of any nearest update ancestor of `heads`
    /// we have not recorded already.
    #[instrument(skip_all)]
    fn derive_missing_ancestor_secrets(&mut self, heads: &Set<Digest<Signed<CgkaOperation>>>) {
        for op_hash in self.ops_graph.nearest_update_ancestors(heads) {
            if self.root_secret_for(&op_hash).is_some() {
                continue;
            }
            if let Err(e) = self.derive_pcs_key_for_op(&op_hash) {
                warn!(?e, "could not derive an ancestor root secret");
            }
        }
    }

    /// Encrypt the root secret of each nearest update ancestor of `heads` under a key
    /// derived from `pcs_key`, so that a member who can derive `pcs_key` can derive
    /// those too.
    #[instrument(skip_all)]
    fn predecessor_secrets(
        &self,
        pcs_key: &PcsKey,
        heads: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> Vec<PredecessorSecret> {
        let wanted = self.ops_graph.nearest_update_ancestors(heads);
        if wanted.is_empty() {
            return Vec::new();
        }
        let key = pcs_key.derive_predecessor_secrets_key();
        let mut candidates: Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> = wanted
            .iter()
            .filter_map(|op_hash| Some((*op_hash, self.root_secret_for(op_hash)?)))
            .collect();
        candidates.sort_by_key(|(op_hash, secret)| (*op_hash, Digest::hash(secret)));
        candidates.dedup_by_key(|(op_hash, secret)| (*op_hash, Digest::hash(secret)));
        let secrets: Vec<PredecessorSecret> = candidates
            .into_iter()
            .filter_map(|(op_hash, secret)| {
                match key.try_seal(secret.0.as_slice(), self.doc_id.as_bytes()) {
                    Ok(sealed) => Some(PredecessorSecret {
                        update_op_hash: op_hash,
                        encrypted_root_secret: sealed,
                    }),
                    Err(e) => {
                        warn!(?e, "could not seal a predecessor root secret");
                        None
                    }
                }
            })
            .collect();
        secrets
    }

    /// Derive and record the current root secret, if it exists.
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
        let pcs_key = self.pcs_key_from_tree_root().ok()?;
        self.insert_pcs_key(&pcs_key, op_hash);
        Some((op_hash, pcs_key))
    }

    /// The root secret `op_hash` produced, if we can reach it without a rebuild.
    fn root_secret_for(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> Option<PcsKey> {
        if !matches!(
            self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload),
            Some(CgkaOperation::Update { .. })
        ) {
            return None;
        }
        self.pcs_keys_by_update.get(op_hash).copied().or_else(|| {
            self.invited_root_secrets()
                .find(|(invited_op, _)| invited_op == op_hash)
                .map(|(_, key)| key)
        })
    }

    /// Every root secret we can reach without a rebuild, paired with the update it
    /// came from.
    fn known_root_secrets(
        &self,
    ) -> impl Iterator<Item = (Digest<Signed<CgkaOperation>>, PcsKey)> + '_ {
        self.pcs_keys_by_update
            .iter()
            .map(|(op_hash, key)| (*op_hash, *key))
            .chain(self.invited_root_secrets())
            .filter(|(op_hash, _)| {
                matches!(
                    self.ops_graph.cgka_ops.get(op_hash).map(|op| &op.payload),
                    Some(CgkaOperation::Update { .. })
                )
            })
    }

    /// Return the requested PCS key and the update that produced it, if we can
    /// derive it from the predecessor secrets chain.
    #[instrument(skip_all)]
    fn pcs_key_from_predecessor_secrets(
        &self,
        pcs_key_hash: &Digest<PcsKey>,
    ) -> Option<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let mut frontier: Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> =
            self.known_root_secrets().collect();
        let mut seen: Set<(Digest<Signed<CgkaOperation>>, Digest<PcsKey>)> = Set::new();
        while let Some((op_hash, pcs_key)) = frontier.pop() {
            if !seen.insert((op_hash, Digest::hash(&pcs_key))) {
                continue;
            }
            let Some(op) = self.ops_graph.cgka_ops.get(&op_hash) else {
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

    /// Every root secret we can open from an invitation addressed to us, paired with
    /// the update operation that produced it.
    fn invited_root_secrets(
        &self,
    ) -> impl Iterator<Item = (Digest<Signed<CgkaOperation>>, PcsKey)> + '_ {
        [self.owner_id, MemberId::public()]
            .into_iter()
            .filter_map(|id| self.invitations.get(&id))
            .flatten()
            .flat_map(|invitation| {
                invitation.head_secrets.iter().filter_map(|invited| {
                    let plaintext = self
                        .owner_sks
                        .try_decrypt_encryption(
                            invitation.inviter_pk,
                            &invited.encrypted_root_secret,
                        )
                        .ok()?;
                    let bytes = <[u8; 32]>::try_from(plaintext).ok()?;
                    Some((
                        invited.update_op_hash,
                        PcsKey::new(ShareSecretKey::force_from_bytes(bytes)),
                    ))
                })
            })
    }

    /// Look up this PCS key and the update that produced it if we have it in an
    /// invitation. Return `None` otherwise.
    #[instrument(skip_all)]
    fn pcs_key_from_invitation(
        &self,
        pcs_key_hash: &Digest<PcsKey>,
    ) -> Option<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let found = self
            .invited_root_secrets()
            .find(|(_, pcs_key)| Digest::hash(pcs_key) == *pcs_key_hash)?;
        info!("recovered a root secret from an invitation");
        Some(found)
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
        debug_assert!(matches!(
            epochs.last()[0].payload,
            CgkaOperation::Update { .. }
        ));
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

    /// Record a root secret and the update that produced it.
    #[instrument(skip_all)]
    fn insert_pcs_key(&mut self, pcs_key: &PcsKey, op_hash: Digest<Signed<CgkaOperation>>) {
        self.pcs_keys.insert((*pcs_key).into());
        self.pcs_keys_by_update.entry(op_hash).or_insert(*pcs_key);
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
        self.receive_invitations(&other.invitations);
        self.pending_ops_for_structural_change = other.pending_ops_for_structural_change;
    }

    fn receive_invitations(&mut self, other: &Map<MemberId, Vec<Invitation>>) {
        for (member, invitations) in other.iter() {
            let stored = self.invitations.entry(*member).or_default();
            for invitation in invitations {
                if !stored.contains(invitation) {
                    stored.push(invitation.clone());
                }
            }
        }
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
        self.receive_invitations(&fork.invitations);
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
