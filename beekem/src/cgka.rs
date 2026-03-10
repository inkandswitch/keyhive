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
    encrypted::EncryptedContent,
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::ShareKeyMap,
    operation::{CgkaEpoch, CgkaOperation, CgkaOperationGraph},
    pcs_key::{ApplicationSecret, PcsKey},
    transact::{Fork, Merge},
    tree::BeeKem,
};
use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use core::hash::{Hash, Hasher};
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::async_signer::AsyncSigner,
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

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

    /// The update operations for each PCS key.
    pcs_key_ops: Map<Digest<PcsKey>, Digest<Signed<CgkaOperation>>>,

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
        self.pcs_key_ops
            .keys()
            .map(|k| k.as_slice())
            .collect::<BTreeSet<_>>()
            .hash(state);
        self.original_member.hash(state);
        self.init_add_op.hash(state);
    }
}

impl Cgka {
    pub async fn new<S: AsyncSigner>(
        doc_id: TreeId,
        owner_id: MemberId,
        owner_pk: ShareKey,
        signer: &S,
    ) -> Result<Self, CgkaError> {
        let init_add_op = CgkaOperation::init_add(doc_id, owner_id, owner_pk);
        let signed_op = signer.try_sign_async(init_add_op).await?;
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
            pcs_key_ops: Map::new(),
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
        cgka.pcs_key_ops = self.pcs_key_ops.clone();
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
    pub async fn new_app_secret_for<
        S: AsyncSigner,
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
        let current_pcs_key = if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            let (pcs_key, update_op) = self
                .update(new_share_key, new_share_secret_key, signer, csprng)
                .await?;
            self.insert_pcs_key(&pcs_key, Digest::hash(&update_op));
            op = Some(update_op);
            pcs_key
        } else {
            self.pcs_key_from_tree_root()?
        };
        let pcs_key_hash = Digest::hash(&current_pcs_key);
        let nonce = Siv::new(&current_pcs_key.into(), content, self.doc_id.as_bytes());
        Ok((
            current_pcs_key.derive_application_secret(
                &nonce,
                content_ref,
                &Digest::hash(pred_refs),
                self.pcs_key_ops
                    .get(&pcs_key_hash)
                    .expect("PcsKey hash should be present becuase we derived it above"),
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
        if !self.pcs_keys.contains_key(&encrypted.pcs_key_hash) {
            self.insert_pcs_key(&pcs_key, encrypted.pcs_update_op_hash);
        }
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
    #[instrument(skip_all)]
    pub async fn add<S: AsyncSigner>(
        &mut self,
        id: MemberId,
        pk: ShareKey,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if self.tree.contains_id(&id) {
            return Ok(None);
        }
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
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

        let signed_op = signer.try_sign_async(op).await?;
        self.ops_graph.add_local_op(&signed_op);
        Ok(Some(signed_op))
    }

    /// Add multiple members to group.
    pub async fn add_multiple<S: AsyncSigner>(
        &mut self,
        members: NonEmpty<(MemberId, ShareKey)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let mut ops = Vec::new();
        for m in members {
            ops.push(self.add(m.0, m.1, signer).await?);
        }
        Ok(ops.into_iter().flatten().collect())
    }

    /// Remove member from group.
    #[instrument(skip_all)]
    pub async fn remove<S: AsyncSigner>(
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
        let signed_op = signer.try_sign_async(op).await?;
        self.ops_graph.add_local_op(&signed_op);
        Ok(Some(signed_op))
    }

    /// Update leaf key pair for this Identifier.
    /// This also triggers a tree path update for that leaf.
    #[instrument(skip_all)]
    pub async fn update<S: AsyncSigner, R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, Signed<CgkaOperation>), CgkaError> {
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        self.owner_sks.insert(new_pk, new_sk);
        let maybe_key_and_path =
            self.tree
                .encrypt_path(self.owner_id, new_pk, &mut self.owner_sks, csprng)?;
        if let Some((pcs_key, new_path)) = maybe_key_and_path {
            let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
            let op = CgkaOperation::Update {
                id: self.owner_id,
                new_path: alloc::boxed::Box::new(new_path),
                predecessors,
                doc_id: self.doc_id,
            };

            let signed_op = signer.try_sign_async(op).await?;
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
                // If all operations in this epoch are updates, we can apply them
                // directly and move on to the next epoch.
                if epoch
                    .iter()
                    .all(|op| matches!(op.payload, CgkaOperation::Update { .. }))
                {
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
    fn pcs_key_from_tree_root(&mut self) -> Result<PcsKey, CgkaError> {
        let key = self
            .tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)?;
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
            Ok(*pcs_key.clone())
        } else {
            if self.has_pcs_key() {
                let pcs_key = self.pcs_key_from_tree_root()?;
                if &Digest::hash(&pcs_key) == pcs_key_hash {
                    return Ok(pcs_key);
                }
            }
            self.derive_pcs_key_for_op(update_op_hash)
        }
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

    #[instrument(skip_all)]
    fn insert_pcs_key(&mut self, pcs_key: &PcsKey, op_hash: Digest<Signed<CgkaOperation>>) {
        let digest = Digest::hash(pcs_key);
        info!("{:?}", digest);
        self.pcs_key_ops.insert(digest, op_hash);
        self.pcs_keys.insert((*pcs_key).into());
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
        self.pcs_key_ops.extend(other.pcs_key_ops.iter());
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
