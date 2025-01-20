pub mod beekem;
pub mod error;
pub mod keys;
pub mod operation;
pub mod secret_store;
pub mod treemath;

#[cfg(feature = "test_utils")]
pub mod test_utils;

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
};

use crate::{
    content::reference::ContentRef,
    crypto::{
        application_secret::{ApplicationSecret, PcsKey},
        digest::Digest,
        encrypted::EncryptedContent,
        share_key::{ShareKey, ShareSecretKey},
        siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::{document::id::DocumentId, individual::id::IndividualId},
    util::content_addressed_map::CaMap,
};
use beekem::BeeKem;
use error::CgkaError;
use keys::ShareKeyMap;
use nonempty::NonEmpty;
use operation::{CgkaEpoch, CgkaOperation, CgkaOperationGraph};

/// Exposes CGKA (Continuous Group Key Agreement) operations like deriving
/// a new application secret, rotating keys, and adding and removing members
/// from the group.
///
/// A CGKA protocol is responsible for maintaining a stream of shared group keys
/// updated over time. We are using a variant of the TreeKEM protocol (which
/// we call BeeKEM) adapted for local-first contexts.
///
/// We assume that all operations are received in causal order (a property
/// guaranteed by Beehive as a whole).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgka {
    doc_id: DocumentId,
    /// The id of the member who owns this tree.
    pub owner_id: IndividualId,
    /// The secret keys of the member who owns this tree.
    pub owner_sks: ShareKeyMap,
    tree: BeeKem,
    /// Graph of all operations seen (but not necessarily applied) so far.
    ops_graph: CgkaOperationGraph,
    /// Whether there are ops in the graph that have not been applied to the
    ///tree due to a structural change.
    pending_ops_for_structural_change: bool,
    // TODO: Enable policies to evict older entries.
    pcs_keys: CaMap<PcsKey>,
    /// The update operations for each PCS key.
    pcs_key_ops: HashMap<Digest<PcsKey>, Digest<CgkaOperation>>,
    original_member: (IndividualId, ShareKey),
}

impl Cgka {
    pub fn new(
        doc_id: DocumentId,
        owner_id: IndividualId,
        owner_pk: ShareKey,
    ) -> Result<Self, CgkaError> {
        let tree = BeeKem::new(doc_id, owner_id, owner_pk)?;
        let cgka = Self {
            doc_id,
            owner_id,
            owner_sks: ShareKeyMap::new(),
            tree,
            ops_graph: CgkaOperationGraph::new(),
            pending_ops_for_structural_change: false,
            pcs_keys: CaMap::new(),
            pcs_key_ops: HashMap::new(),
            original_member: (owner_id, owner_pk),
        };
        Ok(cgka)
    }

    pub fn with_new_owner(
        &self,
        my_id: IndividualId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_sks = owner_sks;
        cgka.pcs_keys = self.pcs_keys.clone();
        cgka.pcs_key_ops = self.pcs_key_ops.clone();
        Ok(cgka)
    }

    /// Derive an [`ApplicationSecret`] from our current [`PcsKey`] for new content
    /// to encrypt.
    ///
    /// If the tree does not currently contain a root key, then we must first
    /// perform a leaf key rotation.
    pub fn new_app_secret_for<T: ContentRef, R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        csprng: &mut R,
    ) -> Result<(ApplicationSecret<T>, Option<CgkaOperation>), CgkaError> {
        let mut op = None;
        let current_pcs_key = if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            let (pcs_key, update_op) = self.update(new_share_key, new_share_secret_key, csprng)?;
            self.insert_pcs_key(&pcs_key, Digest::hash(&update_op));
            op = Some(update_op);
            pcs_key
        } else {
            self.pcs_key_from_tree_root()?
        };
        let pcs_key_hash = Digest::hash(&current_pcs_key);
        let nonce = Siv::new(&current_pcs_key.into(), content, self.doc_id)
            .map_err(|_e| CgkaError::Conversion)?;
        Ok((
            current_pcs_key.derive_application_secret(
                &nonce,
                &Digest::hash(content_ref),
                &Digest::hash(pred_refs),
                self.pcs_key_ops.get(&pcs_key_hash).expect("FIXME"),
            ),
            op,
        ))
    }

    /// Derive a decryption key for encrypted data.
    ///
    /// We must first derive a [`PcsKey`] for the encrypted data's associated
    /// hashes. Then we use that [`PcsKey`] to derive an [`ApplicationSecret`].
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
    pub fn add(&mut self, id: IndividualId, pk: ShareKey) -> Result<CgkaOperation, CgkaError> {
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
        };
        self.ops_graph.add_local_op(&op);
        Ok(op)
    }

    /// Add multiple members to group.
    pub fn add_multiple(
        &mut self,
        members: NonEmpty<(IndividualId, ShareKey)>,
    ) -> Result<Vec<CgkaOperation>, CgkaError> {
        let mut ops = Vec::new();
        for m in members {
            ops.push(self.add(m.0, m.1)?);
        }
        Ok(ops)
    }

    /// Remove member from group.
    pub fn remove(&mut self, id: IndividualId) -> Result<CgkaOperation, CgkaError> {
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
        };
        self.ops_graph.add_local_op(&op);
        Ok(op)
    }

    /// Update leaf key pair for this Identifier. This also triggers a tree path
    /// update for that leaf.
    pub fn update<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        csprng: &mut R,
    ) -> Result<(PcsKey, CgkaOperation), CgkaError> {
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
                new_path: Box::new(new_path),
                predecessors,
            };
            self.ops_graph.add_local_op(&op);
            self.insert_pcs_key(&pcs_key, Digest::hash(&op));
            Ok((pcs_key, op))
        } else {
            Err(CgkaError::IdentifierNotFound)
        }
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// Merge concurrent [`CgkaOperation`].
    ///
    /// If we receive a concurrent membership change (i.e., add or remove), then
    /// we add it to our ops graph but don't apply it yet. If there are no outstanding
    /// membership changes and we receive a concurrent update, we can apply it
    /// immediately.
    pub fn merge_concurrent_operation(&mut self, op: &CgkaOperation) -> Result<(), CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(op)) {
            return Ok(());
        }
        let predecessors = op.predecessors();
        let is_concurrent = !self.ops_graph.heads_contained_in(&predecessors);
        if is_concurrent {
            if self.pending_ops_for_structural_change {
                self.ops_graph.add_op(op, &predecessors);
            } else if matches!(op, CgkaOperation::Add { .. } | CgkaOperation::Remove { .. }) {
                self.pending_ops_for_structural_change = true;
                self.ops_graph.add_op(op, &predecessors);
            } else {
                self.apply_operation(op)?;
            }
        } else {
            if self.should_replay() {
                self.replay_ops_graph()?;
            }
            self.apply_operation(op)?;
        }
        Ok(())
    }

    /// Apply a [`CgkaOperation`].
    fn apply_operation(&mut self, op: &CgkaOperation) -> Result<(), CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(op)) {
            return Ok(());
        }
        match op {
            CgkaOperation::Add { added_id, pk, .. } => {
                self.tree.push_leaf(*added_id, (*pk).into());
            }
            CgkaOperation::Remove { id, .. } => {
                self.tree.remove_id(*id)?;
            }
            CgkaOperation::Update { new_path, .. } => {
                self.tree.apply_path(new_path);
            }
        }
        self.ops_graph.add_op(op, &op.predecessors());
        Ok(())
    }

    /// Apply operations grouped into "epochs", where each epoch contains an ordered
    /// set of concurrent operations.
    fn apply_epochs(&mut self, epochs: &NonEmpty<CgkaEpoch>) -> Result<(), CgkaError> {
        for epoch in epochs {
            if epoch.len() == 1 {
                self.apply_operation(&epoch[0])?;
            } else {
                // If all operations in this epoch are updates, we can apply them
                // directly and move on to the next epoch.
                if epoch
                    .iter()
                    .all(|op| matches!(op.borrow(), CgkaOperation::Update { .. }))
                {
                    for op in epoch.iter() {
                        self.apply_operation(op)?;
                    }
                    continue;
                }

                // An epoch with at least one membership change requires blanking
                // removed paths and sorting added leaves after all ops are applied.
                let mut added_ids = HashSet::new();
                let mut removed_ids = HashSet::new();
                for op in epoch.iter() {
                    match op.borrow() {
                        CgkaOperation::Add { added_id, .. } => {
                            added_ids.insert(*added_id);
                        }
                        CgkaOperation::Remove { id, leaf_idx, .. } => {
                            removed_ids.insert((*id, *leaf_idx));
                        }
                        _ => {}
                    }
                    self.apply_operation(op)?;
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
    fn pcs_key_from_hashes(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<CgkaOperation>,
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
    fn derive_pcs_key_for_op(
        &mut self,
        op_hash: &Digest<CgkaOperation>,
    ) -> Result<PcsKey, CgkaError> {
        if !self.ops_graph.contains_op_hash(op_hash) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let mut heads = HashSet::new();
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
    fn replay_ops_graph(&mut self) -> Result<(), CgkaError> {
        let ordered_ops = self.ops_graph.topsort_graph()?;
        let rebuilt_cgka = self.rebuild_cgka(ordered_ops)?;
        self.update_cgka_from(&rebuilt_cgka);
        self.pending_ops_for_structural_change = false;
        Ok(())
    }

    /// Build a new [`Cgka`] for the provided non-empty list of [`CgkaEpoch`]s.
    fn rebuild_cgka(&mut self, epochs: NonEmpty<CgkaEpoch>) -> Result<Cgka, CgkaError> {
        let mut rebuilt_cgka =
            Cgka::new(self.doc_id, self.original_member.0, self.original_member.1)?
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
    fn rebuild_pcs_key(&mut self, epochs: NonEmpty<CgkaEpoch>) -> Result<PcsKey, CgkaError> {
        debug_assert!(matches!(
            epochs.last()[0].borrow(),
            &CgkaOperation::Update { .. }
        ));
        let mut rebuilt_cgka =
            Cgka::new(self.doc_id, self.original_member.0, self.original_member.1)?
                .with_new_owner(self.owner_id, self.owner_sks.clone())?;
        rebuilt_cgka.apply_epochs(&epochs)?;
        let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
        self.insert_pcs_key(&pcs_key, Digest::hash(&epochs.last()[0]));
        Ok(pcs_key)
    }

    fn insert_pcs_key(&mut self, pcs_key: &PcsKey, op_hash: Digest<CgkaOperation>) {
        self.pcs_key_ops.insert(Digest::hash(pcs_key), op_hash);
        self.pcs_keys.insert((*pcs_key).into());
    }

    /// Extend our state with that of the provided [`Cgka`].
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

#[cfg(feature = "test_utils")]
impl Cgka {
    pub fn secret_from_root(&mut self) -> Result<PcsKey, CgkaError> {
        self.pcs_key_from_tree_root()
    }

    pub fn secret(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<CgkaOperation>,
    ) -> Result<PcsKey, CgkaError> {
        self.pcs_key_from_hashes(pcs_key_hash, update_op_hash)
    }
}

#[cfg(feature = "test_utils")]
#[cfg(test)]
mod tests {
    use test_utils::{
        add_from_all_members, add_from_first_member, apply_test_operations_and_merge_to_all,
        remove_from_left, remove_from_right, remove_odd_members, setup_cgka, setup_member_cgkas,
        setup_members, update_added_members, update_all_members, update_even_members,
        update_odd_members, TestMember, TestMemberCgka, TestOperation,
    };

    use super::*;

    #[test]
    fn test_root_key_after_update_is_not_leaf_sk() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        let doc_id = DocumentId::generate(csprng);
        let members = setup_members(2);
        let (mut cgka, _ops) = setup_cgka(doc_id, &members, 0);
        let sk = ShareSecretKey::generate(csprng);
        let sk_pcs_key: PcsKey = sk.clone().into();
        let pk = sk.share_key();
        let (pcs_key, op) = cgka.update(pk, sk.clone(), csprng)?;
        assert_ne!(
            sk_pcs_key,
            cgka.secret(&Digest::hash(&pcs_key), &Digest::hash(&op))?
        );
        Ok(())
    }

    #[test]
    fn test_simple_add() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        let doc_id = DocumentId::generate(csprng);
        let members = setup_members(2);
        let initial_member_count = members.len();
        let (mut cgka, _ops) = setup_cgka(doc_id, &members, 0);
        assert!(cgka.has_pcs_key());
        let new_m = TestMember::generate(csprng);
        cgka.add(new_m.id, new_m.pk)?;
        assert!(!cgka.has_pcs_key());
        assert_eq!(cgka.tree.member_count(), initial_member_count as u32 + 1);
        Ok(())
    }

    #[test]
    fn test_simple_remove() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        let doc_id = DocumentId::generate(csprng);
        let members = setup_members(2);
        let initial_member_count = members.len();
        let (mut cgka, _ops) = setup_cgka(doc_id, &members, 0);
        assert!(cgka.has_pcs_key());
        cgka.remove(members[1].id)?;
        assert!(!cgka.has_pcs_key());
        assert_eq!(cgka.group_size(), initial_member_count as u32 - 1);
        Ok(())
    }

    #[test]
    fn test_no_root_key_after_concurrent_updates() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        let doc_id = DocumentId::generate(csprng);
        let (mut cgkas, _ops) = setup_member_cgkas(doc_id, 7)?;
        assert!(cgkas[0].cgka.has_pcs_key());
        let (_pcs_key, op1) = cgkas[1].update(csprng)?;
        cgkas[0].cgka.merge_concurrent_operation(&op1)?;
        let (_pcs_key, op6) = cgkas[6].update(csprng)?;
        cgkas[0].cgka.merge_concurrent_operation(&op6)?;
        assert!(!cgkas[0].cgka.has_pcs_key());
        Ok(())
    }

    fn update_merge_and_compare_secrets<R: rand::CryptoRng + rand::RngCore>(
        member_cgkas: &mut Vec<TestMemberCgka>,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        let m_idx = if member_cgkas.len() > 1 { 1 } else { 0 };
        let (post_update_pcs_key, update_op) = member_cgkas[m_idx].update(csprng)?;
        for (idx, m) in member_cgkas.iter_mut().enumerate() {
            if idx == m_idx {
                continue;
            }
            m.cgka.merge_concurrent_operation(&update_op.clone())?;
        }
        // Compare the result of secret() for all members
        for m in member_cgkas.iter_mut() {
            assert_eq!(
                m.cgka.secret(
                    &Digest::hash(&post_update_pcs_key),
                    &Digest::hash(&update_op)
                )?,
                post_update_pcs_key
            );
        }
        Ok(())
    }

    /// A "test round" is a series of TestOperation functions which are applied
    /// concurrently. This function applies each round and then does a single update
    /// and merge across members to check that everyone converges on the same secret
    /// after that round.
    fn run_test_rounds<R: rand::CryptoRng + rand::RngCore>(
        member_count: u32,
        test_rounds: &[Vec<Box<TestOperation>>],
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        assert!(member_count >= 1);
        let doc_id = DocumentId::generate(csprng);
        let (mut member_cgkas, ops) = setup_member_cgkas(doc_id, member_count)?;
        let mut initial_cgka = member_cgkas[0].cgka.clone();
        let initial_pcs_key = initial_cgka.secret_from_root()?;
        let update_op = ops.last().expect("update op");
        for m in &mut member_cgkas {
            assert_eq!(
                m.cgka
                    .secret(&Digest::hash(&initial_pcs_key), &Digest::hash(&update_op))?,
                initial_pcs_key
            );
        }
        for test_round in test_rounds {
            apply_test_operations_and_merge_to_all(&mut member_cgkas, test_round)?;
            update_merge_and_compare_secrets(&mut member_cgkas, csprng)?;
        }
        Ok(())
    }

    fn run_tests_for_various_member_counts<R: rand::CryptoRng + rand::RngCore>(
        test_rounds: Vec<Vec<Box<TestOperation>>>,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        for n in 1..16 {
            run_test_rounds(n, &test_rounds, csprng)?;
        }
        Ok(())
    }

    #[test]
    fn test_update_all_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(vec![vec![update_all_members()]], &mut csprng)
    }

    #[test]
    fn test_update_even_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(vec![vec![update_even_members()]], &mut csprng)
    }

    #[test]
    fn test_remove_odd_concurrently() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        run_tests_for_various_member_counts(vec![vec![remove_odd_members()]], csprng)
    }

    #[test]
    fn test_remove_from_right_concurrently() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        run_tests_for_various_member_counts(vec![vec![remove_from_right(1)]], csprng)
    }

    #[test]
    fn test_remove_from_left_concurrently() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        run_tests_for_various_member_counts(vec![vec![remove_from_left(1)]], csprng)
    }

    #[test]
    fn test_update_then_remove_then_update_even_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(
            vec![
                vec![update_all_members()],
                vec![remove_odd_members()],
                vec![update_even_members()],
            ],
            &mut csprng,
        )
    }

    #[test]
    fn test_update_and_remove_one_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(
            vec![vec![remove_from_right(1), update_odd_members()]],
            &mut csprng,
        )
    }

    #[test]
    fn test_update_and_remove_odd_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(
            vec![vec![
                update_all_members(),
                remove_odd_members(),
                update_even_members(),
            ]],
            &mut csprng,
        )
    }

    #[test]
    fn test_update_and_add_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(
            vec![vec![update_all_members(), add_from_all_members()]],
            &mut csprng,
        )
    }

    #[test]
    fn test_add_one_concurrently() -> Result<(), CgkaError> {
        run_tests_for_various_member_counts(
            vec![vec![add_from_first_member()]],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_all_add_one_concurrently() -> Result<(), CgkaError> {
        run_tests_for_various_member_counts(
            vec![vec![add_from_all_members()]],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_remove_then_all_add_one_then_remove_odd_concurrently() -> Result<(), CgkaError> {
        run_tests_for_various_member_counts(
            vec![
                vec![remove_from_right(1)],
                vec![add_from_all_members()],
                vec![remove_odd_members()],
            ],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_update_all_then_add_from_all_then_remove_odd_then_update_even_concurrently(
    ) -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_various_member_counts(
            vec![
                vec![update_all_members()],
                vec![add_from_all_members()],
                vec![remove_odd_members()],
                vec![update_even_members()],
            ],
            &mut csprng,
        )
    }

    #[test]
    fn test_all_members_add_and_update_concurrently() -> Result<(), CgkaError> {
        run_tests_for_various_member_counts(
            vec![vec![add_from_all_members(), update_all_members()]],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_update_added_members_concurrently() -> Result<(), CgkaError> {
        run_tests_for_various_member_counts(
            vec![vec![add_from_all_members(), update_added_members()]],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_a_bunch_of_ops_in_rounds() -> Result<(), CgkaError> {
        run_tests_for_various_member_counts(
            vec![vec![
                update_all_members(),
                add_from_all_members(),
                add_from_first_member(),
                remove_odd_members(),
                add_from_first_member(),
                remove_from_right(1),
                remove_from_left(1),
                update_even_members(),
                add_from_first_member(),
                update_even_members(),
                add_from_first_member(),
                remove_from_left(2),
                remove_odd_members(),
                update_all_members(),
                add_from_first_member(),
                remove_from_right(2),
                update_even_members(),
            ]],
            &mut rand::thread_rng(),
        )
    }
}
