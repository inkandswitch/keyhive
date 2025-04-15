use super::{
    error::CgkaError, keys::NodeKey, keys::ShareKeyMap, secret_store::SecretStore, treemath,
};
use crate::{
    crypto::{
        application_secret::PcsKey,
        encrypted::EncryptedSecret,
        share_key::{ShareKey, ShareSecretKey},
        siv::Siv,
    },
    principal::{document::id::DocumentId, individual::id::IndividualId},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use tracing::instrument;
use treemath::{InnerNodeIndex, LeafNodeIndex, TreeNodeIndex, TreeSize};

pub type InnerNode = SecretStore;

/// A PathChange represents an update along a path from a leaf to the root.
/// This includes both the new public keys for each node and the keys that have
/// been removed as part of this change.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct PathChange {
    pub leaf_id: IndividualId,
    pub leaf_idx: u32,
    pub leaf_pk: NodeKey,
    // (u32 inner node index, new inner node)
    pub path: Vec<(u32, InnerNode)>,
    pub removed_keys: Vec<ShareKey>,
}

/// BeeKEM is our variant of the [TreeKEM] protocol (used in [MLS]) and inspired by
/// [Matthew Weidner's Causal TreeKEM][Causal TreeKEM]. The distinctive
/// feature of BeeKEM is that when merging concurrent updates, we keep all concurrent
/// public keys at any node where there is a conflict (until they are overwritten by
/// a future update along that path). The conflict keys are used to ensure
/// that a passive adversary needs all of the historical secret keys at
/// one of the leaves in order to read the latest root secret after a merge.
///
/// Leaf nodes represent group members. Each member has a fixed identifier as well
/// as a public key that is rotated over time. Each inner node stores one or more
/// public keys and an encrypted secret used for (deriving a shared key for) decrypting
/// its parent.
///
/// During a key rotation, a leaf will update its public key and then encrypt its path
/// to the root. For each parent it attempts to encrypt, it will encounter one of a few
/// cases:
/// * In the "normal" case, the child's sibling will have a single public key and a
///   corresponding secret key. The child uses the public key of its sibling to derive
///   a shared Diffie Hellman (DH) secret. It then uses this shared DH secret to
///   encrypt the new parent secret.
/// * In case of a blank or conflict sibling, the encrypting child encrypts the secret
///   for each of the nodes in its sibling's resolution (which is the set of the highest
///   non-blank, non-conflict descendents of the sibling). This means a separate DH per
///   node in that resolution. These encryptions of the secret are stored in a map at
///   the parent.
///
/// [Causal TreeKEM]: https://mattweidner.com/assets/pdf/acs-dissertation.pdf
/// [MLS]: https://messaginglayersecurity.rocks/
/// [TreeKEM]: https://inria.hal.science/hal-02425247/file/treekem+(1).pdf
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub(crate) struct BeeKem {
    doc_id: DocumentId,
    /// The next [`LeafNodeIndex`] available for adding a new member.
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    inner_nodes: Vec<Option<InnerNode>>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<IndividualId, LeafNodeIndex>,
    /// The leaf node that was the source of the last path encryption, or [`None`]
    /// if there is currently no root key. This is used to determine when a
    /// decrypter has intersected with the encrypter's path.
    current_secret_encrypter_leaf_idx: Option<LeafNodeIndex>,
}

impl BeeKem {
    pub(crate) fn new(
        doc_id: DocumentId,
        initial_member_id: IndividualId,
        initial_member_pk: ShareKey,
    ) -> Result<Self, CgkaError> {
        let mut tree = Self {
            doc_id,
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            inner_nodes: Vec::new(),
            tree_size: TreeSize::from_leaf_count(1),
            id_to_leaf_idx: BTreeMap::new(),
            current_secret_encrypter_leaf_idx: None,
        };
        tree.grow_tree_to_size();
        tree.push_leaf(initial_member_id, initial_member_pk.into());
        Ok(tree)
    }

    pub(crate) fn contains_id(&self, id: &IndividualId) -> bool {
        self.id_to_leaf_idx.contains_key(id)
    }

    pub(crate) fn node_key_for_id(&self, id: IndividualId) -> Result<NodeKey, CgkaError> {
        let idx = self.leaf_index_for_id(id)?;
        self.node_key_for_index((*idx).into())
    }

    /// For concurrent membership changes, we need to ensure that removed paths
    /// are blanked and concurrently added member leaves are sorted (and their
    /// paths blanked) after any other concurrent operations were applied.
    ///
    /// Sorting concurrently added leaves deterministically resolves add conflicts
    /// (e.g., if two members concurrently add distinct members to the same leaf).
    pub(crate) fn sort_leaves_and_blank_paths_for_concurrent_membership_changes(
        &mut self,
        mut added_ids: HashSet<IndividualId>,
        removed_ids: HashSet<(IndividualId, u32)>,
    ) {
        let mut leaves_to_sort = Vec::new();
        for (id, idx) in removed_ids {
            added_ids.remove(&id);
            let leaf_idx = LeafNodeIndex::new(idx);
            debug_assert!(self.leaf(leaf_idx).is_none());
            // We should have already removed this id during merge, but concurrent
            // updates at other leaves with intersecting paths must be overridden by
            // this remove.
            self.blank_leaf_and_path(leaf_idx);
        }
        while !added_ids.is_empty() && self.next_leaf_idx.u32() > 0 {
            let leaf_idx = self.next_leaf_idx - 1;
            if let Some(next_leaf) = self.leaf(leaf_idx).clone() {
                added_ids.remove(&next_leaf.id);
                leaves_to_sort.push(next_leaf);
            }
            self.blank_leaf_and_path(leaf_idx);
            self.next_leaf_idx = leaf_idx;
        }
        leaves_to_sort.sort_by(|a, b| a.id.cmp(&b.id));
        for leaf in leaves_to_sort {
            self.push_leaf(leaf.id, leaf.pk.clone());
        }
    }

    /// Blank the leaf at the provided [`LeafNodeIndex`] as well as its path
    /// to the root.
    pub(crate) fn blank_leaf_and_path(&mut self, idx: LeafNodeIndex) {
        self.leaves[idx.usize()] = None;
        self.blank_path(treemath::parent(idx.into()));
    }

    /// Add a new leaf to the first available [`LeafNodeIndex`] on the right and
    /// blank that leaf's path to the root.
    pub(crate) fn push_leaf(&mut self, id: IndividualId, pk: NodeKey) -> u32 {
        self.maybe_grow_tree(self.next_leaf_idx.u32());
        let l_idx = self.next_leaf_idx;
        self.next_leaf_idx += 1;
        self.insert_leaf_at(l_idx, id, pk);
        self.id_to_leaf_idx.insert(id, l_idx);
        self.blank_path(treemath::parent(l_idx.into()));
        l_idx.u32()
    }

    /// Remove data for the provided [`IndividualId`] and blank its leaf's
    /// path to the root.
    pub(crate) fn remove_id(
        &mut self,
        id: IndividualId,
    ) -> Result<(u32, Vec<ShareKey>), CgkaError> {
        if self.member_count() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }
        let l_idx = *self.leaf_index_for_id(id)?;
        let mut removed_keys = Vec::new();
        for idx in treemath::direct_path((l_idx).into(), self.tree_size) {
            if let Some(store) = self.inner_node(idx) {
                removed_keys.append(&mut store.node_key().keys());
            }
        }
        self.blank_leaf_and_path(l_idx);
        self.id_to_leaf_idx.remove(&id);
        // Collect any contiguous "tombstones" at the end of the leaves Vec
        while self.leaf(self.next_leaf_idx - 1).is_none() {
            self.blank_path(treemath::parent((self.next_leaf_idx - 1).into()));
            self.next_leaf_idx -= 1;
        }
        Ok((l_idx.u32(), removed_keys))
    }

    /// The count of members currently in the tree.
    pub(crate) fn member_count(&self) -> u32 {
        self.id_to_leaf_idx.len() as u32
    }

    /// Decrypt the current tree secret.
    ///
    /// Starting from the owner's leaf, move up the tree toward the root (i.e., along the
    /// leaf's path). As you look at each parent node along the way, if the node is not
    /// blank, look up the encrypted secret in the parent's secret store using your child
    /// index. Derive a Diffie Hellman shared key using the encrypter public key stored in
    /// the secret store and use that shared key to decrypt the secret key you looked up.
    ///
    /// Hold on to each idx you've seen along the way since ancestors might have been
    /// encrypted for any of these descendents (in cases like a blank node or
    /// conflicting keys on a node on the path).
    #[instrument(skip_all, fields(doc_id, epochs))]
    pub(crate) fn decrypt_tree_secret(
        &self,
        owner_id: IndividualId,
        owner_sks: &mut ShareKeyMap,
    ) -> Result<ShareSecretKey, CgkaError> {
        let leaf_idx = *self.leaf_index_for_id(owner_id)?;
        if !self.has_root_key() {
            return Err(CgkaError::NoRootKey);
        }
        let leaf = self
            .leaf(leaf_idx)
            .as_ref()
            .expect("Leaf should not be blank");
        if Some(leaf_idx) == self.current_secret_encrypter_leaf_idx {
            let NodeKey::ShareKey(pk) = leaf.pk else {
                return Err(CgkaError::ShareKeyNotFound);
            };
            let secret = owner_sks.get(&pk).ok_or(CgkaError::ShareKeyNotFound)?;
            return Ok(secret
                .ratchet_n_forward(treemath::direct_path(leaf_idx.into(), self.tree_size).len()));
        }
        let lca_with_encrypter = treemath::lowest_common_ancestor(
            leaf_idx,
            self.current_secret_encrypter_leaf_idx
                .expect("A tree with a root key should have a current encrypter"),
        );
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut seen_idxs = vec![child_idx];
        // We will return this at the end once we've decrypted the root secret.
        let mut maybe_last_secret_decrypted = None;
        let mut child_node_key = leaf.pk.clone();
        let mut parent_idx: TreeNodeIndex = treemath::parent(child_idx).into();
        while !self.is_root(child_idx) {
            // Find the next non-blank, non-conflict parent
            while self.should_skip_for_resolution(parent_idx) {
                child_idx = parent_idx;
                parent_idx = treemath::parent(child_idx).into();
            }
            debug_assert!(!self.is_root(child_idx));
            maybe_last_secret_decrypted =
                self.maybe_decrypt_parent_key(child_idx, &child_node_key, &seen_idxs, owner_sks)?;
            let Some(ref secret) = maybe_last_secret_decrypted else {
                panic!("Non-blank, non-conflict parent should have a secret we can decrypt");
            };
            // If we have reached the intersection of our path with the encrypter's
            // path, then we can ratchet this parent secret forward for each of the
            // remaining nodes in the path and return early.
            if parent_idx == TreeNodeIndex::Inner(lca_with_encrypter) {
                return Ok(secret
                    .ratchet_n_forward(treemath::direct_path(parent_idx, self.tree_size).len()));
            }
            seen_idxs.push(parent_idx);
            child_idx = parent_idx;
            child_node_key = self.node_key_for_index(child_idx)?;
            parent_idx = treemath::parent(child_idx).into();
        }
        maybe_last_secret_decrypted.ok_or(CgkaError::NoRootKey)
    }

    /// Rotate key and encrypt new secrets along the provided [`IndividualId`]'s path.
    /// This will result in a new root key for the tree.
    ///
    /// Starting from the owner's leaf, move up the tree toward the root (i.e., along the
    /// leaf's path). As you look at each parent node along the way, you need to populate
    /// it with a public key and a map from sibling subtree public keys to newly generated
    /// secret keys encrypted pairwise with each node in the sibling resolution (in the
    /// ideal case, this will just be the sibling node itself, but if the sibling is
    /// blank or contains conflict keys it can be many nodes).
    ///
    /// If your sibling node's resolution is empty, then you will generate the new key
    /// pair but encrypt the secret by doing Diffie Hellman with a different key pair
    /// generated just for that purpose. The secret store for that parent will then
    /// only have an entry for you.
    pub(crate) fn encrypt_path<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        sks: &mut ShareKeyMap,
        csprng: &mut R,
    ) -> Result<Option<(PcsKey, PathChange)>, CgkaError> {
        let leaf_idx = *self.leaf_index_for_id(id)?;
        debug_assert!(self.id_for_leaf(leaf_idx).unwrap() == id);
        let mut new_path = PathChange {
            leaf_id: id,
            leaf_idx: leaf_idx.u32(),
            leaf_pk: NodeKey::ShareKey(pk),
            path: Vec::new(),
            removed_keys: self.node_key_for_id(id)?.keys(),
        };
        self.insert_leaf_at(leaf_idx, id, NodeKey::ShareKey(pk));
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        // An encrypter will always have a single public key at each node as it
        // encrypts up its path. At its leaf, it will have written the latest public
        // key at the start. And as it moves up the path, it will generate a new public
        // key for each ancestor up to the root.
        let mut child_pk = pk;
        let mut child_sk = *sks.get(&pk).ok_or(CgkaError::SecretKeyNotFound)?;
        let mut parent_idx = treemath::parent(child_idx);
        while !self.is_root(child_idx) {
            if let Some(store) = self.inner_node(parent_idx) {
                new_path.removed_keys.append(&mut store.node_key().keys());
            }
            let new_parent_sk = child_sk.ratchet_forward();
            let new_parent_pk = new_parent_sk.share_key();
            self.encrypt_key_for_parent(
                child_idx,
                child_pk,
                &child_sk,
                new_parent_pk,
                &new_parent_sk,
                csprng,
            )?;
            new_path.path.push((
                parent_idx.u32(),
                self.inner_node(parent_idx)
                    .as_ref()
                    .expect("Parent node should not be None after encryption")
                    .clone(),
            ));
            child_idx = parent_idx.into();
            child_pk = new_parent_pk;
            child_sk = new_parent_sk;
            parent_idx = treemath::parent(child_idx);
        }
        self.current_secret_encrypter_leaf_idx = Some(leaf_idx);
        Ok(Some((child_sk.into(), new_path)))
    }

    /// Applies a [`PathChange`] representing new public and encrypted secret keys for each
    /// node on a path.
    pub(crate) fn apply_path(&mut self, new_path: &PathChange) {
        // If this id has been concurrently removed, it might no longer be present
        // when we try to apply the concurrent update at that id.
        if !self.id_to_leaf_idx.contains_key(&new_path.leaf_id) {
            return;
        }
        let leaf_idx = *self
            .leaf_index_for_id(new_path.leaf_id)
            .expect("Id should be present");
        if !self.is_valid_path(new_path) {
            // Since this path is no longer valid, we can only update the leaf for
            // this id.
            let Some(leaf) = self.leaf(leaf_idx) else {
                panic!("Leaf for present ID should not be None");
            };
            let new_node_key = leaf.pk.merge(&new_path.leaf_pk, &new_path.removed_keys);
            self.insert_leaf_at(leaf_idx, new_path.leaf_id, new_node_key);
            self.blank_path(treemath::parent(leaf_idx.into()));
            return;
        }

        let old_leaf = self.leaf(leaf_idx).as_ref().unwrap();
        let new_leaf_pk = new_path.leaf_pk.clone();
        self.insert_leaf_at(
            leaf_idx,
            new_path.leaf_id,
            old_leaf.pk.merge(&new_leaf_pk, &new_path.removed_keys),
        );

        let removed_keys_set: HashSet<ShareKey> =
            HashSet::from_iter(new_path.removed_keys.iter().copied());
        for (idx, node) in &new_path.path {
            let current_idx = InnerNodeIndex::new(*idx);
            if let Some(current_node) = self.inner_node_mut(current_idx) {
                current_node.merge(node, &removed_keys_set);
            } else {
                self.insert_inner_node_at(current_idx, node.clone());
            }
        }

        if self.has_root_key() {
            self.current_secret_encrypter_leaf_idx = Some(leaf_idx);
        } else {
            self.current_secret_encrypter_leaf_idx = None;
        }
    }

    /// Whether the tree currently has a root key.
    pub(crate) fn has_root_key(&self) -> bool {
        let root_idx: TreeNodeIndex = treemath::root(self.tree_size);
        let TreeNodeIndex::Inner(p_idx) = root_idx else {
            panic!("BeeKEM should always have a root at an inner node.")
        };
        if let Some(r) = self.inner_node(p_idx) {
            !r.has_conflict()
        } else {
            false
        }
    }

    /// Decrypt parent node's [`ShareSecretKey`].
    ///
    /// Returns the secret if there is a single parent public key.
    /// In either case, adds any public key/decrypted secret key pairs
    /// it encounters to the [`ShareKeyMap`].
    fn maybe_decrypt_parent_key(
        &self,
        child_idx: TreeNodeIndex,
        child_node_key: &NodeKey,
        seen_idxs: &[TreeNodeIndex],
        child_sks: &mut ShareKeyMap,
    ) -> Result<Option<ShareSecretKey>, CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        let Some(parent) = self.inner_node(parent_idx) else {
            return Ok(None);
        };

        let maybe_secret = match parent.node_key() {
            NodeKey::ConflictKeys(_) => None,
            NodeKey::ShareKey(parent_pk) => {
                if child_sks.contains_key(&parent_pk) {
                    return Ok(child_sks.get(&parent_pk).cloned());
                }
                let secret = parent.decrypt_secret(child_node_key, child_sks, seen_idxs)?;
                child_sks.insert(parent_pk, secret);
                Some(secret)
            }
        };
        Ok(maybe_secret)
    }

    /// Encrypt new secret for parent node.
    fn encrypt_key_for_parent<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        child_idx: TreeNodeIndex,
        child_pk: ShareKey,
        child_sk: &ShareSecretKey,
        new_parent_pk: ShareKey,
        new_parent_sk: &ShareSecretKey,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        let secret_store = self.encrypt_new_secret_store_for_parent(
            child_idx,
            child_pk,
            child_sk,
            new_parent_pk,
            new_parent_sk,
            csprng,
        )?;
        self.insert_inner_node_at(parent_idx, secret_store);
        Ok(())
    }

    /// Build a new [`SecretStore`] for parent node.
    ///
    /// Encrypt the new parent [`ShareSecretKey`] for each member of your sibling
    /// node's resolution. These are then stored in the new [`SecretStore`], indexed
    /// by the tree index for each member of that resolution.
    #[allow(clippy::type_complexity)]
    fn encrypt_new_secret_store_for_parent<R: rand::CryptoRng + rand::RngCore>(
        &self,
        child_idx: TreeNodeIndex,
        child_pk: ShareKey,
        child_sk: &ShareSecretKey,
        new_parent_pk: ShareKey,
        new_parent_sk: &ShareSecretKey,
        csprng: &mut R,
    ) -> Result<SecretStore, CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let sibling_idx = treemath::sibling(child_idx);
        let mut secret_map = BTreeMap::new();
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution);
        if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you generate a key pair
            // just to do DH with when ecrypting the new parent secret.
            let paired_sk = ShareSecretKey::generate(csprng);
            let paired_pk = paired_sk.share_key();
            let encrypted_sk = encrypt_secret(self.doc_id, *new_parent_sk, child_sk, &paired_pk)?;
            secret_map.insert(child_idx, encrypted_sk);
        } else {
            // Encrypt the secret for every node in the sibling resolution, using
            // a new DH shared secret to do the encryption for each node.
            let mut used_paired_sibling = false;
            for idx in sibling_resolution {
                let next_pk = match self.node_key_for_index(idx)? {
                    NodeKey::ShareKey(share_key) => share_key,
                    _ => panic!("Sibling resolution nodes should have exactly one ShareKey"),
                };
                let encrypted_sk = encrypt_secret(self.doc_id, *new_parent_sk, child_sk, &next_pk)?;
                if !used_paired_sibling {
                    secret_map.insert(child_idx, encrypted_sk.clone());
                    used_paired_sibling = true;
                }
                secret_map.insert(idx, encrypted_sk);
            }
        };

        Ok(SecretStore::new(new_parent_pk, child_pk, secret_map))
    }

    fn node_key_for_index(&self, idx: TreeNodeIndex) -> Result<NodeKey, CgkaError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self
                .leaf(l_idx)
                .as_ref()
                .ok_or(CgkaError::ShareKeyNotFound)?
                .pk
                .clone(),
            TreeNodeIndex::Inner(i_idx) => self
                .inner_node(i_idx)
                .as_ref()
                .ok_or(CgkaError::ShareKeyNotFound)?
                .node_key(),
        })
    }

    fn leaf(&self, idx: LeafNodeIndex) -> &Option<LeafNode> {
        self.leaves
            .get(idx.usize())
            .expect("Leaf index should be in bounds")
    }

    pub(crate) fn leaf_index_for_id(&self, id: IndividualId) -> Result<&LeafNodeIndex, CgkaError> {
        self.id_to_leaf_idx
            .get(&id)
            .ok_or(CgkaError::IdentifierNotFound)
    }

    fn id_for_leaf(&self, idx: LeafNodeIndex) -> Result<IndividualId, CgkaError> {
        Ok(self
            .leaf(idx)
            .as_ref()
            .ok_or(CgkaError::IdentifierNotFound)?
            .id)
    }

    fn inner_node(&self, idx: InnerNodeIndex) -> &Option<InnerNode> {
        self.inner_nodes
            .get(idx.usize())
            .expect("Inner node index should be in bounds")
    }

    fn inner_node_mut(&mut self, idx: InnerNodeIndex) -> &mut Option<InnerNode> {
        self.inner_nodes
            .get_mut(idx.usize())
            .expect("Node should not be blank")
    }

    fn insert_leaf_at(&mut self, idx: LeafNodeIndex, id: IndividualId, pk: NodeKey) {
        let leaf = LeafNode { id, pk };
        self.leaves[idx.usize()] = Some(leaf);
    }

    fn insert_inner_node_at(&mut self, idx: InnerNodeIndex, secret_store: SecretStore) {
        self.inner_nodes[idx.usize()] = Some(secret_store);
    }

    fn is_blank(&self, idx: TreeNodeIndex) -> bool {
        match idx {
            TreeNodeIndex::Leaf(l_idx) => self.leaf(l_idx).is_none(),
            TreeNodeIndex::Inner(p_idx) => self.inner_node(p_idx).is_none(),
        }
    }

    fn should_skip_for_resolution(&self, idx: TreeNodeIndex) -> bool {
        match idx {
            TreeNodeIndex::Leaf(_) => self.is_blank(idx),
            TreeNodeIndex::Inner(i_idx) => self
                .inner_node(i_idx)
                .as_ref()
                .is_none_or(|n| n.has_conflict()),
        }
    }

    fn blank_path(&mut self, mut idx: InnerNodeIndex) {
        while !self.is_root(idx.into()) {
            self.blank_inner_node(idx);
            idx = treemath::parent(idx.into());
        }
        self.blank_inner_node(idx);
        self.current_secret_encrypter_leaf_idx = None;
    }

    fn blank_inner_node(&mut self, idx: InnerNodeIndex) {
        self.inner_nodes[idx.usize()] = None;
    }

    /// Whether the [`PathChange`] still makes sense given the state of the tree
    /// we are attempting to merge it into.
    fn is_valid_path(&self, new_path: &PathChange) -> bool {
        debug_assert!(self.id_to_leaf_idx.contains_key(&new_path.leaf_id));
        let leaf_idx = self
            .leaf_index_for_id(new_path.leaf_id)
            .expect("Id should be present");
        new_path.path.len() == self.path_length_for(LeafNodeIndex::new(new_path.leaf_idx))
            && leaf_idx.u32() == new_path.leaf_idx
    }

    /// Growing the tree will add a new root and a new subtree, all blank.
    fn maybe_grow_tree(&mut self, new_count: u32) {
        if self.tree_size >= TreeSize::from_leaf_count(new_count) {
            return;
        }
        self.tree_size.inc();
        self.grow_tree_to_size();
    }

    fn grow_tree_to_size(&mut self) {
        self.leaves
            .resize(self.tree_size.leaf_count() as usize, None);
        self.inner_nodes
            .resize(self.tree_size.inner_node_count() as usize, None);
    }

    fn is_root(&self, idx: TreeNodeIndex) -> bool {
        idx == treemath::root(self.tree_size)
    }

    fn path_length_for(&self, idx: LeafNodeIndex) -> usize {
        treemath::direct_path(idx.into(), self.tree_size).len()
    }

    /// Highest non-blank, non-conflict descendants of a node
    fn append_resolution(&self, idx: TreeNodeIndex, acc: &mut Vec<TreeNodeIndex>) {
        if self.should_skip_for_resolution(idx) {
            if let TreeNodeIndex::Inner(i_idx) = idx {
                let left_idx = treemath::left(i_idx);
                self.append_resolution(left_idx, acc);
                let right_idx = treemath::right(i_idx);
                self.append_resolution(right_idx, acc);
            }
        } else {
            acc.push(idx);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub struct LeafNode {
    pub id: IndividualId,
    pub pk: NodeKey,
}

fn encrypt_secret(
    doc_id: DocumentId,
    secret: ShareSecretKey,
    sk: &ShareSecretKey,
    paired_pk: &ShareKey,
) -> Result<EncryptedSecret<ShareSecretKey>, CgkaError> {
    let key = sk.derive_symmetric_key(paired_pk);
    let mut ciphertext: Vec<u8> = (&secret).into();
    let nonce = Siv::new(&key, &ciphertext, doc_id)
        .map_err(|e| CgkaError::DeriveNonce(format!("{:?}", e)))?;
    key.try_encrypt(nonce, &mut ciphertext)
        .map_err(CgkaError::Encryption)?;
    Ok(EncryptedSecret::new(nonce, ciphertext, *paired_pk))
}
