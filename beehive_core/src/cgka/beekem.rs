use super::{
    error::CgkaError, keys::NodeKey, keys::ShareKeyMap, secret_store::SecretStore, treemath,
};
use crate::{
    crypto::{
        encrypted::NestedEncrypted,
        share_key::{ShareKey, ShareSecretKey},
    },
    principal::{document::id::DocumentId, identifier::Identifier},
};
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use treemath::{InnerNodeIndex, LeafNodeIndex, TreeNodeIndex, TreeSize};

pub type InnerNode = SecretStore;

/// A PathChange represents an update along a path from a leaf to the root.
/// This includes both the new public keys for each node and the keys that have
/// been removed as part of this change.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathChange {
    pub leaf_id: Identifier,
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
/// a future update along that path). The conflict keys are used for nested encryption,
/// ensuring that a passive adversary needs all of the historical secret keys at
/// one of the leaves in order to read the latest secret after a merge.
///
/// Leaf nodes represent group members. Each member has a fixed Identifier as well as a
/// public key that is rotated over time. Each non-leaf node stores one or more public
/// keys and a secret used for (deriving a shared key for) decrypting its parent.
///
/// During a key rotation, a leaf will update its public key and then encrypt its path
/// to the root. For each parent it attempts to encrypt, it will encounter one of a few
/// cases:
/// * In the "normal" case, the child's sibling will have a single public key and a
///   corresponding secret key. That secret is encrypted by the child using the pk of
///   its sibling for Diffie Hellman (DH).
/// * In case of a blank sibling, the encrypting child encrypts the secret for each of
///   the nodes in its sibling's resolution (which is the set of the highest non-blank
///   descendents of the sibling). This means a separate DH per node in that resolution.
///   These encryptions of the secret are stored in a map at the parent.
/// * In the case of a sibling with multiple public keys (because of a merge conflict),
///   the encrypter must use the nested encryption method for encrypting the new secret
///   for the parent. It does DH using the child's secret key with each of its sibling's
///   (sorted) public keys to create a nested encryption.
/// * * An encrypter will always have one public key because it overwrites conflicts on
///     its path as it ascends the tree.
/// * * A node with multiple public keys will also have multiple corresponding encrypted
///     secret keys. On decryption, any leaf with a conflict node on its path will need
///     all those secret keys to do the nested decryption of the conflict node's parent.
/// * * Encryption of a parent of a conflict node will always result in one public key
///     and one corresponding secret key for that parent.
/// * * When starting a decryption, you pass in your map of public keys to decrypted
///     secret keys. If you hit new public keys on the way up, you add the decrypted
///     secret keys to that map. This map allows you to always look up secret keys for
///     nested decryptions.
///
/// [Causal TreeKEM]: https://mattweidner.com/assets/pdf/acs-dissertation.pdf
/// [MLS]: https://messaginglayersecurity.rocks/
/// [TreeKEM]: https://inria.hal.science/hal-02425247/file/treekem+(1).pdf
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct BeeKem {
    doc_id: DocumentId,
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    inner_nodes: Vec<Option<InnerNode>>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<Identifier, LeafNodeIndex>,
    // The leaf node that was the source of the last path encryption, or None
    // if there is currently no root key.
    current_secret_encrypter_leaf_idx: Option<LeafNodeIndex>,
}

impl BeeKem {
    /// We assume members are added in causal order (a property guaranteed by
    /// Beehive as a whole).
    pub(crate) fn new(
        doc_id: DocumentId,
        members: Vec<(Identifier, ShareKey)>,
    ) -> Result<Self, CgkaError> {
        let mut tree = Self {
            doc_id,
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            inner_nodes: Vec::new(),
            tree_size: TreeSize::from_leaf_count(members.len() as u32),
            id_to_leaf_idx: BTreeMap::new(),
            current_secret_encrypter_leaf_idx: None,
        };
        tree.grow_tree_to_size();
        for (id, pk) in members {
            tree.push_leaf(id, pk)?;
        }
        Ok(tree)
    }

    pub(crate) fn node_key_for_id(&self, id: Identifier) -> Result<NodeKey, CgkaError> {
        let idx = self.leaf_index_for_id(id)?;
        self.node_key_for_index((*idx).into())
    }

    pub(crate) fn sort_leaves_and_blank_tree(&mut self) -> Result<(), CgkaError> {
        let mut flattened: Vec<&LeafNode> = self.leaves.iter().flatten().collect();
        flattened.sort_by(|a, b| a.id.cmp(&b.id));
        // TODO: We could choose to shrink the tree at this point if the leaf count
        // has reduced by more than half.
        self.leaves = flattened
            .iter()
            .map(|l| Some((*l).clone()))
            .collect::<Vec<Option<LeafNode>>>();
        self.id_to_leaf_idx.clear();
        for (idx, leaf) in self.leaves.iter().enumerate() {
            if let Some(l) = leaf {
                self.id_to_leaf_idx
                    .insert(l.id, LeafNodeIndex::new(idx as u32));
            }
        }
        self.inner_nodes = vec![None; self.inner_nodes.len()];
        self.grow_tree_to_size();
        self.current_secret_encrypter_leaf_idx = None;
        Ok(())
    }

    pub(crate) fn blank_leaf_and_path(&mut self, idx: LeafNodeIndex) -> Result<(), CgkaError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        self.leaves[idx.usize()] = None;
        self.blank_path(treemath::parent(idx.into()))?;
        self.current_secret_encrypter_leaf_idx = None;
        Ok(())
    }

    pub(crate) fn push_leaf(&mut self, id: Identifier, pk: ShareKey) -> Result<u32, CgkaError> {
        self.maybe_grow_tree(self.next_leaf_idx.u32());
        let l_idx = self.next_leaf_idx;
        self.next_leaf_idx += 1;
        self.insert_leaf_at(l_idx, id, NodeKey::ShareKey(pk))?;
        self.id_to_leaf_idx.insert(id, l_idx);
        self.blank_path(treemath::parent(l_idx.into()))?;
        self.current_secret_encrypter_leaf_idx = None;
        Ok(l_idx.u32())
    }

    pub(crate) fn remove_id(&mut self, id: Identifier) -> Result<Vec<ShareKey>, CgkaError> {
        if self.member_count() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }
        let l_idx = self.leaf_index_for_id(id)?;
        let mut removed_keys = Vec::new();
        for idx in treemath::direct_path((*l_idx).into(), self.tree_size) {
            if let Some(store) = self.inner_node(idx)? {
                removed_keys.append(&mut store.node_key().keys());
            }
        }
        self.blank_leaf_and_path(*l_idx)?;
        self.id_to_leaf_idx.remove(&id);
        self.current_secret_encrypter_leaf_idx = None;
        // TODO: Once we move past the naive "blank the tree and sort leaves"
        // approach to tree structure changes, we can consider optimizations like this.
        // // "Collect" any contiguous tombstones at the end of the leaves Vec
        // while self.leaf(self.next_leaf_idx - 1)?.is_none() {
        //     self.blank_path(treemath::parent((self.next_leaf_idx - 1).into()))?;
        //     self.next_leaf_idx -= 1;
        // }
        Ok(removed_keys)
    }

    pub(crate) fn member_count(&self) -> u32 {
        self.id_to_leaf_idx.len() as u32
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. along the
    /// leaf's path). As you look at each parent node along the way, if the node is not
    /// blank, look up your child idx in the parent's secret store. Derive Diffie Hellman
    /// shared keys using the public keys stored in the secret store and use those shared keys to
    /// decrypt the secret key stored there.
    ///
    /// Hold on to each idx you've seen along the way, since ancestors might have been
    /// encrypted for any of these descendents (in cases like a blank node or
    /// conflicting keys on a node on the path).
    pub(crate) fn decrypt_tree_secret(
        &self,
        owner_id: Identifier,
        owner_sks: &mut ShareKeyMap,
    ) -> Result<ShareSecretKey, CgkaError> {
        let leaf_idx = *self.leaf_index_for_id(owner_id)?;
        let leaf = self
            .leaf(leaf_idx)?
            .as_ref()
            .ok_or(CgkaError::OwnerIdentifierNotFound)?;
        if !self.has_root_key()? {
            return Err(CgkaError::NoRootKey);
        }
        if self.is_blank(leaf_idx.into())? {
            return Err(CgkaError::OwnerIdentifierNotFound);
        }
        if Some(leaf_idx) == self.current_secret_encrypter_leaf_idx {
            let NodeKey::ShareKey(pk) = leaf.pk else {
                return Err(CgkaError::ShareKeyNotFound);
            };
            let secret = owner_sks.get(&pk).ok_or(CgkaError::ShareKeyNotFound)?;
            return Ok(secret
                .ratchet_n_forward(treemath::direct_path(leaf_idx.into(), self.tree_size).len()));
        }

        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut seen_idxs = vec![child_idx];
        // We will return this at the end once we've decrypted the root secret.
        let mut last_secret_decrypted = None;
        let mut child_node_key = leaf.pk.clone();
        let mut parent_idx: TreeNodeIndex = treemath::parent(child_idx).into();
        while !self.is_root(child_idx) {
            // Find the next non-blank parent
            while self.is_blank(parent_idx)? {
                child_idx = parent_idx;
                parent_idx = treemath::parent(child_idx).into();
            }
            debug_assert!(!self.is_root(child_idx));
            last_secret_decrypted =
                self.decrypt_parent_key(child_idx, &child_node_key, &seen_idxs, owner_sks)?;
            if let Some(ref secret) = last_secret_decrypted {
                dbg!("Ho!");
                let lca_with_encrypter = treemath::lowest_common_ancestor(
                    leaf_idx,
                    self.current_secret_encrypter_leaf_idx
                        .ok_or(CgkaError::CurrentEncrypterNotFound)?,
                );
                if parent_idx == TreeNodeIndex::Inner(lca_with_encrypter) {
                    return Ok(secret.ratchet_n_forward(
                        treemath::direct_path(parent_idx, self.tree_size).len(),
                    ));
                }

            }
            seen_idxs.push(parent_idx);
            child_node_key = self.node_key_for_index(parent_idx)?;
            child_idx = parent_idx;
            parent_idx = treemath::parent(child_idx).into();
        }
        last_secret_decrypted.ok_or(CgkaError::NoRootKey)
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. along the
    /// leaf's path). As you look at each parent node along the way, you need to populate
    /// it with a public key and a map from sibling subtree public keys to a newly generated
    /// secret key encrypted pairwise with each node in the sibling resolution (in the
    /// ideal case, this will just be the sibling node itself, but if the sibling is
    /// blank it can be many nodes).
    ///
    /// If the sibling node's resolution is empty, then you will generate the new key
    /// pair but encrypt the secret by doing Diffie Hellman with a different key pair
    /// generated just for that purpose. The secret store for that parent will then
    /// only have an entry for you.
    ///
    /// If one or more members of your sibling's resolution have conflicting public keys,
    /// then you will do a nested encryption of the secret using all of the conflicting
    /// public keys ordered lexicographically.
    pub(crate) fn encrypt_path(
        &mut self,
        id: Identifier,
        pk: ShareKey,
        sks: &mut ShareKeyMap,
    ) -> Result<Option<PathChange>, CgkaError> {
        if !self.id_to_leaf_idx.contains_key(&id) {
            return Ok(None);
        }
        let leaf_idx = *self.leaf_index_for_id(id)?;
        if self.id_for_leaf(leaf_idx)? != id {
            return Err(CgkaError::IdentifierNotFound);
        }

        let mut new_path = PathChange {
            leaf_id: id,
            leaf_idx: leaf_idx.u32(),
            leaf_pk: NodeKey::ShareKey(pk),
            path: Vec::new(),
            removed_keys: self.node_key_for_id(id)?.keys(),
        };
        self.insert_leaf_at(leaf_idx, id, NodeKey::ShareKey(pk))?;
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        // An encrypter will always have a single public key at each node as it
        // encrypts up its path. At its leaf, it will have written the latest public
        // key in the past. And as it moves up the path, it will generate a new public
        // key for each ancestor up to the root.
        let mut child_pk = pk;
        let mut child_sk = *sks.get(&pk).ok_or(CgkaError::SecretKeyNotFound)?;
        let mut parent_idx = treemath::parent(child_idx);
        while !self.is_root(child_idx) {
            if let Some(store) = self.inner_node(parent_idx)? {
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
            )?;
            // Add to our ShareKeyMap so we won't have to decrypt in the future
            sks.insert(new_parent_pk, new_parent_sk);
            new_path.path.push((
                parent_idx.u32(),
                self.inner_node(parent_idx)?
                    .as_ref()
                    .ok_or(CgkaError::ShareKeyNotFound)?
                    .clone(),
            ));
            child_idx = parent_idx.into();
            child_pk = new_parent_pk;
            child_sk = new_parent_sk;
            parent_idx = treemath::parent(child_idx);
        }
        self.current_secret_encrypter_leaf_idx = Some(leaf_idx);
        Ok(Some(new_path))
    }

    /// Applies a PathChange representing new public and encrypted secret keys for each
    /// node on a path.
    pub(crate) fn apply_path(&mut self, new_path: &PathChange) -> Result<(), CgkaError> {
        let leaf_idx = *self.leaf_index_for_id(new_path.leaf_id)?;
        if !self.is_valid_change(new_path)? {
            // A structural change has occurred so we can't apply the whole path.
            let new_node_key = if let Some(leaf) = self.leaf(leaf_idx)? {
                leaf.pk.merge(&new_path.leaf_pk, &new_path.removed_keys)
            } else {
                new_path.leaf_pk.clone()
            };
            self.insert_leaf_at(leaf_idx, new_path.leaf_id, new_node_key)?;
            return Ok(());
        }

        let old_leaf = self.leaf(leaf_idx)?.as_ref().unwrap();
        let new_leaf_pk = new_path.leaf_pk.clone();
        self.insert_leaf_at(
            leaf_idx,
            new_path.leaf_id,
            old_leaf.pk.merge(&new_leaf_pk, &new_path.removed_keys),
        )?;

        for (idx, node) in &new_path.path {
            let current_idx = InnerNodeIndex::new(*idx);
            if let Some(current_node) = self.inner_node_mut(current_idx)? {
                current_node.merge(node, &new_path.removed_keys)?;
            } else {
                self.insert_inner_node_at(current_idx, node.clone())?;
            }
        }
        if self.has_root_key()? {
            self.current_secret_encrypter_leaf_idx = Some(leaf_idx);
        } else {
            self.current_secret_encrypter_leaf_idx = None;
        }
        Ok(())
    }

    pub(crate) fn has_root_key(&self) -> Result<bool, CgkaError> {
        let root_idx: TreeNodeIndex = treemath::root(self.tree_size);
        let TreeNodeIndex::Inner(p_idx) = root_idx else {
            return Err(CgkaError::TreeIndexOutOfBounds);
        };
        Ok(if let Some(r) = self.inner_node(p_idx)? {
            // A root with a public key conflict does not have a decryption secret
            !r.has_conflict()
        } else {
            false
        })
    }

    /// Returns the secret if there is a single parent public key.
    /// In either case, adds the public key/decrypted secret key pair/s to the
    /// secret key map.
    fn decrypt_parent_key(
        &self,
        child_idx: TreeNodeIndex,
        child_node_key: &NodeKey,
        seen_idxs: &[TreeNodeIndex],
        child_sks: &mut ShareKeyMap,
    ) -> Result<Option<ShareSecretKey>, CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        debug_assert!(!self.is_blank(parent_idx.into())?);
        let parent = self
            .inner_node(parent_idx)?
            .as_ref()
            .ok_or(CgkaError::TreeIndexOutOfBounds)?;

        let maybe_secret = match parent.node_key() {
            NodeKey::ConflictKeys(_) => {
                // If we haven't decrypted all secrets for a conflict node, we need to do
                // that before continuing.
                parent.decrypt_undecrypted_secrets(child_node_key, child_sks, seen_idxs)?;
                None
            }
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

    fn encrypt_key_for_parent(
        &mut self,
        child_idx: TreeNodeIndex,
        child_pk: ShareKey,
        child_sk: &ShareSecretKey,
        new_parent_pk: ShareKey,
        new_parent_sk: &ShareSecretKey,
    ) -> Result<(), CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        let secret_store = self.encrypt_new_secret_store_for_parent(
            child_idx,
            child_pk,
            child_sk,
            new_parent_pk,
            new_parent_sk,
        )?;
        self.insert_inner_node_at(parent_idx, secret_store)?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn encrypt_new_secret_store_for_parent(
        &self,
        child_idx: TreeNodeIndex,
        child_pk: ShareKey,
        child_sk: &ShareSecretKey,
        new_parent_pk: ShareKey,
        new_parent_sk: &ShareSecretKey,
    ) -> Result<SecretStore, CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let sibling_idx = treemath::sibling(child_idx);
        let mut secret_map = BTreeMap::new();
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you generate a key pair
            // just to do DH with when ecrypting the new parent secret.
            let paired_sk = ShareSecretKey::generate();
            let paired_pk = paired_sk.share_key();
            let encrypted_sk = NestedEncrypted::<ShareSecretKey>::try_encrypt(
                self.doc_id,
                new_parent_sk,
                child_sk,
                &nonempty![paired_pk],
            )
            .map_err(CgkaError::Encryption)?;

            secret_map.insert(child_idx, encrypted_sk);
        } else {
            // Encrypt the secret for every node in the sibling resolution, using
            // a new DH shared secret to do the encryption for each node. If a node in
            // the resolution has conflicting public keys, you must do a nested encryption
            // for that node.
            let mut used_paired_sibling = false;
            for idx in sibling_resolution {
                let sibling_node_key = self.node_key_for_index(idx)?;
                let encrypted_sk = NestedEncrypted::<ShareSecretKey>::try_encrypt(
                    self.doc_id,
                    new_parent_sk,
                    child_sk,
                    &NonEmpty::from_vec(sibling_node_key.keys()).expect("some keys to exist"),
                )
                .map_err(CgkaError::Encryption)?;

                if !used_paired_sibling {
                    secret_map.insert(child_idx, encrypted_sk.clone());
                    used_paired_sibling = true;
                }
                secret_map.insert(idx, encrypted_sk);
            }
        };

        Ok(SecretStore::new(
            new_parent_pk,
            child_pk,
            secret_map,
        ))
    }

    fn node_key_for_index(&self, idx: TreeNodeIndex) -> Result<NodeKey, CgkaError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self
                .leaf(l_idx)?
                .as_ref()
                .ok_or(CgkaError::ShareKeyNotFound)?
                .pk
                .clone(),
            TreeNodeIndex::Inner(i_idx) => self
                .inner_node(i_idx)?
                .as_ref()
                .ok_or(CgkaError::ShareKeyNotFound)?
                .node_key(),
        })
    }

    fn leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CgkaError> {
        self.leaves
            .get(idx.usize())
            .ok_or(CgkaError::TreeIndexOutOfBounds)
    }

    fn leaf_index_for_id(&self, id: Identifier) -> Result<&LeafNodeIndex, CgkaError> {
        self.id_to_leaf_idx
            .get(&id)
            .ok_or(CgkaError::IdentifierNotFound)
    }

    fn id_for_leaf(&self, idx: LeafNodeIndex) -> Result<Identifier, CgkaError> {
        Ok(self
            .leaf(idx)?
            .as_ref()
            .ok_or(CgkaError::IdentifierNotFound)?
            .id)
    }

    fn inner_node(&self, idx: InnerNodeIndex) -> Result<&Option<InnerNode>, CgkaError> {
        self.inner_nodes
            .get(idx.usize())
            .ok_or(CgkaError::TreeIndexOutOfBounds)
    }

    fn inner_node_mut(&mut self, idx: InnerNodeIndex) -> Result<&mut Option<InnerNode>, CgkaError> {
        self.inner_nodes
            .get_mut(idx.usize())
            .ok_or(CgkaError::TreeIndexOutOfBounds)
    }

    fn insert_leaf_at(
        &mut self,
        idx: LeafNodeIndex,
        id: Identifier,
        pk: NodeKey,
    ) -> Result<(), CgkaError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        let leaf = LeafNode { id, pk };
        self.leaves[idx.usize()] = Some(leaf);
        Ok(())
    }

    fn insert_inner_node_at(
        &mut self,
        idx: InnerNodeIndex,
        secret_store: SecretStore,
    ) -> Result<(), CgkaError> {
        if idx.usize() >= self.inner_nodes.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        self.inner_nodes[idx.usize()] = Some(secret_store);
        Ok(())
    }

    fn is_blank(&self, idx: TreeNodeIndex) -> Result<bool, CgkaError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self.leaf(l_idx)?.is_none(),
            TreeNodeIndex::Inner(p_idx) => self.inner_node(p_idx)?.is_none(),
        })
    }

    fn blank_path(&mut self, idx: InnerNodeIndex) -> Result<(), CgkaError> {
        self.blank_parent(idx)?;
        if self.is_root(idx.into()) {
            return Ok(());
        }
        self.blank_path(treemath::parent(idx.into()))
    }

    fn blank_parent(&mut self, idx: InnerNodeIndex) -> Result<(), CgkaError> {
        if idx.usize() >= self.inner_nodes.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        self.inner_nodes[idx.usize()] = None;
        Ok(())
    }

    fn is_valid_change(&self, new_path: &PathChange) -> Result<bool, CgkaError> {
        let leaf_idx = self.leaf_index_for_id(new_path.leaf_id)?;
        Ok(
            new_path.path.len() == self.path_length_for(LeafNodeIndex::new(new_path.leaf_idx))
                && leaf_idx.u32() == new_path.leaf_idx,
        )
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

    /// Highest non-blank descendants of a node
    fn append_resolution(
        &self,
        idx: TreeNodeIndex,
        acc: &mut Vec<TreeNodeIndex>,
    ) -> Result<(), CgkaError> {
        match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                if self.leaf(l_idx)?.is_some() {
                    acc.push(l_idx.into());
                }
            }
            TreeNodeIndex::Inner(p_idx) => {
                if self.inner_node(p_idx)?.is_some() {
                    acc.push(p_idx.into());
                } else {
                    let left_idx = treemath::left(p_idx);
                    self.append_resolution(left_idx, acc)?;
                    let right_idx = treemath::right(p_idx);
                    self.append_resolution(right_idx, acc)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LeafNode {
    pub id: Identifier,
    pub pk: NodeKey,
}
