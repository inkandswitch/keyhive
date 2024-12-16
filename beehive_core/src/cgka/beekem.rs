use super::{
    error::CgkaError,
    keys::{NodeKey, ShareKeyMap},
    secret_store::SecretStore,
    tombstone::CgkaTombstoneId,
    treemath,
};
use crate::{
    crypto::{
        application_secret::PcsKey,
        encrypted::NestedEncrypted,
        share_key::{ShareKey, ShareSecretKey},
    },
    principal::{document::id::DocumentId, individual::id::IndividualId},
};
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use treemath::{InnerNodeIndex, LeafNodeIndex, TreeNodeIndex, TreeSize};

/// A PathChange represents an update along a path from a leaf to the root.
/// This includes both the new public keys for each node and the keys that have
/// been removed as part of this change.
// FIXME
// #[derive(Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct PathChange {
    pub leaf_id: IndividualId,
    pub leaf_idx: u32,
    pub leaf_pk: NodeKey,
    // (u32 inner node index, new inner node)
    pub path: Vec<(u32, SecretStore)>,
    pub removed_keys: Vec<ShareKey>,
    pub removed_tombstones: Vec<CgkaTombstoneId>,
}

// FIXME
// impl fmt::Debug for PathChange {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_struct("PathChange")
//          .field("leaf_id", &self.leaf_id)
//          .field("leaf_idx", &self.leaf_idx)
//          .field("leaf_pk", &self.leaf_pk)
//          .field("removed_keys", &self.removed_keys)
//          .field("removed_tombstones", &self.removed_tombstones)
//          .finish()
//     }
// }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BeeKem {
    doc_id: DocumentId,
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    inner_nodes: Vec<InnerNode>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<IndividualId, LeafNodeIndex>,
    // FIXME Remove or use method
    pub has_structural_change: bool,
    // The leaf node that was the source of the last path encryption, or None
    // if there is currently no root key.
    current_secret_encrypter_leaf_idx: Option<LeafNodeIndex>,
}

impl BeeKem {
    /// We assume members are added in causal order (a property guaranteed by
    /// Beehive as a whole).
    pub(crate) fn new(
        doc_id: DocumentId,
        initial_member_id: IndividualId,
        initial_member_pk: ShareKey,
    ) -> Result<Self, CgkaError> {
        let mut tree = Self {
            doc_id,
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            inner_nodes: vec![Default::default()],
            tree_size: TreeSize::from_leaf_count(1),
            id_to_leaf_idx: BTreeMap::new(),
            has_structural_change: false,
            current_secret_encrypter_leaf_idx: None,
        };
        tree.resize_tree();
        tree.push_leaf(initial_member_id, initial_member_pk)?;
        Ok(tree)
    }

    pub(crate) fn contains_id(&self, id: IndividualId) -> bool {
        self.id_to_leaf_idx.contains_key(&id)
    }

    pub(crate) fn node_key_for_id(&self, id: IndividualId) -> Result<NodeKey, CgkaError> {
        let idx = self.leaf_index_for_id(id)?;
        self.node_key_for_index((*idx).into())
    }

    pub(crate) fn sort_leaves_and_blank_tree(
        &mut self,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<(), CgkaError> {
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
        let root_tombstones = self.root_tombstones().clone();
        for node in &mut self.inner_nodes {
            // FIXME
            // node.clear_secret_store();
            node.clear_tombstones();
            node.add_tombstone(tombstone_id);
        }
        self.root_mut()
            .expect("tree to have root")
            .clear_associated_tombstones();
        self.grow_tree_to_size(root_tombstones);
        self.current_secret_encrypter_leaf_idx = None;
        self.has_structural_change = true;
        Ok(())
    }

    pub(crate) fn blank_leaf_and_path(
        &mut self,
        idx: LeafNodeIndex,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<(), CgkaError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        self.leaves[idx.usize()] = None;
        self.blank_path(treemath::parent(idx.into()), tombstone_id)?;
        Ok(())
    }

    // FIXME
    fn root_tombstones(&self) -> RootTombstones {
        match treemath::root(self.tree_size) {
            TreeNodeIndex::Inner(idx) => {
                let root = self.inner_node(idx).expect("root to exist");
                RootTombstones::new(
                    root.tombstones().clone(),
                    root.associated_tombstones().clone(),
                )
            }
            _ => panic!("root should be an inner node"),
        }
    }

    // TODO: If id already exists, add ShareKey to node key for that id's leaf
    pub(crate) fn add_leaf(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<u32, CgkaError> {
        println!(
            "-- PRE add_leaf root tombstones: {:?}",
            self.root_tombstones()
        );
        println!("add_leaf and placing tombstone id {:?}", tombstone_id);
        let l_idx = self.push_leaf(id, pk)?;
        println!(
            "-- -- add_leaf: After push_leaf root tombstones: {:?}",
            self.root_tombstones()
        );
        self.blank_path(treemath::parent(l_idx.into()), tombstone_id)?;
        println!(
            "-- post add_leaf root tombstones: {:?}",
            self.root_tombstones()
        );
        Ok(l_idx.u32())
    }

    fn push_leaf(&mut self, id: IndividualId, pk: ShareKey) -> Result<LeafNodeIndex, CgkaError> {
        self.maybe_grow_tree(self.next_leaf_idx.u32());
        let l_idx = self.next_leaf_idx;
        self.next_leaf_idx += 1;
        self.insert_leaf_at(l_idx, id, NodeKey::ShareKey(pk))?;
        println!(
            "push_leaf(): Adding id to leaf: ID {:?}, treesize: {:?}, member count: {:?}",
            id,
            self.tree_size,
            self.member_count()
        );
        self.id_to_leaf_idx.insert(id, l_idx);
        Ok(l_idx)
    }

    pub(crate) fn remove_id(
        &mut self,
        id: IndividualId,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<Vec<ShareKey>, CgkaError> {
        if self.member_count() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }
        let l_idx = self.leaf_index_for_id(id)?;
        let mut removed_keys = Vec::new();
        for idx in treemath::direct_path((*l_idx).into(), self.tree_size) {
            let store = self.inner_node(idx)?;
            if let Some(node_key) = store.node_key() {
                removed_keys.append(&mut node_key.keys());
            }
        }
        self.blank_leaf_and_path(*l_idx, tombstone_id)?;
        self.id_to_leaf_idx.remove(&id);
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
        owner_id: IndividualId,
        owner_sks: &mut ShareKeyMap,
    ) -> Result<ShareSecretKey, CgkaError> {
        if !self.has_root_key() {
            return Err(CgkaError::NoRootKey);
        }
        let leaf_idx = *self.leaf_index_for_id(owner_id)?;
        println!(
            "++decrypt_tree_secret (starting from {:?}). Encrypter was {:?}",
            leaf_idx, self.current_secret_encrypter_leaf_idx
        );
        let leaf = self
            .leaf(leaf_idx)?
            .as_ref()
            .ok_or(CgkaError::OwnerIdentifierNotFound)?;

        // println!("--decrypt_tree_secret 2");
        if self.is_blank(leaf_idx.into())? {
            return Err(CgkaError::OwnerIdentifierNotFound);
        }
        if Some(leaf_idx) == self.current_secret_encrypter_leaf_idx {
            println!(
                "-- We're the current encrypter. decrypt_tree_secret looking up leaf ShareKey"
            );
            let NodeKey::ShareKey(pk) = leaf.pk else {
                return Err(CgkaError::ShareKeyNotFound);
            };
            println!("-- decrypt_tree_secret looking pk in owner_sks");
            let secret = owner_sks.get(&pk).ok_or(CgkaError::ShareKeyNotFound)?;
            return Ok(secret
                .ratchet_n_forward(treemath::direct_path(leaf_idx.into(), self.tree_size).len()));
        }

        // println!("--decrypt_tree_secret 3");
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut seen_idxs = vec![child_idx];
        // We will return this at the end once we've decrypted the root secret.
        let mut last_secret_decrypted = None;
        let mut child_node_key = leaf.pk.clone();
        let mut parent_idx: TreeNodeIndex = treemath::parent(child_idx).into();
        // println!("--decrypt_tree_secret 4");

        // FIXME
        let mut temp_parent_idx = parent_idx.clone();
        println!("-- ~~ NODES IN PATH");
        // FIXME
        while !self.is_root(temp_parent_idx) {
            if let TreeNodeIndex::Inner(pidx) = temp_parent_idx {
                let node = self.inner_node(pidx)?;
                println!(
                    "-- ~~ -- {:?}, has_keys: {:?}, conflict_keys: {:?}, tombstones: {:?}",
                    pidx,
                    node.has_keys(),
                    node.has_conflict(),
                    node.tombstones()
                );
            }
            temp_parent_idx = treemath::parent(temp_parent_idx).into();
        }
        // FIXME
        if let TreeNodeIndex::Inner(pidx) = temp_parent_idx {
            let root = self.root()?;
            println!(
                "-- ~~ -- ROOT: {:?}, has_keys: {:?}, conflict_keys: {:?}, tombstones: {:?}",
                pidx,
                root.has_keys(),
                root.has_conflict(),
                root.tombstones()
            );
        }

        println!("\n\nALL NODES:");
        // FIXME
        self.print_nodes();

        while !self.is_root(child_idx) {
            // Find the next non-blank parent
            while self.is_blank(parent_idx)? {
                // println!("\n is_blank parent_idx: {:?}, tree_size: {:?}", parent_idx, self.tree_size);
                child_idx = parent_idx;
                parent_idx = treemath::parent(child_idx).into();
            }
            // println!("\n check is root for idx: {:?}, tree_size: {:?}", child_idx, self.tree_size);
            debug_assert!(!self.is_root(child_idx));
            // println!("--decrypt_tree_secret 4a");
            last_secret_decrypted =
                self.decrypt_parent_key(child_idx, &child_node_key, &seen_idxs, owner_sks)?;
            if let Some(ref secret) = last_secret_decrypted {
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
            // println!("--decrypt_tree_secret 4b");
            seen_idxs.push(parent_idx);
            child_node_key = self.node_key_for_index(parent_idx)?;
            child_idx = parent_idx;
            parent_idx = treemath::parent(child_idx).into();
        }
        // println!("--decrypt_tree_secret 5");
        last_secret_decrypted.ok_or(CgkaError::NoRootKey)
    }

    // FIXME: REmove
    pub(crate) fn print_nodes(&self) {
        for (idx, node) in self.leaves.iter().enumerate() {
            if idx > 7 {
                continue;
            }
            println!("-- ~~ -- Leaf idx {:?}\nLeafNode: {:?}", idx, node);
            println!("-----------------------");
        }
        // FIXME
        for (idx, node) in self.inner_nodes.iter().enumerate() {
            if idx > 7 {
                continue;
            }
            println!("-- ~~ -- inner idx {:?}, has_keys: {:?}, conflict_keys: {:?}, tombstones: {:?}\nSecret store: {:?}", idx, node.has_keys(), node.has_conflict(), node.tombstones(), node.secret_store());
            println!("-----------------------");
        }
        println!("\n\n");
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
    pub(crate) fn encrypt_path<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        sks: &mut ShareKeyMap,
        tombstone_id: CgkaTombstoneId,
        csprng: &mut R,
    ) -> Result<Option<(PcsKey, PathChange)>, CgkaError> {
        // FIXME
        let root = self.root_mut()?;
        println!("\nROOT NODE for update: {:?}", root);

        println!(
            "encrypt_path 1, treesize: {:?}, member count: {:?}",
            self.tree_size,
            self.member_count()
        );
        if !self.id_to_leaf_idx.contains_key(&id) {
            println!("Couldn't find id at leaf: ID {:?}", id);
            return Ok(None);
        }
        let mut removed_tombstones = HashSet::new();
        let leaf_idx = *self.leaf_index_for_id(id)?;
        if self.id_for_leaf(leaf_idx)? != id {
            return Err(CgkaError::IdentifierNotFound);
        }
        self.insert_leaf_at(leaf_idx, id, NodeKey::ShareKey(pk))?;
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut new_path = PathChange {
            leaf_id: id,
            leaf_idx: leaf_idx.u32(),
            leaf_pk: NodeKey::ShareKey(pk),
            path: Default::default(),
            removed_keys: self.node_key_for_id(id)?.keys(),
            removed_tombstones: Default::default(),
        };

        // An encrypter will always have a single public key at each node as it
        // encrypts up its path. At its leaf, it will have written the latest public
        // key in the past. And as it moves up the path, it will generate a new public
        // key for each ancestor up to the root.
        let mut child_pk = pk;
        println!("\n\n\n\nencrypt_path lookup secret key");
        let mut child_sk = *sks.get(&pk).ok_or(CgkaError::SecretKeyNotFound)?;
        let mut parent_idx = treemath::parent(child_idx);
        while !self.is_root(child_idx) {
            let store = self.inner_node(parent_idx)?;
            if let Some(node_key) = store.node_key() {
                new_path.removed_keys.append(&mut node_key.keys());
            }
            println!(
                "-- Adding to removed_tombstones set: {:?}",
                store.tombstones()
            );
            removed_tombstones.extend(store.tombstones().clone());
            removed_tombstones.extend(store.associated_tombstones().clone());
            let new_parent_sk = child_sk.ratchet_forward();
            let new_parent_pk = new_parent_sk.share_key();
            self.encrypt_key_for_parent(
                csprng,
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
                self.inner_node(parent_idx)?.secret_store().clone(),
            ));
            child_idx = parent_idx.into();
            child_pk = new_parent_pk;
            child_sk = new_parent_sk;
            parent_idx = treemath::parent(child_idx);
        }
        let root = self.root_mut()?;
        println!("\nROOT NODE after update: {:?}", root);
        println!(
            "Extending removed tombstones by root assoc: {:?}",
            root.associated_tombstones()
        );
        removed_tombstones.extend(root.associated_tombstones().clone());
        new_path.removed_tombstones = Vec::from_iter(removed_tombstones.iter().cloned());
        root.clear_associated_tombstones();
        root.add_associated_tombstone(tombstone_id);
        self.current_secret_encrypter_leaf_idx = Some(leaf_idx);
        // FIXME: Bring this back
        // let pcs_key = (leaf_sk.ratchet_n_forward(self.path_length_for(leaf_idx))).into();
        println!("IN encrypt_path ABOUT TO CALL derive_tree_secret()");
        let pcs_key = self.decrypt_tree_secret(id, sks)?.into();
        println!(
            "post encrypt_path root tombstones: {:?}",
            self.root_tombstones()
        );
        Ok(Some((pcs_key, new_path)))
    }

    /// Applies a PathChange representing new public and encrypted secret keys for each
    /// node on a path.
    pub(crate) fn apply_path(
        &mut self,
        new_path: &PathChange,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<(), CgkaError> {
        println!(
            "-- PRE apply_path root tombstones: {:?}",
            self.root_tombstones()
        );

        println!("\n\nALL NODES BEFORE APPLYING PATH:");
        // FIXME
        self.print_nodes();

        // println!("apply_path 1");
        let leaf_idx = *self.leaf_index_for_id(new_path.leaf_id)?;
        if !self.is_valid_change(new_path)? { // FIXME REMOVE: || self.has_structural_change {
            println!("-- -- apply_path but NOT VALID CHANGE");
            // A structural change has occurred so we can't apply the whole path.
            let new_node_key = if let Some(leaf) = self.leaf(leaf_idx)? {
                leaf.pk.merge(&new_path.leaf_pk, &new_path.removed_keys)
            } else {
                new_path.leaf_pk.clone()
            };
            self.insert_leaf_at(leaf_idx, new_path.leaf_id, new_node_key)?;
            let parent_idx = treemath::parent(leaf_idx.into());
            self.remove_tombstones_from_path(
                parent_idx,
                &HashSet::from_iter(new_path.removed_tombstones.iter().copied()),
            )?;
            self.blank_path(parent_idx, tombstone_id)?;
            return Ok(());
        }

        // println!("apply_path 2");
        let old_leaf = self.leaf(leaf_idx)?.as_ref().unwrap();
        let new_leaf_pk = new_path.leaf_pk.clone();
        // println!("apply_path 3");
        self.insert_leaf_at(
            leaf_idx,
            new_path.leaf_id,
            old_leaf.pk.merge(&new_leaf_pk, &new_path.removed_keys),
        )?;

        let removed_tombstones = HashSet::from_iter(new_path.removed_tombstones.iter().copied());
        println!(
            "apply_path: tombstones to remove: {:?}",
            removed_tombstones.iter().map(|t| t).collect::<Vec<_>>()
        );
        println!(
            "apply_path: keys to remove: {:?}",
            new_path.removed_keys.iter().map(|t| t).collect::<Vec<_>>()
        );
        for (node_idx, node) in new_path.path.iter() {
            println!("-- apply_path, next node: InnerNodeIndex({node_idx})");
            let current_idx = InnerNodeIndex::new(*node_idx);

            // // FIXME: Check that keys in Secret Store still exist
            // // If not, we blank the rest of the path.
            // // DO we actually want to do this?
            // let (contributors, contributor_leaves) = node.encryption_contributors();
            // for (idx, node_key) in contributors {
            //     println!("-- -- Next contributor index: {:?}", idx);
            //     let mut blank_and_return = false;
            //     match idx {
            //         TreeNodeIndex::Inner(iidx) => {
            //             println!("-- -- PathChange node key: {:?}", node_key);
            //             println!(
            //                 "-- -- Our curr node key: {:?}",
            //                 self.inner_node(iidx)?.node_key()
            //             );
            //             if !self.contains_node_key(idx, &node_key)? {
            //                 println!("-- -- apply_path WE HIT A MISSING NODE KEY for {:?}", idx);
            //                 blank_and_return = true;
            //             }
            //         }
            //         TreeNodeIndex::Leaf(lidx) => {
            //             if let Some(leaf) = self.leaf(lidx)? {
            //                 println!(
            //                     "-- -- leaf.id: {:?}, contirbutor_leaves.leaf.id: {:?}",
            //                     leaf.id,
            //                     contributor_leaves.get(&lidx).expect("leaf to be present")
            //                 );
            //                 blank_and_return = leaf.id
            //                     != *contributor_leaves.get(&lidx).expect("leaf to be present");
            //                 if blank_and_return {
            //                     println!("-- -- apply_path but THE LEAF ID FOR IDX {:?} WAS NOT THE ORIGINAL. Orig {:?} != Cur {:?} ", lidx, contributor_leaves.get(&lidx).expect("leaf to be present"), leaf.id);
            //                 }
            //             } else {
            //                 println!("-- -- apply_path but THE LEAF FOR IDX {:?} WAS BLANK", lidx);
            //                 blank_and_return = true;
            //             }
            //         }
            //     }
            //     if blank_and_return {
            //         self.remove_tombstones_from_path(
            //             current_idx,
            //             &HashSet::from_iter(new_path.removed_tombstones.iter().copied()),
            //         )?;
            //         self.blank_path(current_idx, tombstone_id)?;
            //         return Ok(());
            //     }
            // }

            self.inner_node_mut(current_idx)?.merge(
                node,
                &new_path.removed_keys,
                &removed_tombstones,
            )?;
            // println!("\n__--__Merged inner node idx {node_idx} is now: {:?}", self.inner_node(current_idx)?);
            // println!("----- -- ^^ node tombstones: {:?}", self.inner_node(current_idx)?.tombstones().iter().map(|t| t).collect::<Vec<_>>())
        }

        self.root_mut()?.add_associated_tombstone(tombstone_id);
        println!(
            "post apply_path root tombstones: {:?}",
            self.root_tombstones()
        );
        if self.has_root_key() {
            self.current_secret_encrypter_leaf_idx = Some(leaf_idx);
        } else {
            self.current_secret_encrypter_leaf_idx = None;
        }

        println!("\n\nALL NODES AFTER APPLYING PATH:");
        // FIXME
        self.print_nodes();

        Ok(())
    }

    pub(crate) fn has_root_key(&self) -> bool {
        let TreeNodeIndex::Inner(r_idx) = treemath::root(self.tree_size) else {
            panic!("BeeKEM should always have a root node.")
        };
        self.inner_node(r_idx)
            .expect("root node index to be in tree")
            .has_single_key()
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
        let parent = self.inner_node(parent_idx)?;
        println!("-- decrypt_parent_key: looking up parent node_key");
        let Some(parent_node_key) = parent.node_key() else {
            return Err(CgkaError::ShareKeyNotFound);
        };

        let maybe_secret = match parent_node_key {
            NodeKey::ConflictKeys(_) => {
                println!("-- calling decrypt_undecrypted_secrets on {:?}", parent_idx);
                // If we haven't decrypted all secrets for a conflict node, we need to do
                // that before continuing.
                parent.decrypt_undecrypted_secrets(child_node_key, child_sks, seen_idxs)?;
                None
            }
            NodeKey::ShareKey(parent_pk) => {
                if child_sks.contains_key(&parent_pk) {
                    return Ok(child_sks.get(&parent_pk).cloned());
                }
                println!("\n-- about to decrypt_secret for {:?}. Member count: {:?}, Tree size: {:?}, Root node tombstones: {:?}", parent_idx, self.member_count(), self.tree_size, self.root()?.tombstones());
                // FIXME
                if let TreeNodeIndex::Inner(cidx) = child_idx {
                    println!(
                        "\n-- -- child node tombstones: {:?}",
                        self.inner_node(cidx)?.tombstones()
                    );
                }
                let secret = parent.decrypt_secret(child_node_key, child_sks, seen_idxs)?;
                child_sks.insert(parent_pk, secret);
                Some(secret)
            }
        };
        Ok(maybe_secret)
    }

    fn encrypt_key_for_parent<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
        child_idx: TreeNodeIndex,
        child_pk: ShareKey,
        child_sk: &ShareSecretKey,
        new_parent_pk: ShareKey,
        new_parent_sk: &ShareSecretKey,
    ) -> Result<(), CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        let secret_store = self.encrypt_new_secret_store_for_parent(
            csprng,
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
    fn encrypt_new_secret_store_for_parent<R: rand::CryptoRng + rand::RngCore>(
        &self,
        csprng: &mut R,
        child_idx: TreeNodeIndex,
        child_pk: ShareKey,
        child_sk: &ShareSecretKey,
        new_parent_pk: ShareKey,
        new_parent_sk: &ShareSecretKey,
    ) -> Result<SecretStore, CgkaError> {
        debug_assert!(!self.is_root(child_idx));
        let sibling_idx = treemath::sibling(child_idx);
        let mut secret_map = BTreeMap::new();
        // FIXME
        // let mut encrypter_sk = None;
        let mut leaf_map = BTreeMap::new();
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you generate a key pair
            // just to do DH with when ecrypting the new parent secret.
            let paired_sk = ShareSecretKey::generate(csprng);
            let paired_pk = paired_sk.share_key();
            let encrypted_sk = NestedEncrypted::<ShareSecretKey>::try_encrypt(
                self.doc_id,
                new_parent_sk,
                child_sk,
                &nonempty![paired_pk],
            )
            .map_err(CgkaError::Encryption)?;

            println!("-- FAKING A PK: {:?} for child {:?}", paired_pk, child_idx);
            secret_map.insert(child_idx, encrypted_sk);
            // FIXME
            // encrypter_sk = Some(encrypted_sk);
            if let TreeNodeIndex::Leaf(lidx) = child_idx {
                leaf_map.insert(lidx, self.leaf(lidx)?.clone().expect("leaf to exist").id);
            }
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
                    // FIXME
                    // encrypter_sk = Some(encrypted_sk.clone());
                    if let TreeNodeIndex::Leaf(lidx) = child_idx {
                        leaf_map.insert(lidx, self.leaf(lidx)?.clone().expect("leaf to exist").id);
                    }
                    used_paired_sibling = true;
                }
                secret_map.insert(idx, encrypted_sk);
                if let TreeNodeIndex::Leaf(l_idx) = idx {
                    leaf_map.insert(l_idx, self.leaf(l_idx)?.clone().expect("leaf to exist").id);
                }
            }
        };

        Ok(SecretStore::from_keys(
            new_parent_pk,
            child_pk,
            // FIXME
            // encrypter_sk,
            secret_map,
            leaf_map,
        ))
    }

    fn node_key_for_index(&self, idx: TreeNodeIndex) -> Result<NodeKey, CgkaError> {
        println!("-- node_key_for_index");
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self
                .leaf(l_idx)?
                .as_ref()
                .ok_or(CgkaError::ShareKeyNotFound)?
                .pk
                .clone(),
            TreeNodeIndex::Inner(i_idx) => self
                .inner_node(i_idx)?
                .node_key()
                .ok_or(CgkaError::ShareKeyNotFound)?,
        })
    }

    fn leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CgkaError> {
        // println!("leaf()");
        self.leaves
            .get(idx.usize())
            .ok_or(CgkaError::TreeIndexOutOfBounds)
    }

    pub(crate) fn leaf_index_for_id(&self, id: IndividualId) -> Result<&LeafNodeIndex, CgkaError> {
        // println!("leaf_index_for_id");
        self.id_to_leaf_idx
            .get(&id)
            .ok_or(CgkaError::IdentifierNotFound)
    }

    fn id_for_leaf(&self, idx: LeafNodeIndex) -> Result<IndividualId, CgkaError> {
        Ok(self
            .leaf(idx)?
            .as_ref()
            .ok_or(CgkaError::IdentifierNotFound)?
            .id)
    }

    fn inner_node(&self, idx: InnerNodeIndex) -> Result<&InnerNode, CgkaError> {
        // println!("inner_node()");
        self.inner_nodes
            .get(idx.usize())
            .ok_or(CgkaError::TreeIndexOutOfBounds)
    }

    fn inner_node_mut(&mut self, idx: InnerNodeIndex) -> Result<&mut InnerNode, CgkaError> {
        // println!("inner_node_mut()");
        self.inner_nodes
            .get_mut(idx.usize())
            .ok_or(CgkaError::TreeIndexOutOfBounds)
    }

    fn root(&self) -> Result<&InnerNode, CgkaError> {
        match treemath::root(self.tree_size) {
            TreeNodeIndex::Inner(idx) => Ok(self.inner_node(idx)?),
            _ => Err(CgkaError::TreeIndexOutOfBounds),
        }
    }

    fn root_mut(&mut self) -> Result<&mut InnerNode, CgkaError> {
        match treemath::root(self.tree_size) {
            TreeNodeIndex::Inner(idx) => Ok(self.inner_node_mut(idx)?),
            _ => Err(CgkaError::TreeIndexOutOfBounds),
        }
    }

    fn sibling_node_key(&self, tidx: TreeNodeIndex) -> Result<Option<NodeKey>, CgkaError> {
        let sibling_idx = treemath::sibling(tidx);
        Ok(match sibling_idx {
            TreeNodeIndex::Inner(idx) => self.inner_node(idx)?.node_key(),
            TreeNodeIndex::Leaf(idx) => self.leaf(idx)?.as_ref().map(|l| l.pk.clone()),
        })
    }

    fn insert_leaf_at(
        &mut self,
        idx: LeafNodeIndex,
        id: IndividualId,
        pk: NodeKey,
    ) -> Result<(), CgkaError> {
        // println!("insert_leaf_at()");
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
        // println!("insert_inner_node_at()");
        if idx.usize() >= self.inner_nodes.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        self.inner_nodes[idx.usize()] = secret_store.into();
        Ok(())
    }

    fn is_blank(&self, idx: TreeNodeIndex) -> Result<bool, CgkaError> {
        // println!("-- -- calling is_blank on {:?}, inner_nodes len: {:?}", idx, self.inner_nodes.len());
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self.leaf(l_idx)?.is_none(),
            TreeNodeIndex::Inner(p_idx) => !self.inner_node(p_idx)?.has_keys(),
        })
    }

    fn blank_path(
        &mut self,
        idx: InnerNodeIndex,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<(), CgkaError> {
        self.blank_inner_node(idx, tombstone_id)?;
        if self.is_root(idx.into()) {
            self.current_secret_encrypter_leaf_idx = None;
            println!("@@@ blank_path: At root, placed {:?}", tombstone_id);
            return Ok(());
        }
        self.blank_path(treemath::parent(idx.into()), tombstone_id)
    }

    fn remove_tombstones_from_path(
        &mut self,
        mut idx: InnerNodeIndex,
        tombstone_ids: &HashSet<CgkaTombstoneId>,
    ) -> Result<(), CgkaError> {
        while !self.is_root(idx.into()) {
            let node = self.inner_node_mut(idx)?;
            node.remove_tombstones(tombstone_ids);
            idx = treemath::parent(idx.into());
        }
        let node = self.inner_node_mut(idx)?;
        node.remove_tombstones(tombstone_ids);
        Ok(())
    }

    fn blank_inner_node(
        &mut self,
        idx: InnerNodeIndex,
        tombstone_id: CgkaTombstoneId,
    ) -> Result<(), CgkaError> {
        // println!("blank_inner_node()");
        if idx.usize() >= self.inner_nodes.len() {
            return Err(CgkaError::TreeIndexOutOfBounds);
        }
        let node = self.inner_node_mut(idx)?;
        node.add_tombstone(tombstone_id);
        node.clear_secret_store();
        if self.is_root(idx.into()) {
            println!("@@@ blank_inner_node: At root, placed {:?}", tombstone_id);
            self.current_secret_encrypter_leaf_idx = None;
        }
        Ok(())
    }

    fn is_valid_change(&self, new_path: &PathChange) -> Result<bool, CgkaError> {
        let leaf_idx = self.leaf_index_for_id(new_path.leaf_id)?;
        println!("is_valid_change(): tree_size: {:?}, member count: {:?}, leaf_idx {:?} vs. new_path.leaf_idx {:?}", self.tree_size, self.member_count(), leaf_idx.u32(), new_path.leaf_idx);
        println!(
            "-- new_path len: {:?} vs. my path len: {:?}",
            new_path.path.len(),
            self.path_length_for(LeafNodeIndex::new(new_path.leaf_idx))
        );
        // TODO: We can probably apply a path change in some cases where the tree
        // size has changed, for example if the path and copath of the subtree it
        // was part of are still preserved. For now, we are blanking the path if
        // we find the tree size has changed.
        Ok(leaf_idx.u32() == new_path.leaf_idx
            && new_path.path.len() == self.path_length_for(LeafNodeIndex::new(new_path.leaf_idx)))
    }

    /// Growing the tree will add a new root and a new subtree, all blank.
    fn maybe_grow_tree(&mut self, new_count: u32) {
        if self.tree_size >= TreeSize::from_leaf_count(new_count) {
            return;
        }
        let root_tombstones = self.root_tombstones().clone();
        self.root_mut()
            .expect("tree to have root")
            .clear_associated_tombstones();
        self.tree_size.inc();
        self.grow_tree_to_size(root_tombstones);
    }

    fn grow_tree_to_size(&mut self, root_tombstones: RootTombstones) {
        self.resize_tree();
        let root = self.root_mut().expect("tree to have root node");
        for t in root_tombstones.tombstones {
            root.add_tombstone(t);
        }
        for t in root_tombstones.associated_tombstones {
            root.add_associated_tombstone(t);
        }
    }

    fn resize_tree(&mut self) {
        self.leaves
            .resize(self.tree_size.leaf_count() as usize, None);
        self.inner_nodes
            .resize_with(self.tree_size.inner_node_count() as usize, Default::default);
    }

    fn is_root(&self, idx: TreeNodeIndex) -> bool {
        idx == treemath::root(self.tree_size)
    }

    fn path_length_for(&self, idx: LeafNodeIndex) -> usize {
        treemath::direct_path(idx.into(), self.tree_size).len()
    }

    fn contains_node_key(
        &self,
        tidx: TreeNodeIndex,
        node_key: &NodeKey,
    ) -> Result<bool, CgkaError> {
        Ok(match tidx {
            TreeNodeIndex::Inner(idx) => self.inner_node(idx)?.contains_node_key(node_key),
            TreeNodeIndex::Leaf(idx) => {
                if let Some(l) = self.leaf(idx)? {
                    l.pk.contains_node_key(node_key)
                } else {
                    false
                }
            }
        })
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
                if self.inner_node(p_idx)?.has_keys() {
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LeafNode {
    pub id: IndividualId,
    pub pk: NodeKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerNode {
    secret_store: SecretStore,
    tombstones: HashSet<CgkaTombstoneId>,
    /// Tombstones associated with updates that could have been
    /// applied elsewhere (e.g. when an update is concurrent with
    /// concurrent adds).
    associated_tombstones: HashSet<CgkaTombstoneId>,
}

impl InnerNode {
    pub fn secret_store(&self) -> &SecretStore {
        &self.secret_store
    }

    pub fn clear_secret_store(&mut self) {
        self.secret_store.clear();
    }

    pub fn tombstones(&self) -> &HashSet<CgkaTombstoneId> {
        &self.tombstones
    }

    pub fn associated_tombstones(&self) -> &HashSet<CgkaTombstoneId> {
        &self.associated_tombstones
    }

    pub fn has_single_key(&self) -> bool {
        self.secret_store.has_single_key() && self.tombstones.is_empty()
    }

    pub fn has_keys(&self) -> bool {
        self.secret_store.has_keys() && self.tombstones.is_empty()
    }

    pub fn has_conflict(&self) -> bool {
        self.secret_store.has_conflict()
    }

    pub fn node_key(&self) -> Option<NodeKey> {
        self.secret_store.node_key()
    }

    pub fn contains_node_key(&self, node_key: &NodeKey) -> bool {
        if let Some(nk) = self.node_key() {
            nk.contains_node_key(node_key)
        } else {
            false
        }
    }

    pub fn decrypt_secret(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<ShareSecretKey, CgkaError> {
        self.secret_store
            .decrypt_secret(child_node_key, child_sks, seen_idxs)
    }

    pub fn decrypt_undecrypted_secrets(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<(), CgkaError> {
        self.secret_store
            .decrypt_undecrypted_secrets(child_node_key, child_sks, seen_idxs)
    }

    pub fn merge(
        &mut self,
        other: &SecretStore,
        removed_keys: &[ShareKey],
        removed_tombstones: &HashSet<CgkaTombstoneId>,
    ) -> Result<(), CgkaError> {
        self.remove_tombstones(removed_tombstones);
        // FIXME
        // if !self.tombstones.is_empty() {
        //     self.secret_store.clear();
        // }

        // // FIXME Do we want to do this here?
        // if !self.tombstones.is_empty() {
        //     return Ok(());
        // }

        self.secret_store.merge(other, removed_keys)
    }

    pub fn add_tombstone(&mut self, tombstone_id: CgkaTombstoneId) {
        // println!("Inserting {:?}", tombstone_id);
        self.tombstones.insert(tombstone_id);
        // FIXME: Do we want to do this here? If so, we can remove at sort and blank
        // self.secret_store.clear();
    }

    pub fn add_associated_tombstone(&mut self, tombstone_id: CgkaTombstoneId) {
        println!("Inserting associated {:?}", tombstone_id);
        self.associated_tombstones.insert(tombstone_id);
    }

    pub fn clear_tombstones(&mut self) {
        // FIXME
        // if !self.tombstones.is_empty() {
        //     self.secret_store.clear();
        // }
        self.tombstones.clear();
    }

    pub fn clear_associated_tombstones(&mut self) {
        self.associated_tombstones.clear();
    }

    fn remove_tombstones(&mut self, removed_tombstones: &HashSet<CgkaTombstoneId>) {
        println!(
            "-- -- Removing tombstones: {:?}",
            removed_tombstones.iter().map(|t| t).collect::<Vec<_>>()
        );
        self.tombstones = self
            .tombstones
            .difference(removed_tombstones)
            .cloned()
            .collect();
    }
}

impl Default for InnerNode {
    fn default() -> Self {
        Self {
            secret_store: Default::default(),
            tombstones: Default::default(),
            associated_tombstones: Default::default(),
        }
    }
}

impl From<SecretStore> for InnerNode {
    fn from(secret_store: SecretStore) -> Self {
        Self {
            secret_store,
            tombstones: Default::default(),
            associated_tombstones: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootTombstones {
    pub(crate) tombstones: HashSet<CgkaTombstoneId>,
    pub(crate) associated_tombstones: HashSet<CgkaTombstoneId>,
}

impl RootTombstones {
    pub(crate) fn new(
        tombstones: HashSet<CgkaTombstoneId>,
        associated_tombstones: HashSet<CgkaTombstoneId>,
    ) -> Self {
        Self {
            tombstones,
            associated_tombstones,
        }
    }
}
