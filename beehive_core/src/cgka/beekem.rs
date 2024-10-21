// * Leaf nodes represent members. Each member has a fixed Identifier as well
//   as a public key that is rotated over time.
// * Each non-leaf node stores one or more public keys and a secret used
//   for deriving a shared key for decrypting the parent.
// * Secrets are randomly generated.
// * In the simple case, a node is encrypted via Diffie Hellman using the private key of
//   one child node and the public key of its sibling. If the sibling subtree is blank,
//   the child will use its own secret key to encrypt directly. If the sibling is blank
//   but has non-blank descendents, the child node will do Diffie Hellman with each of
//   those descendents to encrypt the parent secret (storing these in a map).
// * All operations start from a leaf.
// * Concurrent adds create conflicting leaf orders. How do we minimize restructuring
//   of the tree on merge?
// * * Current proposal: keep the longest of the two conflicting sets of adds and append
//   the non-redundant adds from the shorter set to the right in lexicographic Identifier
//   order.
// * Remove blanks the path of the removed node.
// * Blanks are skipped when determining effective children of a parent by taking
//   the resolution.
// * There should always be at least one leaf node.
// *
// * Brooke's innovation: for conflicting node updates off your path, you keep
//   all conflicting public keys at those nodes when merging. At the node on your path
//   with a multi-key child, you perform a nested Diffie Hellman.
// * * There will be at most one sibling with multiple conflict public keys at the
//     moment of updating the parent (because the updater would replace the other sibling
//     on its path with a single public key)?
// *
// * Tree structure conflicts to consider (the auth graph crdt determines who wins in say add/remove conflicts):
// * * Concurrent key rotations
// * * Concurrent adds
// * * Concurrent removes
// * * Concurrent key rotations, adds, and removes
//
// * Rotations are probably much more common than adds
// * Adds are more common than removes
// * We hypothesize that earlier members (who tend to be further left in the leaves
//   vector) will be less likely to be removed. Removals on the left are more expensive
//   to "garbage collect" since filling in those blanks (i.e. implicit tombstones)
//   requires moving more leaves to the left.
//
// Is it an invariant that the root will always have a secret? To guarantee this
// we need to
// * initialize a root key on tree construction
// * recalculate the root key when removing another leaf
// * recalculate the root key when doing any operation that blanks up to the root
// Should these invariants be managed at the CGKA or BeeKEM tree level?

use std::{collections::BTreeMap, fmt::{self, Debug, Formatter}};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use treemath::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize};
use x25519_dalek::{self, x25519, StaticSecret};

use crate::{
    crypto::{encrypted::Encrypted, hash::Hash, symmetric_key::SymmetricKey},
    principal::identifier::Identifier,
};

use super::{error::CGKAError, message::TreePath, treemath};
pub type PublicKey = x25519_dalek::PublicKey;
pub type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BeeKEM {
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<Identifier, LeafNodeIndex>,
}

impl BeeKEM {
    /// We can assume members are in causal order (a property guaranteed by
    /// Beehive as a whole).
    pub(crate) fn new(
        members: Vec<(Identifier, PublicKey)>,
    ) -> Result<Self, CGKAError> {
        let mut tree = Self {
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            parents: Vec::new(),
            tree_size: TreeSize::from_leaf_count(members.len() as u32),
            id_to_leaf_idx: BTreeMap::new(),
        };
        tree.grow_tree_to_size();
        for (idx, (id, pk)) in members.iter().enumerate() {
            tree.push_leaf(*id, *pk)?;
        }
        Ok(tree)
    }

    /// Hash of the tree
    pub fn hash(&self) -> Hash<BeeKEM> {
        Hash::hash(self.clone())
    }

    pub(crate) fn public_key(&self, idx: TreeNodeIndex) -> Result<&PublicKey, CGKAError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                &self
                    .leaf(l_idx)?
                    .as_ref()
                    .ok_or(CGKAError::PublicKeyNotFound)?
                    .pk
            }
            TreeNodeIndex::Parent(p_idx) => {
                &self
                    .parent(p_idx)?
                    .as_ref()
                    .ok_or(CGKAError::PublicKeyNotFound)?
                    .pk
            }
        })
    }

    pub(crate) fn public_key_for_id(&self, id: Identifier) -> Result<&PublicKey, CGKAError> {
        let idx = self.leaf_index_for_id(id)?;
        self.public_key((*idx).into())
    }

    pub(crate) fn leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CGKAError> {
        self.leaves
            .get(idx.usize())
            .ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    fn leaf_index_for_id(&self, id: Identifier) -> Result<&LeafNodeIndex, CGKAError> {
        self.id_to_leaf_idx
            .get(&id)
            .ok_or(CGKAError::IdentifierNotFound)
    }

    fn id_for_leaf(&self, idx: LeafNodeIndex) -> Result<Identifier, CGKAError> {
        Ok(self
            .leaf(idx)?
            .as_ref()
            .ok_or(CGKAError::IdentifierNotFound)?
            .id)
    }

    pub(crate) fn parent(&self, idx: ParentNodeIndex) -> Result<&Option<ParentNode>, CGKAError> {
        self.parents
            .get(idx.usize())
            .ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    pub(crate) fn insert_leaf_at(
        &mut self,
        idx: LeafNodeIndex,
        leaf: LeafNode,
    ) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        self.leaves[idx.usize()] = Some(leaf);
        Ok(())
    }

    pub(crate) fn insert_parent_at(
        &mut self,
        idx: ParentNodeIndex,
        parent: ParentNode,
    ) -> Result<(), CGKAError> {
        if idx.usize() >= self.parents.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        self.parents[idx.usize()] = Some(parent);
        Ok(())
    }

    pub(crate) fn blank_leaf_and_path(&mut self, idx: LeafNodeIndex) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }

        self.leaves[idx.usize()] = None;
        self.blank_path(treemath::parent(idx.into()))
    }

    pub(crate) fn push_leaf(&mut self, id: Identifier, pk: PublicKey) -> Result<u32, CGKAError> {
        self.maybe_grow_tree(self.next_leaf_idx.u32());
        let l_idx = self.next_leaf_idx;
        // Increment next leaf idx
        self.next_leaf_idx += 1;
        self.id_to_leaf_idx.insert(id, l_idx);
        self.insert_leaf_at(l_idx, LeafNode { id, pk })?;
        self.blank_path(treemath::parent(l_idx.into()));
        Ok(l_idx.u32())
    }

    pub(crate) fn remove_id(&mut self, id: Identifier) -> Result<u32, CGKAError> {
        if self.member_count() == 1 {
            return Err(CGKAError::RemoveLastMember);
        }
        let l_idx = self.leaf_index_for_id(id)?;
        let l_idx_u32 = l_idx.u32();
        self.blank_leaf_and_path(*l_idx)?;
        self.id_to_leaf_idx.remove(&id);
        // "Collect" any contiguous tombstones at the end of the leaves Vec
        while self.leaf(self.next_leaf_idx - 1)?.is_none() {
            self.next_leaf_idx -= 1;
        }
        Ok(l_idx_u32)
    }

    pub(crate) fn member_count(&self) -> u32 {
        self.id_to_leaf_idx.len() as u32
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. along the
    /// leaf's path). As you look at each parent node along the way, if the node is not
    /// blank, look up your child idx in the parent's secret key map. Derive a Diffie Hellman
    /// shared key using the public key stored in the secret map and use that shared key to
    /// decrypt the secret key stored there.
    ///
    /// If the parent is blank, hold on to the last non-blank child node's index and secret
    /// key and move to the next parent.
    pub(crate) fn decrypt_tree_secret(
        &mut self,
        owner_id: Identifier,
        owner_sk: SecretKey,
    ) -> Result<SecretKey, CGKAError> {
        let leaf_idx = *self.leaf_index_for_id(owner_id)?;
        let leaf = self.leaf(leaf_idx)?.as_ref()
            .ok_or(CGKAError::OwnerIdentifierNotFound)?;
        // TODO: Should we enforce an invariant that there will always be a root key?
        if self.no_root_key()? {
            self.encrypt_path(leaf.id, leaf.pk, owner_sk.clone())?;
            return Err(CGKAError::NoRootKey);
        }
        if self.is_blank(leaf_idx.into())? {
            return Err(CGKAError::OwnerIdentifierNotFound);
        }
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut last_non_blank_child_idx: TreeNodeIndex = child_idx;
        let mut child_sk = owner_sk.clone();
        let mut child_pk = leaf.pk;
        let mut parent_idx: TreeNodeIndex = treemath::parent(child_idx).into();
        while !self.is_root(child_idx) {
            // Find the next non-blank parent
            while self.is_blank(parent_idx)? {
                child_idx = parent_idx.into();
                parent_idx = treemath::parent(child_idx).into();
            }
            debug_assert!(!self.is_root(child_idx));
            child_sk = self.decrypt_parent_key(
                last_non_blank_child_idx,
                child_idx,
                child_pk,
                child_sk.clone(),
            )?;
            child_pk = *self.public_key(parent_idx)?;
            child_idx = parent_idx;
            last_non_blank_child_idx = child_idx;
            parent_idx = treemath::parent(child_idx).into();
        }
        Ok(child_sk)
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. along the
    /// leaf's path). As you look at each parent node along the way, you need to populate
    /// it with a public key and a map from sibling subtree public keys to a newly generated
    /// secret key encrypted pairwise with each node in the sibling resolution (in the
    /// ideal case, this will just be the sibling node itself, but if the sibling is
    /// blank it can be many nodes).
    ///
    /// If the sibling node's resolution is empty, then you will generate the new key
    /// pair but encrypt the secret with your last secret (instead of using Diffie Hellman
    /// with a sibling). The secret key map for that parent will then only have an entry
    /// for you.
    pub(crate) fn encrypt_path(
        &mut self,
        id: Identifier,
        pk: PublicKey,
        sk: SecretKey,
    ) -> Result<TreePath, CGKAError> {
        let leaf_idx = *self.leaf_index_for_id(id)?;
        let mut new_path = vec![(leaf_idx.u32(), pk)];
        if self.id_for_leaf(leaf_idx)? != id {
            return Err(CGKAError::IdentifierNotFound);
        }
        self.insert_leaf_at(leaf_idx, LeafNode { id, pk })?;
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut child_pk = pk;
        let mut child_sk = sk.clone();
        let mut parent_idx = treemath::parent(child_idx);
        while !self.is_root(child_idx) {
            let (new_parent_pk, new_parent_sk) = generate_new_key_pair();
            self.encrypt_key_for_parent(
                child_idx,
                child_pk,
                child_sk.clone(),
                new_parent_pk,
                new_parent_sk.clone(),
            )?;
            child_idx = parent_idx.into();
            child_pk = new_parent_pk;
            child_sk = new_parent_sk;
            parent_idx = treemath::parent(child_idx);
            new_path.push((child_idx.u32(), child_pk));
        }
        Ok(new_path)
    }

    pub(crate) fn no_root_key(&self) -> Result<bool, CGKAError> {
        let root_idx = treemath::root(self.tree_size);
        let TreeNodeIndex::Parent(p_idx) = root_idx else {
            return Err(CGKAError::TreeIndexOutOfBounds);
        };
        Ok(self.parent(p_idx)?.is_none())
    }

    fn decrypt_parent_key(
        &self,
        non_blank_child_idx: TreeNodeIndex,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_sk: SecretKey,
    ) -> Result<SecretKey, CGKAError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        debug_assert!(!self.is_blank(parent_idx.into())?);
        let parent = self
            .parent(parent_idx)?
            .as_ref()
            .ok_or(CGKAError::TreeIndexOutOfBounds)?;
        let encrypted = parent
            .sk
            .get(&non_blank_child_idx)
            // FIXME: Pick a better error
            .ok_or(CGKAError::IdentifierNotFound)?;

        let sibling_idx = treemath::sibling(child_idx);
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        let decrypt_key = if child_pk == parent.encrypter_pk {
            if let Some(paired_pk) = parent.encrypter_paired_pk {
                generate_shared_key(&paired_pk, child_sk)
            } else {
                // Normally you use a DH shared key to encrypt/decrypt the next node up,
                // but if there's a blank sibling subtree, then you use your secret key
                // directly instead.
                child_sk
            }
        } else {
            let paired_pk = parent.encrypter_pk;
            generate_shared_key(&paired_pk, child_sk)
        };

        decrypt_secret(encrypted, decrypt_key)
    }

    fn encrypt_key_for_parent(
        &mut self,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_sk: SecretKey,
        new_parent_pk: PublicKey,
        new_parent_sk: SecretKey,
    ) -> Result<(), CGKAError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        let (encrypter_paired_pk, new_secret_map) =
            self.encrypt_new_secret_for_parent(child_idx, child_pk, child_sk, new_parent_sk)?;
        let node = ParentNode {
            pk: new_parent_pk,
            sk: new_secret_map,
            encrypter_pk: child_pk,
            encrypter_paired_pk,
        };
        self.insert_parent_at(parent_idx, node)?;
        Ok(())
    }

    fn encrypt_new_secret_for_parent(
        &self,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_sk: SecretKey,
        new_parent_sk: SecretKey,
    ) -> Result<
        (
            Option<PublicKey>,
            BTreeMap<TreeNodeIndex, Encrypted<SecretKey>>,
        ),
        CGKAError,
    > {
        debug_assert!(!self.is_root(child_idx));
        let sibling_idx = treemath::sibling(child_idx);
        let mut secret_map = BTreeMap::new();
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        let encrypter_paired_pk = if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you use your secret key
            // directly instead.
            let encrypted_sk = encrypt_secret(new_parent_sk.clone(), child_sk.clone())?;
            secret_map.insert(child_idx, encrypted_sk);
            None
        } else {
            // Encrypt the secret for every node in the sibling resolution, using
            // a new DH shared secret to do the encryption for each node.
            let mut paired_pk = None;
            for idx in sibling_resolution {
                let sibling_pk = self.public_key(idx)?;
                let shared_key = generate_shared_key(sibling_pk, child_sk.clone());
                let encrypted_sk = encrypt_secret(new_parent_sk.clone(), shared_key.clone())?;
                if paired_pk.is_none() {
                    secret_map.insert(child_idx, encrypted_sk.clone());
                    paired_pk = Some(*sibling_pk);
                }
                secret_map.insert(idx, encrypted_sk);
            }
            paired_pk
        };
        Ok((encrypter_paired_pk, secret_map))
    }

    fn is_blank(&self, idx: TreeNodeIndex) -> Result<bool, CGKAError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self.leaf(l_idx)?.is_none(),
            TreeNodeIndex::Parent(p_idx) => self.parent(p_idx)?.is_none(),
        })
    }

    fn blank_path(&mut self, idx: ParentNodeIndex) -> Result<(), CGKAError> {
        self.blank_parent(idx)?;
        if self.is_root(idx.into()) {
            return Ok(());
        }
        self.blank_path(treemath::parent(idx.into()))
    }

    fn blank_parent(&mut self, idx: ParentNodeIndex) -> Result<(), CGKAError> {
        if idx.usize() >= self.parents.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        self.parents[idx.usize()] = None;
        Ok(())
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
        self.parents
            .resize(self.tree_size.parent_count() as usize, None);
    }

    fn is_root(&self, idx: TreeNodeIndex) -> bool {
        idx == treemath::root(self.tree_size)
    }

    /// Highest non-blank descendents of a node
    fn append_resolution(
        &self,
        idx: TreeNodeIndex,
        acc: &mut Vec<TreeNodeIndex>,
    ) -> Result<(), CGKAError> {
        match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                if self.leaf(l_idx)?.is_some() {
                    acc.push(l_idx.into());
                }
            }
            TreeNodeIndex::Parent(p_idx) => {
                if self.parent(p_idx)?.is_some() {
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

// TODO: This is currently just a stopgap for tree hashing. How do we actually want
// to derive the tree hash?
impl From<BeeKEM> for Vec<u8> {
    fn from(tree: BeeKEM) -> Self {
        bincode::serialize(&tree).expect("Serialization failed")
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct LeafNode {
    pub id: Identifier,
    pub pk: PublicKey,
}

impl Debug for LeafNode {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_struct("LeafNode")
      .field("id", &self.id)
      .field("pk", &self.pk.to_bytes())
      .finish()
  }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ParentNode {
    // TODO: Handle multiple public keys for BeeKEM conflict resolution
    pub pk: PublicKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub sk: BTreeMap<TreeNodeIndex, Encrypted<SecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub encrypter_pk: PublicKey,
    /// If this is None, the sibling subtree was blank when encrypting this parent.
    /// Otherwise, it is the first PublicKey in the sibling resolution, which the
    /// encrypter used for its own Diffie Hellman shared secret.
    pub encrypter_paired_pk: Option<PublicKey>,
}

impl Debug for ParentNode {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_struct("ParentNode")
      .field("pk", &self.pk.to_bytes())
      .field("encrypter_pk", &self.encrypter_pk.to_bytes())
      .field("encrypter_paired_pk", &self.encrypter_paired_pk.map(|pk| pk.to_bytes()))
      .finish()
  }
}


//////////////////////////////////////////////////////////////////
// FIXME: Replace this section with using beehive crypto capabilities
// directly
//////////////////////////////////////////////////////////////////
fn generate_new_key_pair() -> (PublicKey, SecretKey) {
    let sk = StaticSecret::random_from_rng(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);
    (pk, sk)
}

fn generate_shared_key(their_public_key: &PublicKey, my_secret: SecretKey) -> SecretKey {
    x25519(my_secret.to_bytes(), their_public_key.to_bytes()).into()
}

fn encrypt_secret(
    secret: SecretKey,
    encrypt_key: SecretKey,
) -> Result<Encrypted<SecretKey>, CGKAError> {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let symmetric_key = SymmetricKey::from(encrypt_key.to_bytes());
    let encrypted_secret_bytes = symmetric_key
        .encrypt(nonce.into(), secret.as_bytes())
        .map_err(CGKAError::Encryption)?;
    let encrypted_secret: Encrypted<SecretKey> =
        Encrypted::new(nonce.into(), encrypted_secret_bytes);
    Ok(encrypted_secret)
}

fn decrypt_secret(
    encrypted: &Encrypted<SecretKey>,
    decrypt_key: SecretKey,
) -> Result<SecretKey, CGKAError> {
    let symmetric_key = SymmetricKey::from(decrypt_key.to_bytes());
    let decrypted_bytes: [u8; 32] = symmetric_key
        .decrypt(encrypted.nonce, &encrypted.ciphertext)
        .map_err(|e| CGKAError::Decryption(e.to_string()))?
        .try_into()
        .map_err(|e| CGKAError::Conversion)?;
    Ok(StaticSecret::from(decrypted_bytes))
}
//////////////////////////////////////////////////////////////////
