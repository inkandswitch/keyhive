pub mod beekem;
pub mod error;
pub mod keys;
pub mod operation;
pub mod secret_store;
pub mod treemath;

#[cfg(feature = "test_utils")]
pub mod test_utils;

use std::{borrow::Borrow, rc::Rc};

use crate::{
    content::reference::ContentRef,
    crypto::{
        application_secret::{ApplicationSecret, PcsKey},
        digest::Digest,
        encrypted::Encrypted,
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
use operation::CgkaOperation;
use serde::{Deserialize, Serialize};

/// A CGKA (Continuous Group Key Agreement) protocol is responsible for
/// maintaining a stream of updating shared group keys over time. We are
/// using a variation of the TreeKEM protocol (which we call BeeKEM).
///
/// This Cgka struct provides a protocol-agnostic interface for retrieving the
/// latest secret, rotating keys, and adding and removing members from the group.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Cgka {
    doc_id: DocumentId,
    pub owner_id: IndividualId,
    pub owner_sks: ShareKeyMap,
    tree: BeeKem,
    // TODO: Once we can rebuild the tree to correspond to earlier PcsKeys,
    // convert this to a cache of some kind with policies.
    pcs_keys: CaMap<PcsKey>,
}

/// Constructors
impl Cgka {
    /// We assume members are in causal order.
    pub fn new<R: rand::CryptoRng + rand::RngCore>(
        members: NonEmpty<(IndividualId, ShareKey)>,
        doc_id: DocumentId,
        owner_id: IndividualId,
        owner_pk: ShareKey,
        owner_sk: ShareSecretKey,
        csprng: &mut R,
    ) -> Result<Self, CgkaError> {
        if !members
            .iter()
            .any(|(id, pk)| *id == owner_id && *pk == owner_pk)
        {
            return Err(CgkaError::OwnerIdentifierNotFound);
        }
        let tree = BeeKem::new(doc_id, members)?;
        let mut owner_sks = ShareKeyMap::new();
        owner_sks.insert(owner_pk, owner_sk);
        let mut cgka = Self {
            doc_id,
            owner_id,
            owner_sks,
            tree,
            pcs_keys: Default::default(),
        };
        cgka.tree
            .encrypt_path(owner_id, owner_pk, &mut cgka.owner_sks, csprng)?;
        let pcs_key = cgka.derive_pcs_key()?;
        cgka.pcs_keys.insert(Rc::new(pcs_key));
        Ok(cgka)
    }

    pub fn with_new_owner(
        &self,
        my_id: IndividualId,
        pk: ShareKey,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        if !self.tree.node_key_for_id(my_id)?.contains_key(&pk) {
            return Err(CgkaError::ShareKeyNotFound);
        }
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_sks = owner_sks;
        cgka.pcs_keys = Default::default();
        if self.has_pcs_key() {
            let pcs_key = cgka.derive_pcs_key()?;
            cgka.pcs_keys.insert(Rc::new(pcs_key));
        }
        Ok(cgka)
    }

    fn derive_pcs_key(&mut self) -> Result<PcsKey, CgkaError> {
        let key = self
            .tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)?;
        Ok(PcsKey::new(key))
    }
}

/// Public CGKA operations
impl Cgka {
    pub fn new_app_secret_for<T: ContentRef, R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_ref: &Vec<T>,
        csprng: &mut R,
    ) -> Result<ApplicationSecret<T>, CgkaError> {
        // If the tree currently has no root key, we generate a new key pair
        // and use it to perform a PCS update. Note that this means the new leaf
        // key pair is only known at the Cgka level where it is stored in the
        // ShareKeyMap.
        if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            self.update(new_share_key, new_share_secret_key, csprng)
                .expect("FIXME");
        }
        let current_pcs_key = self.derive_pcs_key()?;
        let pcs_key_hash = Digest::hash(&current_pcs_key);
        if !self.pcs_keys.contains_key(&pcs_key_hash) {
            self.pcs_keys.insert(Rc::new(current_pcs_key));
        }
        let nonce = Siv::new(&current_pcs_key.into(), content, self.doc_id)
            .map_err(|_e| CgkaError::Conversion)?;
        Ok(current_pcs_key.derive_application_secret(
            &nonce,
            &Digest::hash(content_ref),
            &Digest::hash(pred_ref),
        ))
    }

    // TODO: Remove once we move to Rust 2024 and can rewrite with an if let chain.
    #[allow(clippy::unnecessary_unwrap)]
    pub fn decryption_key_for<T, Cr: ContentRef>(
        &mut self,
        encrypted: &Encrypted<T, Cr>,
    ) -> Result<SymmetricKey, CgkaError> {
        let maybe_pcs_key: Option<Rc<PcsKey>> = self.pcs_keys.get(&encrypted.pcs_key_hash).cloned();
        // TODO: With Rust 2024, we'll be able to use if let chains to rewrite this
        // in a cleaner way. See https://github.com/rust-lang/rust/pull/132833.
        let last_key = if maybe_pcs_key.is_some()
            && Digest::hash(maybe_pcs_key.clone().expect("is some").borrow())
                == encrypted.pcs_key_hash
        {
            maybe_pcs_key.expect("is some")
        } else {
            let pcs_key = self.derive_pcs_key()?;
            if Digest::hash(&pcs_key) == encrypted.pcs_key_hash {
                Rc::new(pcs_key)
            } else {
                // FIXME: Right now it's possible that we never derived a PCS key
                // from the update corresponding to the PCS key hash in the metadata.
                // For example, we might have applied that update as part of a
                // concurrent merge, which left the tree with no root secret.
                return Err(CgkaError::UnknownPcsKey);
            }
        };
        self.pcs_keys.insert(last_key.clone());
        let app_secret = last_key.derive_application_secret(
            &encrypted.nonce,
            &encrypted.content_ref,
            &encrypted.pred_ref,
        );
        Ok(app_secret.key())
    }

    /// Get secret for decryption/encryption. If you are using this for a new
    /// encryption, you need to update your leaf key first to ensure you are
    /// using a fresh root secret.
    pub fn secret(&mut self) -> Result<ShareSecretKey, CgkaError> {
        self.tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
    }

    pub fn has_pcs_key(&self) -> bool {
        self.tree.has_root_key()
    }

    /// Add member.
    pub fn add(&mut self, id: IndividualId, pk: ShareKey) -> Result<CgkaOperation, CgkaError> {
        let leaf_index = self.tree.push_leaf(id, pk)?;
        let op = CgkaOperation::Add { id, pk, leaf_index };
        Ok(op)
    }

    /// Remove member.
    pub fn remove(&mut self, id: IndividualId) -> Result<CgkaOperation, CgkaError> {
        if self.group_size() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }

        let removed_keys = self.tree.remove_id(id)?;
        let op = CgkaOperation::Remove { id, removed_keys };
        Ok(op)
    }

    /// Update key pair for this Identifier.
    pub fn update<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        csprng: &mut R,
    ) -> Result<CgkaOperation, CgkaError> {
        self.owner_sks.insert(new_pk, new_sk);
        let maybe_new_path =
            self.tree
                .encrypt_path(self.owner_id, new_pk, &mut self.owner_sks, csprng)?;
        if let Some(new_path) = maybe_new_path {
            let op = CgkaOperation::Update {
                id: self.owner_id,
                new_path,
            };
            Ok(op)
        } else {
            Err(CgkaError::IdentifierNotFound)
            // // Currently, if the id is not present, we return an error.
            // // This would happen if the id has been removed. But causal ordering
            // // should ensure this never happens for a non-removed id.
        }
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// Apply an operation that is an immediate causal successor to the current Cgka
    /// state.
    pub fn apply_operation(&mut self, op: &CgkaOperation) -> Result<(), CgkaError> {
        match op {
            CgkaOperation::Add {
                id,
                pk,
                leaf_index: _,
            } => {
                // TODO: Check we don't already have this id in the tree.
                self.tree.push_leaf(*id, *pk)?;
            }
            CgkaOperation::Remove {
                id,
                removed_keys: _,
            } => {
                self.tree.remove_id(*id)?;
            }
            CgkaOperation::Update { id, new_path } => {
                // TODO: We are currently ignoring a missing id here. Causal ordering
                // should ensure that an update for an id will always come after the
                // add of that id but might come after a remove. If it came after a
                // remove, we ignore it.
                if self.tree.contains_id(*id) {
                    self.tree.apply_path(new_path)?;
                }
            }
        }
        Ok(())
    }

    /// Merge
    pub fn merge_concurrent_operations(&mut self, ops: &[CgkaOperation]) -> Result<(), CgkaError> {
        let mut includes_add = false;
        for op in ops {
            if matches!(op, CgkaOperation::Add { .. }) {
                includes_add = true;
            }
            self.apply_operation(op)?;
        }
        // TODO: This is the naive approach to merging concurrent adds: blank the inner
        // nodes and lexicographically sort the leaves.
        if includes_add {
            self.tree.sort_leaves_and_blank_tree()?;
        }
        Ok(())
    }

    /// Replace current tree with tree from other Cgka
    pub fn replace_tree(&mut self, other: &Self) {
        self.tree = other.tree.clone();
    }
}

#[cfg(test)]
mod tests {
    use test_utils::{
        add_from_all_members, add_from_first_member, apply_test_operations_rewind_and_merge_to_all,
        remove_from_left, remove_from_right, remove_odd_members, setup_cgka, setup_member_cgkas,
        setup_members, update_added_members, update_all_members, update_even_members, TestMember,
        TestMemberCgka, TestOperation,
    };

    use super::*;

    #[test]
    fn test_root_key_after_update_is_not_leaf_sk() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        let doc_id = DocumentId::generate(csprng);
        let members = setup_members(2);
        let mut cgka = setup_cgka(doc_id, &members, 0);
        let sk = ShareSecretKey::generate(csprng);
        let pk = sk.share_key();
        cgka.update(pk, sk.clone(), csprng)?;
        assert_ne!(sk, cgka.secret()?);
        Ok(())
    }

    #[test]
    fn test_simple_add() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        let doc_id = DocumentId::generate(csprng);
        let members = setup_members(2);
        let initial_member_count = members.len();
        let mut cgka = setup_cgka(doc_id, &members, 0);
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
        let mut cgka = setup_cgka(doc_id, &members, 0);
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
        let mut cgkas = setup_member_cgkas(doc_id, 7)?;
        assert!(cgkas[0].cgka.has_pcs_key());
        let op1 = cgkas[1].update(csprng)?;
        cgkas[0].cgka.merge_concurrent_operations(&vec![op1])?;
        let op6 = cgkas[6].update(csprng)?;
        cgkas[0].cgka.merge_concurrent_operations(&vec![op6])?;
        assert!(!cgkas[0].cgka.has_pcs_key());
        Ok(())
    }

    fn update_merge_and_compare_secrets<R: rand::CryptoRng + rand::RngCore>(
        member_cgkas: &mut Vec<TestMemberCgka>,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        // One member updates and all merge that in so that the tree has a root secret.
        let m_idx = if member_cgkas.len() > 1 { 1 } else { 0 };
        let update_op = member_cgkas[m_idx].update(csprng)?;
        let post_update_secret_bytes = member_cgkas[m_idx].cgka.secret()?.to_bytes();
        for (idx, m) in member_cgkas.iter_mut().enumerate() {
            if idx == m_idx {
                continue;
            }
            m.cgka
                .merge_concurrent_operations(&vec![update_op.clone()])?;
        }
        member_cgkas[m_idx].cgka.secret()?.to_bytes();
        // Compare the result of secret() for all members
        for m in member_cgkas.iter_mut() {
            assert_eq!(m.cgka.secret()?.to_bytes(), post_update_secret_bytes);
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
        let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
        let mut initial_cgka = member_cgkas[0].cgka.clone();
        let initial_secret_bytes = initial_cgka.secret()?.to_bytes();
        for m in &mut member_cgkas {
            assert_eq!(m.cgka.secret()?.to_bytes(), initial_secret_bytes);
        }
        for test_round in test_rounds {
            apply_test_operations_rewind_and_merge_to_all(&mut member_cgkas, test_round)?;
            update_merge_and_compare_secrets(&mut member_cgkas, csprng)?;
        }
        Ok(())
    }

    fn run_tests_for_1_to_32_members<R: rand::CryptoRng + rand::RngCore>(
        test_rounds: Vec<Vec<Box<TestOperation>>>,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        for n in 1..16 {
            run_test_rounds(n, &test_rounds, csprng)?;
        }
        run_test_rounds(20, &test_rounds, csprng)?;
        run_test_rounds(25, &test_rounds, csprng)?;
        run_test_rounds(31, &test_rounds, csprng)?;
        run_test_rounds(32, &test_rounds, csprng)?;
        Ok(())
    }

    #[test]
    fn test_update_all_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_1_to_32_members(vec![vec![update_all_members()]], &mut csprng)
    }

    #[test]
    fn test_update_even_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_1_to_32_members(vec![vec![update_even_members()]], &mut csprng)
    }

    #[test]
    fn test_remove_odd_concurrently() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        run_tests_for_1_to_32_members(vec![vec![remove_odd_members()]], csprng)
    }

    #[test]
    fn test_remove_from_right_concurrently() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        run_tests_for_1_to_32_members(vec![vec![remove_from_right(1)]], csprng)
    }

    #[test]
    fn test_remove_from_left_concurrently() -> Result<(), CgkaError> {
        let csprng = &mut rand::thread_rng();
        run_tests_for_1_to_32_members(vec![vec![remove_from_left(1)]], csprng)
    }

    #[test]
    fn test_update_then_remove_then_update_even_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_1_to_32_members(
            vec![
                vec![update_all_members()],
                vec![remove_odd_members()],
                vec![update_even_members()],
            ],
            &mut csprng,
        )
    }

    #[test]
    fn test_update_and_remove_concurrently() -> Result<(), CgkaError> {
        let mut csprng = rand::thread_rng();
        run_tests_for_1_to_32_members(
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
        run_tests_for_1_to_32_members(
            vec![vec![update_all_members(), add_from_all_members()]],
            &mut csprng,
        )
    }

    #[test]
    fn test_add_one_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![add_from_first_member()]], &mut rand::thread_rng())
    }

    #[test]
    fn test_all_add_one_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![add_from_all_members()]], &mut rand::thread_rng())
    }

    #[test]
    fn test_remove_then_all_add_one_then_remove_odd_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(
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
        run_tests_for_1_to_32_members(
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
        run_tests_for_1_to_32_members(
            vec![vec![add_from_all_members(), update_all_members()]],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_update_added_members_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(
            vec![vec![add_from_all_members(), update_added_members()]],
            &mut rand::thread_rng(),
        )
    }

    #[test]
    fn test_a_bunch_of_ops_in_rounds() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(
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
