pub mod beekem;
pub mod error;
pub mod keys;
pub mod operation;
pub mod secret_store;
pub mod treemath;

// FIXME: This is also used for benches, so using the feature flag breaks
// the build
// #[cfg(feature = "test_utils")]
pub mod test_utils;

use crate::{
    crypto::share_key::{ShareKey, ShareSecretKey},
    principal::{document::id::DocumentId, identifier::Identifier},
};
use beekem::BeeKem;
use error::CgkaError;
use keys::ShareKeyMap;
use operation::CgkaOperation;
use serde::{Deserialize, Serialize};

/// A CGKA (Continuous Group Key Agreement) protocol is responsible for
/// maintaining a stream of updating shared group keys over time. We are
/// using a variation of the TreeKEM protocol (which we call BeeKEM).
///
/// This Cgka struct provides a protocol-agnostic interface for retrieving the
/// latest secret, rotating keys, and adding and removing members from the group.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cgka {
    owner_id: Identifier,
    /// Invariant: An owner will never have conflict keys for its public key since
    /// any updates to that pk must be initiated by the owner.
    owner_pk: ShareKey,
    owner_sks: ShareKeyMap,
    tree: BeeKem,
}

/// Constructors
impl Cgka {
    /// We assume members are in causal order.
    pub fn new(
        members: Vec<(Identifier, ShareKey)>,
        doc_id: DocumentId,
        owner_id: Identifier,
        owner_pk: ShareKey,
        owner_sk: ShareSecretKey,
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
            owner_id,
            owner_pk,
            owner_sks,
            tree,
        };
        // TODO: We don't strictly need to do this but current tests depend on it and
        // assume an initialized Cgka has a root secret.
        cgka.tree
            .encrypt_path(owner_id, owner_pk, &mut cgka.owner_sks)?;
        Ok(cgka)
    }

    pub fn with_new_owner(
        &self,
        my_id: Identifier,
        pk: ShareKey,
        sk: ShareSecretKey,
    ) -> Result<Self, CgkaError> {
        if !self.tree.node_key_for_id(my_id)?.contains_key(&pk) {
            return Err(CgkaError::ShareKeyNotFound);
        }
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_pk = pk;
        cgka.owner_sks = ShareKeyMap::new();
        cgka.owner_sks.insert(pk, sk);
        Ok(cgka)
    }
}

/// Public CGKA operations
impl Cgka {
    /// Get secret for decryption/encryption. If you are using this for a new
    /// encryption, you need to update your leaf key first to ensure you are
    /// using a fresh root secret.
    pub fn secret(&mut self) -> Result<ShareSecretKey, CgkaError> {
        self.tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
    }

    /// Add member.
    pub fn add(&mut self, id: Identifier, pk: ShareKey) -> Result<CgkaOperation, CgkaError> {
        let leaf_index = self.tree.push_leaf(id, pk)?;
        let op = CgkaOperation::Add { id, pk, leaf_index };
        Ok(op)
    }

    /// Remove member.
    pub fn remove(&mut self, id: Identifier) -> Result<CgkaOperation, CgkaError> {
        if self.group_size() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }
        let removed_keys = self.tree.remove_id(id)?;
        let op = CgkaOperation::Remove { id, removed_keys };
        Ok(op)
    }

    /// Update key pair for this Identifier.
    pub fn update(
        &mut self,
        id: Identifier,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
    ) -> Result<Option<CgkaOperation>, CgkaError> {
        debug_assert!(id == self.owner_id);
        self.owner_pk = new_pk;
        self.owner_sks.insert(new_pk, new_sk);
        let maybe_new_path = self.tree.encrypt_path(id, new_pk, &mut self.owner_sks)?;
        if let Some(new_path) = maybe_new_path {
            let op = CgkaOperation::Update { id, new_path };
            Ok(Some(op))
        } else {
            // Currently, if the id is not present, we treat update as a no-op.
            // This would happen if the id has been removed. But causal ordering
            // should ensure this never happens for a non-removed id.
            Ok(None)
        }
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// Merge
    pub fn merge(&mut self, op: CgkaOperation) -> Result<(), CgkaError> {
        match op {
            CgkaOperation::Add {
                id,
                pk,
                leaf_index: _,
            } => {
                // TODO: This is the naive approach to merging concurrent adds: grow
                // the tree if necessary, blank the parent nodes, and lexicographically
                // sort the leaves.
                // TODO: Check we don't already have this id in the tree.
                self.tree.push_leaf(id, pk)?;
                self.tree.sort_leaves_and_blank_tree()?;
            }
            CgkaOperation::Remove {
                id,
                removed_keys: _,
            } => {
                self.remove(id)?;
            }
            CgkaOperation::Update { id: _, new_path } => {
                self.tree.apply_path(&new_path)?;
            }
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
        setup_members, update_all_members, update_even_members, TestMember, TestMemberCgka,
        TestOperation,
    };

    use super::*;

    #[test]
    fn test_simple_add() -> Result<(), CgkaError> {
        let doc_id = DocumentId::generate();
        let members = setup_members(2);
        let initial_member_count = members.len();
        let mut cgka = setup_cgka(doc_id, &members, 0);
        assert!(cgka.tree.has_root_key()?);
        let new_m = TestMember::generate();
        cgka.add(new_m.id, new_m.pk)?;
        assert!(!cgka.tree.has_root_key()?);
        assert_eq!(cgka.tree.member_count(), initial_member_count as u32 + 1);
        Ok(())
    }

    #[test]
    fn test_simple_remove() -> Result<(), CgkaError> {
        let doc_id = DocumentId::generate();
        let members = setup_members(2);
        let initial_member_count = members.len();
        let mut cgka = setup_cgka(doc_id, &members, 0);
        assert!(cgka.tree.has_root_key()?);
        cgka.remove(members[1].id)?;
        assert!(!cgka.tree.has_root_key()?);
        assert_eq!(cgka.group_size(), initial_member_count as u32 - 1);
        Ok(())
    }

    #[test]
    fn test_no_root_key_after_concurrent_updates() -> Result<(), CgkaError> {
        let doc_id = DocumentId::generate();
        let mut cgkas = setup_member_cgkas(doc_id, 7)?;
        assert!(cgkas[0].cgka.tree.has_root_key()?);
        let op1 = cgkas[1].update()?.ok_or(CgkaError::InvalidOperation)?;
        cgkas[0].cgka.merge(op1)?;
        let op6 = cgkas[6].update()?.ok_or(CgkaError::InvalidOperation)?;
        cgkas[0].cgka.merge(op6)?;
        assert!(!cgkas[0].cgka.tree.has_root_key()?);
        Ok(())
    }

    fn update_merge_and_compare_secrets(
        member_cgkas: &mut Vec<TestMemberCgka>,
    ) -> Result<(), CgkaError> {
        // One member updates and all merge that in so that the tree has a root secret.
        let m_idx = if member_cgkas.len() > 1 { 1 } else { 0 };
        let update_op = member_cgkas[m_idx]
            .update()?
            .ok_or(CgkaError::IdentifierNotFound)?;
        let post_update_secret_bytes = member_cgkas[m_idx].cgka.secret()?.to_bytes();
        for (idx, m) in member_cgkas.iter_mut().enumerate() {
            if idx == m_idx {
                continue;
            }
            m.cgka.merge(update_op.clone())?;
        }
        member_cgkas[m_idx].cgka.secret()?.to_bytes();
        // Compare the result of secret() for all members
        for m in member_cgkas.iter_mut().skip(1) {
            assert_eq!(m.cgka.secret()?.to_bytes(), post_update_secret_bytes);
        }
        Ok(())
    }

    /// A "test round" is a series of TestOperation functions which are applied
    /// concurrently. This function applies each round and then does a single update
    /// and merge across members to check that everyone converges on the same secret
    /// after that round.
    fn run_test_rounds(
        member_count: u32,
        test_rounds: &[Vec<Box<TestOperation>>],
    ) -> Result<(), CgkaError> {
        assert!(member_count >= 1);
        let doc_id = DocumentId::generate();
        let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
        let mut initial_cgka = member_cgkas[0].cgka.clone();
        let initial_secret_bytes = initial_cgka.secret()?.to_bytes();
        for m in &mut member_cgkas {
            assert_eq!(m.cgka.secret()?.to_bytes(), initial_secret_bytes);
        }
        for test_round in test_rounds {
            apply_test_operations_rewind_and_merge_to_all(&mut member_cgkas, test_round)?;
            update_merge_and_compare_secrets(&mut member_cgkas)?;
        }
        Ok(())
    }

    fn run_tests_for_1_to_32_members(
        test_rounds: Vec<Vec<Box<TestOperation>>>,
    ) -> Result<(), CgkaError> {
        for n in 1..16 {
            run_test_rounds(n, &test_rounds)?;
        }
        run_test_rounds(20, &test_rounds)?;
        run_test_rounds(25, &test_rounds)?;
        run_test_rounds(31, &test_rounds)?;
        run_test_rounds(32, &test_rounds)?;
        Ok(())
    }

    #[test]
    fn test_update_all_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![update_all_members()]])
    }

    #[test]
    fn test_update_even_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![update_even_members()]])
    }

    #[test]
    fn test_remove_odd_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![remove_odd_members()]])
    }

    #[test]
    fn test_remove_from_right_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![remove_from_right(1)]])
    }

    #[test]
    fn test_remove_from_left_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![remove_from_left(1)]])
    }

    #[test]
    fn test_update_then_remove_then_update_even_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![
            vec![update_all_members()],
            vec![remove_odd_members()],
            vec![update_even_members()],
        ])
    }

    #[test]
    fn test_update_and_remove_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![
            update_all_members(),
            remove_odd_members(),
            update_even_members(),
        ]])
    }

    #[test]
    fn test_update_and_add_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![update_all_members(), add_from_all_members()]])
    }

    #[test]
    fn test_add_one_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![add_from_first_member()]])
    }

    #[test]
    fn test_all_add_one_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![add_from_all_members()]])
    }

    #[test]
    fn test_remove_then_all_add_one_then_remove_odd_concurrently() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![
            vec![remove_from_right(1)],
            vec![add_from_all_members()],
            vec![remove_odd_members()],
        ])
    }

    #[test]
    fn test_update_all_then_add_from_all_then_remove_odd_then_update_even_concurrently(
    ) -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![
            vec![update_all_members()],
            vec![add_from_all_members()],
            vec![remove_odd_members()],
            vec![update_even_members()],
        ])
    }

    #[test]
    fn test_a_bunch_of_ops_in_rounds() -> Result<(), CgkaError> {
        run_tests_for_1_to_32_members(vec![vec![
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
        ]])
    }
}
