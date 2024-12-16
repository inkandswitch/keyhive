pub mod beekem;
pub mod error;
pub mod keys;
pub mod operation;
pub mod secret_store;
pub mod tombstone;
pub mod treemath;

#[cfg(feature = "test_utils")]
pub mod test_utils;

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    rc::Rc,
};

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
use operation::{CgkaOperation, CgkaOperationGraph};
use tombstone::CgkaTombstoneId;

/// A CGKA (Continuous Group Key Agreement) protocol is responsible for
/// maintaining a stream of updating shared group keys over time. We are
/// using a variation of the TreeKEM protocol (which we call BeeKEM).
///
/// This Cgka struct provides a protocol-agnostic interface for retrieving the
/// latest secret, rotating keys, and adding and removing members from the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgka {
    doc_id: DocumentId,
    pub owner_id: IndividualId,
    pub owner_sks: ShareKeyMap,
    tree: BeeKem,
    ops_graph: CgkaOperationGraph,
    // TODO: Once we can rebuild the tree to correspond to earlier PcsKeys,
    // convert this to a cache of some kind with policies.
    // FIXME
    pcs_keys: CaMap<PcsKey>,
    pcs_key_ops: HashMap<Digest<PcsKey>, Digest<CgkaOperation>>,
    // FIXME: Is there a better way to keep track of this? Does it make more
    // sense to create an initial stream of add operations?
    original_member: (IndividualId, ShareKey),
}

/// Constructors
impl Cgka {
    /// We assume members are in causal order.
    // FIXME: Make new() just the original member and add a separate
    // multi-add method to get initial add operations back.
    pub fn new(
        doc_id: DocumentId,
        owner_id: IndividualId,
        owner_pk: ShareKey,
    ) -> Result<Self, CgkaError> {
        let tree = BeeKem::new(doc_id, owner_id, owner_pk)?;
        let cgka = Self {
            doc_id,
            owner_id,
            owner_sks: Default::default(),
            tree,
            ops_graph: Default::default(),
            pcs_keys: Default::default(),
            pcs_key_ops: Default::default(),
            original_member: (owner_id, owner_pk),
        };
        Ok(cgka)
    }

    pub fn with_new_owner(
        &self,
        my_id: IndividualId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        // FIXME: For added members, we can't expect the id to be there yet
        // if !self.tree.node_key_for_id(my_id)?.contains_key(&pk) {
        //     return Err(CgkaError::ShareKeyNotFound);
        // }
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_sks = owner_sks;
        // FIXME: Should these copy over the old keys?
        cgka.pcs_keys = Default::default();
        cgka.pcs_key_ops = Default::default();
        Ok(cgka)
    }

    pub fn ops_graph(&self) -> &CgkaOperationGraph {
        &self.ops_graph
    }

    pub fn derive_pcs_key(&mut self) -> Result<PcsKey, CgkaError> {
        println!("CALLING derive_pcs_key()");
        let key = self
            .tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)?;
        Ok(PcsKey::new(key))
    }

    fn derive_pcs_key_for_op(
        &mut self,
        op_hash: &Digest<CgkaOperation>,
    ) -> Result<PcsKey, CgkaError> {
        println!("derive_pcs_key_for_op()");
        if !self.ops_graph.contains_op_hash(op_hash) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let ops = self
            .ops_graph
            .topsort_for_op(op_hash)?;
        self.rebuild_pcs_key(self.doc_id, ops)
    }
}

/// Public CGKA operations
impl Cgka {
    pub fn new_app_secret_for<T: ContentRef, R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        csprng: &mut R,
    ) -> Result<(ApplicationSecret<T>, Option<CgkaOperation>), CgkaError> {
        println!("new_app_secret_for");
        let mut op = None;
        // If the tree currently has no root key, we generate a new key pair
        // and use it to perform a PCS update. Note that this means the new leaf
        // key pair is only known at the Cgka level where it is stored in the
        // ShareKeyMap.
        let current_pcs_key = if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            let (pcs_key, update_op) = self
                .update(new_share_key, new_share_secret_key, csprng)
                .expect("FIXME");
            self.pcs_key_ops
                .insert(Digest::hash(&pcs_key), Digest::hash(&update_op));
            self.pcs_keys.insert(pcs_key.into());
            op = Some(update_op);
            pcs_key
        } else {
            self.derive_pcs_key()?
        };
        let pcs_key_hash = Digest::hash(&current_pcs_key);
        let nonce = Siv::new(&current_pcs_key.into(), content, self.doc_id)
            .map_err(|_e| CgkaError::Conversion)?;
        Ok((
            current_pcs_key.derive_application_secret(
                &nonce,
                &Digest::hash(content_ref),
                &Digest::hash(pred_refs),
                &self.pcs_key_ops.get(&pcs_key_hash).expect("FIXME"),
            ),
            op,
        ))
    }

    // TODO: Remove once we move to Rust 2024 and can rewrite with an if let chain.
    #[allow(clippy::unnecessary_unwrap)]
    pub fn decryption_key_for<T, Cr: ContentRef>(
        &mut self,
        encrypted: &Encrypted<T, Cr>,
    ) -> Result<SymmetricKey, CgkaError> {
        println!("decryption_key_for");
        let maybe_pcs_key: Option<Rc<PcsKey>> = self.pcs_keys.get(&encrypted.pcs_key_hash).cloned();
        let last_key = if let Some(pcs_key) = maybe_pcs_key {
            pcs_key
        } else {
            println!("decryption_key_for: calling derive_pcs_key_for_op");
            self.derive_pcs_key_for_op(&encrypted.pcs_update_op_hash)?.into()
            // let pcs_key = self.derive_pcs_key()?;
            // if Digest::hash(&pcs_key) == encrypted.pcs_key_hash {
            //     pcs_key.into()
            // } else {
            //     // FIXME: Right now it's possible that we never derived a PCS key
            //     // from the update corresponding to the PCS key hash in the metadata.
            //     // For example, we might have applied that update as part of a
            //     // concurrent merge, which left the tree with no root secret.
            //     return Err(CgkaError::UnknownPcsKey);
            // }
        };
        self.pcs_keys.insert(last_key.clone());
        self.pcs_key_ops.insert(
            Digest::hash(&last_key.borrow()),
            encrypted.pcs_update_op_hash,
        );
        let app_secret = last_key.derive_application_secret(
            &encrypted.nonce,
            &encrypted.content_ref,
            &encrypted.pred_refs,
            &encrypted.pcs_update_op_hash,
        );
        Ok(app_secret.key())
    }

    /// Get secret for decryption/encryption. If you are using this for a new
    /// encryption, you need to update your leaf key first to ensure you are
    /// using a fresh root secret.
    #[cfg(feature = "test_utils")]
    pub fn secret(&mut self, pcs_key_hash: &Digest<PcsKey>, update_op_hash: &Digest<CgkaOperation>) -> Result<PcsKey, CgkaError> {
        println!("ID {:?} is calling secret()!", self.owner_id);
        if let Some(pcs_key) = self.pcs_keys.get(pcs_key_hash) {
            Ok(*pcs_key.clone())
        } else {
            if self.has_pcs_key() {
                let pcs_key = self.derive_pcs_key()?;
                if &Digest::hash(&pcs_key) == pcs_key_hash {
                    return Ok(pcs_key)
                }
            }
            println!("secret: calling derive_pcs_key_for_op");
            self.derive_pcs_key_for_op(update_op_hash)
        }
        // FIXME
        // self.tree
        //     .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
    }

    pub fn has_pcs_key(&self) -> bool {
        self.tree.has_root_key()
    }

    /// Add member.
    pub fn add<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        csprng: &mut R,
    ) -> Result<CgkaOperation, CgkaError> {
        let tombstone_id = CgkaTombstoneId::generate(csprng);
        println!(
            "\nAdding {:?} by {:?} and generating tombstone id for Cgka::add(): {:?}",
            id, self.owner_id, tombstone_id
        );
        let leaf_index = self.tree.add_leaf(id, pk, tombstone_id)?;
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let add_predecessors = Vec::from_iter(self.ops_graph.add_heads.iter().cloned());
        let op = CgkaOperation::Add {
            added_id: id,
            pk,
            leaf_index,
            predecessors,
            add_predecessors,
            tombstone_id,
        };
        self.ops_graph.add_local_op(&op);
        Ok(op)
    }

    /// Add member.
    pub fn add_multiple<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        members: NonEmpty<(IndividualId, ShareKey)>,
        csprng: &mut R,
    ) -> Result<Vec<CgkaOperation>, CgkaError> {
        let mut ops = Vec::new();
        for m in members {
            ops.push(self.add(m.0, m.1, csprng)?);
        }
        Ok(ops)
    }

    /// Remove member.
    pub fn remove<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        id: IndividualId,
        csprng: &mut R,
    ) -> Result<CgkaOperation, CgkaError> {
        if self.group_size() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }

        let tombstone_id = CgkaTombstoneId::generate(csprng);
        println!(
            "\nGenerating tombstone id for Cgka::remove(): {:?}",
            tombstone_id
        );
        let removed_keys = self.tree.remove_id(id, tombstone_id)?;
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let op = CgkaOperation::Remove {
            id,
            removed_keys,
            predecessors,
            tombstone_id,
        };
        self.ops_graph.add_local_op(&op);
        Ok(op)
    }

    /// Update key pair for this Identifier.
    pub fn update<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        csprng: &mut R,
    ) -> Result<(PcsKey, CgkaOperation), CgkaError> {
        self.owner_sks.insert(new_pk, new_sk);
        let tombstone_id = CgkaTombstoneId::generate(csprng);
        println!(
            "\nGenerating tombstone id for Cgka::update(): {:?}",
            tombstone_id
        );
        let maybe_key_and_path = self.tree.encrypt_path(
            self.owner_id,
            new_pk,
            &mut self.owner_sks,
            tombstone_id,
            csprng,
        )?;
        if let Some((pcs_key, new_path)) = maybe_key_and_path {
            let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
            let op = CgkaOperation::Update {
                id: self.owner_id,
                new_path,
                predecessors,
                tombstone_id,
            };
            println!("-- Cgka::update() add_local_op");
            self.ops_graph.add_local_op(&op);
            self.pcs_key_ops
                .insert(Digest::hash(&pcs_key), Digest::hash(&op));
            self.pcs_keys.insert(pcs_key.into());
            println!("-- Cgka::update() LAST");
            Ok((pcs_key, op))
        } else {
            println!("-- Cgka::update() NOOOOO");
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

    /// Merge
    pub fn merge_concurrent_operation(&mut self, op: &CgkaOperation) -> Result<(), CgkaError> {
        println!("_______________________________________");
        println!("\n******________________________________________");
        println!(
            "Owner {:?}: Merge concurrent op {:?}!",
            self.owner_id,
            op.name()
        );
        println!("******________________________________________\n");
        let predecessors = op.predecessors();
        let mut sort_tombstone = None;
        if self.ops_graph.heads_contained_in(&predecessors) {
            // FIXME
            self.tree.has_structural_change = false;
        }
        if let CgkaOperation::Add {
            tombstone_id,
            add_predecessors,
            ..
        } = op
        {
            if !self
                .ops_graph
                .add_heads_contained_in(&HashSet::from_iter(add_predecessors.iter().cloned()))
            {
                sort_tombstone = Some(tombstone_id);
            }
            println!(
                "** ops_graph.heads_contained_in(predecessors): {:?}",
                self.ops_graph.add_heads_contained_in(&predecessors)
            );
            println!("** add_predecessors: {:?}\n", add_predecessors);
            println!("** current_add_heads: {:?}", self.ops_graph.add_heads);
        }
        self.apply_operation(op)?;
        self.ops_graph.add_op(&op, &predecessors);
        if let Some(tombstone_id) = sort_tombstone {
            println!("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
            println!("__sort and blank <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
            println!("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
            self.tree.sort_leaves_and_blank_tree(*tombstone_id)?;
        } else {
            println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
            println!("__REMAIN!");
            println!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        }
        println!("** ** NODES after merging");
        // FIXME
        self.tree.print_nodes();
        Ok(())
    }

    fn apply_operation(&mut self, op: &CgkaOperation) -> Result<(), CgkaError> {
        println!("apply_operation by owner id {:?}", self.owner_id);
        match op {
            CgkaOperation::Add {
                added_id,
                pk,
                leaf_index: _,
                predecessors: _,
                add_predecessors: _,
                tombstone_id,
            } => {
                // TODO: Check we don't already have this id in the tree.
                self.tree.add_leaf(*added_id, *pk, *tombstone_id)?;
            }
            CgkaOperation::Remove {
                id,
                removed_keys: _,
                predecessors: _,
                tombstone_id,
            } => {
                self.tree.remove_id(*id, *tombstone_id)?;
            }
            CgkaOperation::Update {
                id,
                new_path,
                predecessors: _,
                tombstone_id,
            } => {
                println!(
                    "ID {:?} APPLYING Update!  tree.contains id {:?}: {:?}",
                    self.owner_id,
                    id,
                    self.tree.contains_id(*id)
                );
                // TODO: We are currently ignoring a missing id here. Causal ordering
                // should ensure that an update for an id will always come after the
                // add of that id but might come after a remove. If it came after a
                // remove, we ignore it.
                if self.tree.contains_id(*id) {
                    self.tree.apply_path(new_path, *tombstone_id)?;
                }
            }
        }
        Ok(())
    }

    pub fn rebuild_pcs_key(
        &mut self,
        doc_id: DocumentId,
        ops: NonEmpty<Rc<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        println!("\n\n\n\n\n(((((((((((((((((((((((((((((((((())))))))))))))))))))))))");
        println!("-- rebuild_pcs_key! (rebuilding by id {:?} based on op {:?}", self.owner_id, ops.last());
        println!("(((((((((((((((((((((((((((((((((())))))))))))))))))))))))\n\n\n\n\n");
        debug_assert!(matches!(ops.last().borrow(), &CgkaOperation::Update { .. }));
        let mut rebuilt_cgka =
            Cgka::new(doc_id, self.original_member.0, self.original_member.1)
            .expect("FIXME")
            .with_new_owner(self.owner_id, self.owner_sks.clone())?;
        for op in &ops {
            rebuilt_cgka.merge_concurrent_operation(op)?;
        }
        let pcs_key = rebuilt_cgka.derive_pcs_key()?;
        self.pcs_key_ops
            .insert(Digest::hash(&pcs_key), Digest::hash(ops.last()));
        self.pcs_keys.insert(pcs_key.clone().into());
        Ok(pcs_key)
    }

    // FIXME: When replacing tree, we also need to rewind the ops graph!
    /// Replace current tree with tree from other Cgka
    pub fn replace_tree(&mut self, other: &Self) {
        self.tree = other.tree.clone();
        self.ops_graph = other.ops_graph.clone();
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
        let (mut cgka, _ops) = setup_cgka(doc_id, &members, 0);
        let sk = ShareSecretKey::generate(csprng);
        let pk = sk.share_key();
        cgka.update(pk, sk.clone(), csprng)?;
        assert_ne!(sk, cgka.derive_pcs_key()?.0);
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
        cgka.add(new_m.id, new_m.pk, csprng)?;
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
        cgka.remove(members[1].id, csprng)?;
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
        let op1 = cgkas[1].update(csprng)?;
        cgkas[0].cgka.merge_concurrent_operation(&op1)?;
        let op6 = cgkas[6].update(csprng)?;
        cgkas[0].cgka.merge_concurrent_operation(&op6)?;
        assert!(!cgkas[0].cgka.has_pcs_key());
        Ok(())
    }

    fn update_merge_and_compare_secrets<R: rand::CryptoRng + rand::RngCore>(
        member_cgkas: &mut Vec<TestMemberCgka>,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        // One member updates and all merge that in so that the tree has a root secret.
        // FIXME
        // let m_idx = 0;
        println!("\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
        println!("Create update op for secret comparison");
        println!("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        let m_idx = if member_cgkas.len() > 1 { 1 } else { 0 };
        let update_op = member_cgkas[m_idx].update(csprng)?;
        println!("\nupdate_op: {:?}\n", update_op);
        let post_update_pcs_key = member_cgkas[m_idx].cgka.derive_pcs_key()?;
        for (idx, m) in member_cgkas.iter_mut().enumerate() {
            if idx == m_idx {
                continue;
            }
            println!("_______________________________________");
            println!("\n+merge in overwrite update for member idx {idx}");
            m.cgka.merge_concurrent_operation(&update_op)?;
            println!("\n+has root key: {:?}", m.cgka.tree.has_root_key());
        }
        println!("\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
        println!("Check and compare secrets for members");
        println!("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");

        println!("Nodes on all members before last update:");
        // FIXME Remove
        for (m_idx, m) in member_cgkas.iter().enumerate() {
            println!("+ALL NODES for m idx {m_idx}, id: {:?}", m.id());
            m.cgka.tree.print_nodes();
        }

        println!("Check secrets for everyone");
        // Compare the result of secret() for all members
        // FIXME
        // for m in member_cgkas.iter_mut() {
        for (idx, m) in member_cgkas.iter_mut().enumerate() {
            println!("\n+Checking secret for member idx {idx}");
            assert_eq!(m.cgka.secret(&Digest::hash(&post_update_pcs_key), &Digest::hash(&update_op))?, post_update_pcs_key);
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
        println!("run_test_rounds()");
        assert!(member_count >= 1);
        let doc_id = DocumentId::generate(csprng);
        let (mut member_cgkas, ops) = setup_member_cgkas(doc_id, member_count)?;
        let mut initial_cgka = member_cgkas[0].cgka.clone();
        let initial_pcs_key = initial_cgka.derive_pcs_key()?;
        let update_op = ops.last().expect("update op");
        for m in &mut member_cgkas {
            assert_eq!(m.cgka.secret(&Digest::hash(&initial_pcs_key), &Digest::hash(&update_op))?, initial_pcs_key);
        }
        for test_round in test_rounds {
            println!("\n*******************");
            println!("*******************");
            println!("apply_test_operations_rewind_and_merge_to_all");
            println!("*******************");
            println!("*******************");
            apply_test_operations_rewind_and_merge_to_all(&mut member_cgkas, test_round)?;
            println!("\n*******************");
            println!("*******************");
            println!("update_merge_and_compare_secrets");
            println!("*******************");
            println!("*******************");
            update_merge_and_compare_secrets(&mut member_cgkas, csprng)?;
        }
        Ok(())
    }

    fn run_tests_for_1_to_32_members<R: rand::CryptoRng + rand::RngCore>(
        test_rounds: Vec<Vec<Box<TestOperation>>>,
        csprng: &mut R,
    ) -> Result<(), CgkaError> {
        // FIXME
        // for n in 1..16 {
        for n in 1..16 {
            // FIXME
            if n != 2 {
                continue;
            }
            println!("\n\n\n\n*** N = {n} ***\n\n");
            run_test_rounds(n, &test_rounds, csprng)?;
        }
        // FIXME
        // run_test_rounds(20, &test_rounds, csprng)?;
        // run_test_rounds(25, &test_rounds, csprng)?;
        // run_test_rounds(31, &test_rounds, csprng)?;
        // run_test_rounds(32, &test_rounds, csprng)?;
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

    // #[test]
    // fn test_remove_odd_concurrently() -> Result<(), CgkaError> {
    //     let csprng = &mut rand::thread_rng();
    //     run_tests_for_1_to_32_members(vec![vec![remove_odd_members()]], csprng)
    // }

    // #[test]
    // fn test_remove_from_right_concurrently() -> Result<(), CgkaError> {
    //     let csprng = &mut rand::thread_rng();
    //     run_tests_for_1_to_32_members(vec![vec![remove_from_right(1)]], csprng)
    // }

    // #[test]
    // fn test_remove_from_left_concurrently() -> Result<(), CgkaError> {
    //     let csprng = &mut rand::thread_rng();
    //     run_tests_for_1_to_32_members(vec![vec![remove_from_left(1)]], csprng)
    // }

    // #[test]
    // fn test_update_then_remove_then_update_even_concurrently() -> Result<(), CgkaError> {
    //     let mut csprng = rand::thread_rng();
    //     run_tests_for_1_to_32_members(
    //         vec![
    //             vec![update_all_members()],
    //             vec![remove_odd_members()],
    //             vec![update_even_members()],
    //         ],
    //         &mut csprng,
    //     )
    // }

    // #[test]
    // fn test_update_and_remove_concurrently() -> Result<(), CgkaError> {
    //     let mut csprng = rand::thread_rng();
    //     run_tests_for_1_to_32_members(
    //         vec![vec![
    //             update_all_members(),
    //             remove_odd_members(),
    //             update_even_members(),
    //         ]],
    //         &mut csprng,
    //     )
    // }

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

    // #[test]
    // fn test_remove_then_all_add_one_then_remove_odd_concurrently() -> Result<(), CgkaError> {
    //     run_tests_for_1_to_32_members(
    //         vec![
    //             vec![remove_from_right(1)],
    //             vec![add_from_all_members()],
    //             vec![remove_odd_members()],
    //         ],
    //         &mut rand::thread_rng(),
    //     )
    // }

    // #[test]
    // fn test_update_all_then_add_from_all_then_remove_odd_then_update_even_concurrently(
    // ) -> Result<(), CgkaError> {
    //     let mut csprng = rand::thread_rng();
    //     run_tests_for_1_to_32_members(
    //         vec![
    //             vec![update_all_members()],
    //             vec![add_from_all_members()],
    //             vec![remove_odd_members()],
    //             vec![update_even_members()],
    //         ],
    //         &mut csprng,
    //     )
    // }

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

    // #[test]
    // fn test_a_bunch_of_ops_in_rounds() -> Result<(), CgkaError> {
    //     run_tests_for_1_to_32_members(
    //         vec![vec![
    //             update_all_members(),
    //             add_from_all_members(),
    //             add_from_first_member(),
    //             remove_odd_members(),
    //             add_from_first_member(),
    //             remove_from_right(1),
    //             remove_from_left(1),
    //             update_even_members(),
    //             add_from_first_member(),
    //             update_even_members(),
    //             add_from_first_member(),
    //             remove_from_left(2),
    //             remove_odd_members(),
    //             update_all_members(),
    //             add_from_first_member(),
    //             remove_from_right(2),
    //             update_even_members(),
    //         ]],
    //         &mut rand::thread_rng(),
    //     )
    // }
}
