use super::{error::CgkaError, operation::CgkaOperation, Cgka};
use crate::{
    cgka::keys::ShareKeyMap,
    crypto::{
        digest::Digest,
        share_key::{ShareKey, ShareSecretKey},
    },
    principal::{document::id::DocumentId, identifier::Identifier, individual::id::IndividualId},
};
use nonempty::{nonempty, NonEmpty};
use rand::{thread_rng, Rng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    mem,
};

pub type TestContentRef = u32;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TestMember {
    pub id: IndividualId,
    pub pk: ShareKey,
    pub sk: ShareSecretKey,
}

impl TestMember {
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let id = IndividualId(Identifier::generate(csprng));
        let sk = ShareSecretKey::generate(csprng);
        let pk = sk.share_key();
        Self { id, pk, sk }
    }

    pub fn cgka_from(&self, cgka: &Cgka) -> Result<Cgka, CgkaError> {
        let mut sks = ShareKeyMap::new();
        sks.insert(self.pk, self.sk);
        cgka.with_new_owner(self.id, sks)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestMemberCgka {
    pub m: TestMember,
    pub cgka: Cgka,
}

impl TestMemberCgka {
    pub fn new(m: TestMember, other_cgka: &Cgka) -> Result<Self, CgkaError> {
        let cgka = m.cgka_from(&other_cgka)?;
        Ok(Self { m, cgka })
    }

    pub fn id(&self) -> IndividualId {
        self.m.id
    }

    pub fn update<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<CgkaOperation, CgkaError> {
        let sk = ShareSecretKey::generate(csprng);
        let pk = sk.share_key();
        self.m.pk = pk;
        self.m.sk = sk;
        let (_pcs_key, op) = self.cgka.update(pk, sk, csprng)?;
        Ok(op)
    }

    pub fn update_cgka_to(&mut self, cgka: &Cgka) -> Result<(), CgkaError> {
        let sks = self.cgka.owner_sks.clone();
        self.cgka = cgka.with_new_owner(self.id(), sks)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestConcurrentOperations {
    pub ops: HashMap<IndividualId, VecDeque<CgkaOperation>>,
    // This is distinguished so that we can ensure added member ops are ordered after
    // the ops of members that added them.
    pub added_member_ops: HashMap<IndividualId, VecDeque<CgkaOperation>>,
}

impl TestConcurrentOperations {
    pub fn new() -> Self {
        Self {
            ops: Default::default(),
            added_member_ops: Default::default(),
        }
    }

    pub fn add(&mut self, member_id: IndividualId, op: CgkaOperation) {
        self.ops.entry(member_id).or_default().push_back(op);
    }

    pub fn add_to_added_member_ops(&mut self, member_id: IndividualId, op: CgkaOperation) {
        self.added_member_ops
            .entry(member_id)
            .or_default()
            .push_back(op);
    }

    /// Interweave concurrent ops from all members while maintaining order within each
    /// member's ops. The relative ordering of concurrent ops is randomized each time.
    /// The cancelled adds help simulate the fact that Beehive will not
    /// apply operations for a member after removing that member.
    pub fn simulated_ordering_with_cancelled_adds(
        &mut self,
    ) -> (Vec<(IndividualId, CgkaOperation)>, HashSet<IndividualId>) {
        let mut cancelled_adds = HashSet::new();
        let mut member_ops: Vec<(IndividualId, VecDeque<CgkaOperation>)> = self
            .ops
            .iter()
            .map(|(id, ops)| (*id, ops.clone()))
            .collect::<Vec<_>>();
        let mut ops = Vec::new();
        let mut removed_ids = HashSet::new();
        while !member_ops.is_empty() {
            let idx = thread_rng().gen_range(0..member_ops.len());
            let (m_id, ref mut next_member_ops) = &mut member_ops[idx];
            if let Some(next_op) = next_member_ops.pop_front() {
                if removed_ids.contains(m_id) {
                    if let CgkaOperation::Add { added_id, .. } = next_op {
                        cancelled_adds.insert(added_id);
                    }
                } else {
                    if let CgkaOperation::Remove { id, .. } = next_op {
                        removed_ids.insert(id);
                    }
                    ops.push((*m_id, next_op));
                }
            }
            if next_member_ops.is_empty() {
                member_ops.remove(idx);
            }
        }
        for (id, added_member_ops) in &self.added_member_ops {
            if !removed_ids.contains(&id) {
                for op in added_member_ops {
                    ops.push((*id, op.clone()))
                }
            }
        }
        (ops, cancelled_adds)
    }
}

pub fn setup_members(member_count: u32) -> NonEmpty<TestMember> {
    assert!(member_count > 0);
    let mut csprng = rand::thread_rng();
    let mut ms = nonempty![TestMember::generate(&mut csprng)];
    for _ in 1..member_count {
        ms.push(TestMember::generate(&mut csprng));
    }
    ms
}

pub fn setup_cgka(
    doc_id: DocumentId,
    members: &NonEmpty<TestMember>,
    m_idx: usize,
) -> (Cgka, Vec<CgkaOperation>) {
    let owner = &members[m_idx];
    let first = members.first().clone();
    let mut cgka = Cgka::new(doc_id, first.id, first.pk).expect("CGKA construction failed");
    let mut ops = Vec::new();
    if members.len() > 1 {
        ops = cgka
            .add_multiple(
                NonEmpty::from_vec(
                    members
                        .iter()
                        .skip(1)
                        .map(|p| (p.id, p.pk))
                        .collect::<Vec<_>>(),
                )
                .expect("there to be extra members"),
                &mut rand::thread_rng(),
            )
            .expect("there to be extra members");
    }

    let mut owner_sks = ShareKeyMap::new();
    owner_sks.insert(owner.pk, owner.sk);
    let mut cgka = cgka
        .with_new_owner(owner.id, owner_sks)
        .expect("CGKA construction failed");
    let (_pcs_key, op) = cgka.update(owner.pk, owner.sk, &mut rand::thread_rng())
        .expect("CGKA update to succeed");
    ops.push(op);
    (cgka, ops)
}

/// Set up cgkas for all members with the same secret, but only the initial member
/// has updated its path.
pub fn setup_member_cgkas(
    doc_id: DocumentId,
    member_count: u32,
) -> Result<(Vec<TestMemberCgka>, Vec<CgkaOperation>), CgkaError> {
    let members = setup_members(member_count);
    let (initial_cgka, ops) = setup_cgka(doc_id, &members, 0);
    let mut member_cgkas = Vec::new();
    for m in members {
        member_cgkas.push(TestMemberCgka::new(m.clone(), &initial_cgka)?);
    }
    Ok((member_cgkas, ops))
}

/// Set up cgkas for all members with the same secret, with every member
/// having updated its path and no conflict keys in the inner nodes.
pub fn setup_updated_and_synced_member_cgkas(
    doc_id: DocumentId,
    member_count: u32,
) -> Result<(Vec<TestMemberCgka>, Vec<CgkaOperation>), CgkaError> {
    let mut members = setup_members(member_count);
    let (initial_cgka, mut all_ops) = setup_cgka(doc_id, &members, 0);
    let mut member_cgkas = vec![TestMemberCgka::new(members[0].clone(), &initial_cgka)?];
    let mut ops = Vec::new();
    for m in members.iter_mut().skip(1) {
        let mut member_cgka = TestMemberCgka::new(m.clone(), &initial_cgka)?;
        let op = member_cgka.update(&mut rand::thread_rng())?;
        member_cgkas[0].cgka.merge_concurrent_operation(&op)?;
        ops.push((m.id, op));
        member_cgkas.push(member_cgka);
    }
    let op = member_cgkas[0].update(&mut rand::thread_rng())?;
    ops.push((member_cgkas[0].id(), op));
    for m in member_cgkas.iter_mut().skip(1) {
        for (id, op) in &ops {
            if *id != m.id() {
                m.cgka.merge_concurrent_operation(&op)?;
            }
        }
    }
    all_ops.extend(ops.iter().map(|(id, op)| op).cloned().collect::<Vec<_>>());
    Ok((member_cgkas, all_ops))
}

#[derive(Debug, Clone)]
pub enum TestMergeStrategy {
    MergeToAllMembers,
    MergeToOneMemberAndClone,
}

pub fn apply_test_operations(
    member_cgkas: &mut Vec<TestMemberCgka>,
    test_operations: &[Box<TestOperation>],
    test_merge_strategy: TestMergeStrategy,
) -> Result<(), CgkaError> {
    println!("apply_test_operations 1");
    let mut ops = TestConcurrentOperations::new();
    let starting_cgkas = member_cgkas.clone();
    let initial_cgka = starting_cgkas[0].cgka.clone();
    let mut added_members = Vec::new();
    println!("apply_test_operations 2");
    // FIXME
    // for test_op in test_operations {
    for (idx, test_op) in test_operations.iter().enumerate() {
        println!("-- test_op idx {idx}");
        test_op(member_cgkas, &initial_cgka, &mut added_members, &mut ops)?;
    }
    let (ordered_ops, cancelled_adds) = ops.simulated_ordering_with_cancelled_adds();

    println!("apply_test_operations 3");
    match test_merge_strategy {
        TestMergeStrategy::MergeToAllMembers => {
            // For each member, we go back to the original CGKA versions and apply
            // this set of changes.
            // for (idx, m) in member_cgkas.iter_mut().enumerate() {
            //     m.cgka.replace_tree(&starting_cgkas[idx].cgka);
            // }
            // for m in added_members.iter_mut() {
            //     m.cgka.replace_tree(&starting_cgkas[0].cgka);
            // }
            // FIXME
            println!("\n\nMerging in ordered ops\n");
            for (_id, op) in &ordered_ops {
                println!("op: {:?}\n", op);
            }

            let old_member_count = member_cgkas.len();

            // FIXME
            // for m in member_cgkas.iter_mut().chain(added_members.iter_mut()) {
            for (m_idx, m) in member_cgkas
                .iter_mut()
                .chain(added_members.iter_mut())
                .enumerate()
            {
                println!("\n\n** Merging for idx {m_idx}");
                for (id, op) in &ordered_ops {
                    // FIXME
                    if m_idx >= old_member_count {
                        if let CgkaOperation::Add { added_id, .. } = op {
                            println!("\n\nadded_id: {:?}, m.id: {:?}", added_id, m.id());
                            if *added_id == m.id() {
                                continue;
                            }
                        } else {
                            println!("NO ADD!");
                        }
                    } else {
                        println!("NOT BIGGER THAN OLD MEMBER COUNT");
                    }
                    if *id != m.id() {
                        m.cgka.merge_concurrent_operation(op)?;
                    }
                }

                // FIXME
                // m.cgka.merge_concurrent_operations(
                //     &(ordered_ops
                //         .iter()
                //         // FIXME: For if we don't rewind
                //         // .filter(|(id, op)| {
                //         //     *id != m.id()
                //         // } )
                //         .map(|(_id, op)| op.clone())
                //         .collect::<Vec<_>>()),
                // )?;
            }
        }
        TestMergeStrategy::MergeToOneMemberAndClone => {
            // FIXME
            // member_cgkas[0].cgka.replace_tree(&starting_cgkas[0].cgka);
            let m_id = member_cgkas[0].id();
            println!("apply_test_operations 3a: merge in ops to 0");
            for (id, op) in &ordered_ops {
                if *id != m_id {
                    member_cgkas[0].cgka.merge_concurrent_operation(op)?;
                }
            }

            // FIXME
            // member_cgkas[0].cgka.merge_concurrent_operations(
            //     &(ordered_ops
            //         .iter()
            //         // FIXME: For if we don't rewind
            //         // .filter(|(id, op)| *id != m_id)
            //         .map(|(_id, op)| op.clone())
            //         .collect::<Vec<_>>()),
            // )?;
            let base_cgka = member_cgkas[0].cgka.clone();
            println!("apply_test_operations 3b: merge in ops to everyone");
            for m in member_cgkas
                .iter_mut()
                .chain(added_members.iter_mut())
                .skip(1)
            {
                m.update_cgka_to(&base_cgka)?;
            }
        }
    }

    println!("apply_test_operations 4: added_members");
    for m in added_members {
        if cancelled_adds.contains(&m.id()) {
            continue;
        }
        member_cgkas.push(m.clone());
    }
    Ok(())
}

/// Apply test operations and then rewind all members and merge these
/// operations in a deterministic order into all of them.
pub fn apply_test_operations_rewind_and_merge_to_all(
    member_cgkas: &mut Vec<TestMemberCgka>,
    test_operations: &[Box<TestOperation>],
) -> Result<(), CgkaError> {
    apply_test_operations(
        member_cgkas,
        test_operations,
        TestMergeStrategy::MergeToAllMembers,
    )
}

/// Apply test operations, merge them into one member, and clone that tree
/// for other
pub fn apply_test_operations_and_merge(
    member_cgkas: &mut Vec<TestMemberCgka>,
    test_operations: &[Box<TestOperation>],
) -> Result<(), CgkaError> {
    apply_test_operations(
        member_cgkas,
        test_operations,
        TestMergeStrategy::MergeToOneMemberAndClone,
    )
}

pub fn setup_member_cgkas_with_maximum_conflict_keys(
    doc_id: DocumentId,
    member_count: u32,
) -> Result<Vec<TestMemberCgka>, CgkaError> {
    let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count)?;
    // Every member concurrently updates its own path. When these are all merged,
    // the tree will contain the maximum possible number of conflict keys in inner nodes.
    apply_test_operations_and_merge(&mut member_cgkas, &[update_all_members()])?;
    // The first member updates just its path. There will now be a shared root secret
    // but inner nodes outside that path will still contain the maximum possible number
    // of conflict keys.
    apply_test_operations_and_merge(&mut member_cgkas, &[update_first_member()])?;

    Ok(member_cgkas)
}

pub fn setup_member_cgkas_with_all_updated_and_10_adds(
    doc_id: DocumentId,
    member_count: u32,
) -> Result<Vec<TestMemberCgka>, CgkaError> {
    let add_count = 10;
    debug_assert!(member_count > add_count);
    let member_count = member_count - add_count;
    let (mut member_cgkas, _ops) = setup_updated_and_synced_member_cgkas(doc_id, member_count)?;
    apply_test_operations_and_merge(
        &mut member_cgkas,
        &[add_from_last_n_members(add_count as usize)],
    )?;
    // Update the first member's path and merge into other members so the trees will
    // have a shared root secret.
    apply_test_operations_and_merge(&mut member_cgkas, &[update_first_member()])?;
    Ok(member_cgkas)
}

/////////////////////////////
// Test Operations
/////////////////////////////

pub type TestOperation = dyn Fn(
    &mut Vec<TestMemberCgka>,
    &Cgka,
    &mut Vec<TestMemberCgka>,
    &mut TestConcurrentOperations,
) -> Result<(), CgkaError>;

pub fn add_from_all_members() -> Box<TestOperation> {
    Box::new(move |cgkas, initial_cgka, added_members, ops| {
        for m in cgkas.iter_mut() {
            let new_m = TestMember::generate(&mut rand::thread_rng());
            let mut new_m_cgka = TestMemberCgka::new(new_m, initial_cgka)?;
            let op = m.cgka.add(new_m.id, new_m.pk, &mut rand::thread_rng())?;
            new_m_cgka.cgka.merge_concurrent_operation(&op)?;
            ops.add(m.id(), op);
            added_members.push(new_m_cgka);
        }
        Ok(())
    })
}

pub fn add_from_last_n_members(n: usize) -> Box<TestOperation> {
    Box::new(move |cgkas, initial_cgka, added_members, ops| {
        debug_assert!(n < cgkas.len());
        println!("add_from_last_n_members");
        let skip_count = cgkas.len() - n;
        // FIXME
        // for m in cgkas.iter_mut().skip(skip_count) {
        for (idx, m) in cgkas.iter_mut().skip(skip_count).enumerate() {
            println!("--TestMember::gen--");
            let new_m = TestMember::generate(&mut rand::thread_rng());
            println!("--TestMemberCgka::new--");
            let mut new_m_cgka = TestMemberCgka::new(new_m, initial_cgka)?;
            println!("Adding from member idx {idx}");
            let op = m.cgka.add(new_m.id, new_m.pk, &mut rand::thread_rng())?;
            new_m_cgka.cgka.merge_concurrent_operation(&op)?;
            ops.add(m.id(), op);
            added_members.push(new_m_cgka);
        }
        println!("cool");
        Ok(())
    })
}

pub fn add_from_first_member() -> Box<TestOperation> {
    Box::new(move |cgkas, initial_cgka, added_members, ops| {
        let new_m = TestMember::generate(&mut rand::thread_rng());
        let mut new_m_cgka = TestMemberCgka::new(new_m, initial_cgka)?;
        let adder = &mut cgkas[0];
        println!("--- Adder id {:?} added id {:?}", adder.id(), new_m.id);
        let op = adder
            .cgka
            .add(new_m.id, new_m.pk, &mut rand::thread_rng())?;
        new_m_cgka.cgka.merge_concurrent_operation(&op)?;
        ops.add(adder.id(), op);
        added_members.push(new_m_cgka);
        Ok(())
    })
}

pub fn remove_from_left(n: usize) -> Box<TestOperation> {
    Box::new(move |cgkas, _initial_cgka, _added_members, ops| {
        let n = if n >= cgkas.len() - 1 {
            cgkas.len() - 1
        } else {
            n
        };
        let mut post_remove_cgkas = Vec::new();
        let mut ids_to_remove = Vec::new();
        for m in cgkas.iter().take(n) {
            ids_to_remove.push(m.id());
        }
        for m in cgkas.iter().skip(n) {
            post_remove_cgkas.push(m.clone());
        }
        for id in ids_to_remove {
            let mut remover = post_remove_cgkas[0].clone();
            let op = remover.cgka.remove(id, &mut rand::thread_rng())?;
            ops.add(remover.id(), op);
        }
        mem::swap(cgkas, &mut post_remove_cgkas);
        Ok(())
    })
}

pub fn remove_from_right(n: usize) -> Box<TestOperation> {
    Box::new(move |cgkas, _initial_cgka, _added_members, ops| {
        let n = if n >= cgkas.len() - 1 {
            cgkas.len() - 1
        } else {
            n
        };
        let mut ids_to_remove = Vec::new();
        for _ in 0..n {
            let m = cgkas.pop().unwrap();
            ids_to_remove.push(m.id());
        }
        for id in ids_to_remove {
            let mut remover = cgkas[0].clone();
            let op = remover.cgka.remove(id, &mut rand::thread_rng())?;
            ops.add(remover.id(), op);
        }
        Ok(())
    })
}

pub fn remove_odd_members() -> Box<TestOperation> {
    Box::new(move |cgkas, _initial_cgka, _added_members, ops| {
        let mut post_remove_cgkas = Vec::new();
        let mut ids_to_remove = Vec::new();
        for (idx, m) in cgkas.iter_mut().enumerate() {
            if idx % 2 == 0 {
                post_remove_cgkas.push(m.clone());
            } else {
                ids_to_remove.push(m.id());
            }
        }
        for id in ids_to_remove {
            let mut remover = post_remove_cgkas[0].clone();
            let op = remover.cgka.remove(id, &mut rand::thread_rng())?;
            ops.add(remover.id(), op);
        }
        mem::swap(cgkas, &mut post_remove_cgkas);
        Ok(())
    })
}

pub fn update_all_members() -> Box<TestOperation> {
    Box::new(move |cgkas, _initial_cgka, _added_members, ops| {
        for m in cgkas.iter_mut() {
            let next_op = m.update(&mut rand::thread_rng())?;
            ops.add(m.id(), next_op);
        }
        Ok(())
    })
}

pub fn update_first_member() -> Box<TestOperation> {
    Box::new(move |cgkas, _initial_cgka, _added_members, ops| {
        let id = cgkas[0].id();
        ops.add(id, cgkas[0].update(&mut rand::thread_rng())?);
        Ok(())
    })
}

pub fn update_even_members() -> Box<TestOperation> {
    Box::new(move |cgkas, _initial_cgka, _added_members, ops| {
        for (idx, m) in cgkas.iter_mut().enumerate() {
            if idx % 2 != 0 {
                continue;
            }
            let next_op = m.update(&mut rand::thread_rng())?;
            ops.add(m.id(), next_op);
        }
        Ok(())
    })
}

pub fn update_added_members() -> Box<TestOperation> {
    Box::new(move |_cgkas, _initial_cgka, added_members, ops| {
        for m in added_members {
            let next_op = m.update(&mut rand::thread_rng())?;
            ops.add_to_added_member_ops(m.id(), next_op);
        }
        Ok(())
    })
}

#[allow(dead_code)]
#[cfg(any(feature = "test_utils", test))]
fn check_same_secret_as_first(member_cgkas: &mut Vec<TestMemberCgka>, ops: &Vec<CgkaOperation>) -> Result<(), CgkaError> {
    println!("__check_same_secret_as_first()");
    let pcs_key = member_cgkas[0].cgka.derive_pcs_key()?;
    let pcs_key_hash = Digest::hash(&pcs_key);
    let op_hash = Digest::hash(ops.last().expect("update op"));
    for m in member_cgkas.iter_mut().skip(1) {
        // assert!(m.cgka.has_pcs_key());
        assert_eq!(m.cgka.secret(&pcs_key_hash, &op_hash)?, pcs_key)
    }
    Ok(())
}

#[test]
fn test_setup_member_cgkas() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let member_count = 4;
    println!("\n\n\n\n\n\ntest_setup_member_cgkas(): setup_member_cgkas");
    println!("((((((((((((((((((((((((((((()))))))))))))))))))))))))))))))");
    let (mut member_cgkas, ops) = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    println!("\n\n\n\n\n\ntest_setup_member_cgkas(): check_same_secret_as_first");
    println!("((((((((((((((((((((((((((((()))))))))))))))))))))))))))))))");
    check_same_secret_as_first(&mut member_cgkas, &ops)
}

#[test]
fn test_setup_updated_and_synced_member_cgkas() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let member_count = 4;
    let (mut member_cgkas, ops) = setup_updated_and_synced_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    check_same_secret_as_first(&mut member_cgkas, &ops)
}

#[test]
fn test_setup_add() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let add_count = 2;
    let member_count = 4;
    println!("\nsetup_m_cgkas");
    let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    println!("\napply_test_ops_and_merge");
    apply_test_operations_and_merge(
        &mut member_cgkas,
        &vec![add_from_last_n_members(add_count as usize)],
    )?;
    assert_eq!(member_cgkas.len(), (member_count + add_count) as usize);
    Ok(())
}

#[test]
fn test_setup_remove() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let remove_count = 2;
    let member_count = 4;

    let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);

    apply_test_operations_and_merge(
        &mut member_cgkas,
        &vec![remove_from_right(remove_count as usize)],
    )?;

    assert_eq!(member_cgkas.len(), (member_count - remove_count) as usize);
    Ok(())
}

#[test]
fn test_setup_update() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let member_count = 4;
    let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    apply_test_operations_and_merge(&mut member_cgkas, &vec![update_first_member()])?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    Ok(())
}
