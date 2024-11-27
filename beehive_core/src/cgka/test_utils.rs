use super::{error::CgkaError, operation::CgkaOperation, Cgka};
use crate::{
    crypto::share_key::{ShareKey, ShareSecretKey},
    cgka::keys::ShareKeyMap,
    principal::{document::id::DocumentId, identifier::Identifier, individual::id::IndividualId},
};
use nonempty::{nonempty, NonEmpty};
use std::{collections::HashMap, mem};

pub type TestContentRef = u32;

#[derive(Debug, Clone)]
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
        cgka.with_new_owner(self.id, self.pk, sks)
    }
}

#[derive(Clone, Debug)]
pub struct TestMemberCgka {
    pub m: TestMember,
    pub cgka: Cgka,
    pub is_removed: bool,
}

impl TestMemberCgka {
    pub fn new(m: TestMember, cgka: Cgka) -> Self {
        Self {
            m,
            cgka,
            is_removed: false,
        }
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
        self.cgka.update(pk, sk, csprng)
    }

    pub fn update_cgka_to(&mut self, cgka: &Cgka) -> Result<(), CgkaError> {
        let sks = self.cgka.owner_sks.clone();
        self.cgka = cgka.with_new_owner(self.id(), self.m.pk, sks)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestConcurrentOperations {
    pub ops: HashMap<IndividualId, Vec<CgkaOperation>>,
}

impl TestConcurrentOperations {
    pub fn new() -> Self {
        Self {
            ops: Default::default(),
        }
    }

    pub fn add(&mut self, member_id: IndividualId, op: CgkaOperation) {
        match op {
            CgkaOperation::Remove { id, removed_keys } => {
                self.ops
                    .entry(member_id)
                    .or_default()
                    .push(CgkaOperation::Remove { id, removed_keys });
            }
            _ => {
                self.ops.entry(member_id).or_default().push(op);
            }
        }
    }

    pub fn ordered(&mut self) -> Vec<CgkaOperation> {
        // TODO: This doesn't randomly intersperse the operations but just
        // places them in order of one member's list of concurrent ops after another.
        self.ops
            .iter()
            .flat_map(|(id, ops)| (0..ops.len()).map(|n| (*id, n)).collect::<Vec<_>>())
            .map(|(id, idx)| self.ops.get(&id).unwrap()[idx].clone())
            .collect()
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

pub fn setup_cgka(doc_id: DocumentId, members: &NonEmpty<TestMember>, m_idx: usize) -> Cgka {
    let owner = &members[m_idx];
    let first: (IndividualId, ShareKey) = (members.first().id, members.first().pk);
    let member_id_pks = NonEmpty::from((
        first,
        members.iter().skip(1).map(|p| (p.id, p.pk)).collect(),
    ));

    Cgka::new(
        member_id_pks,
        doc_id,
        owner.id,
        owner.pk,
        owner.sk,
        &mut rand::thread_rng(),
    )
    .expect("CGKA construction failed")
}

/// Set up cgkas for all members with the same secret, but only the initial member
/// has updated its path.
pub fn setup_member_cgkas(
    doc_id: DocumentId,
    member_count: u32,
) -> Result<Vec<TestMemberCgka>, CgkaError> {
    let members = setup_members(member_count);
    let initial_cgka = setup_cgka(doc_id, &members, 0);
    let mut member_cgkas = Vec::new();
    for m in members {
        let cgka = m.cgka_from(&initial_cgka)?;
        member_cgkas.push(TestMemberCgka::new(m.clone(), cgka));
    }
    Ok(member_cgkas)
}

/// Set up cgkas for all members with the same secret, with every member
/// having updated its path and no conflict keys in the inner nodes.
pub fn setup_updated_and_synced_member_cgkas(
    doc_id: DocumentId,
    member_count: u32,
) -> Result<Vec<TestMemberCgka>, CgkaError> {
    let mut members = setup_members(member_count);
    let initial_cgka = setup_cgka(doc_id, &members, 0);
    let mut member_cgkas = vec![TestMemberCgka::new(members[0].clone(), initial_cgka)];
    for m in members.iter_mut().skip(1) {
        let cgka = m.cgka_from(&member_cgkas[0].cgka)?;
        let mut member_cgka = TestMemberCgka::new(m.clone(), cgka);
        let op = member_cgka.update(&mut rand::thread_rng())?;
        member_cgkas[0].cgka.merge_concurrent_operations(&vec![op])?;
        member_cgkas.push(member_cgka);
    }
    let base_cgka = member_cgkas[0].cgka.clone();
    for m in member_cgkas.iter_mut().skip(1) {
        m.update_cgka_to(&base_cgka)?;
    }

    Ok(member_cgkas)
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
    let mut ops = TestConcurrentOperations::new();
    let starting_cgkas = member_cgkas.clone();
    let mut added_members = Vec::new();
    for test_op in test_operations {
        test_op(member_cgkas, &mut added_members, &mut ops)?;
    }
    let ordered_ops = ops.ordered();

    match test_merge_strategy {
        TestMergeStrategy::MergeToAllMembers => {
            // For each member, we go back to the original CGKA versions and apply
            // this set of changes.
            for (idx, m) in member_cgkas.iter_mut().enumerate() {
                m.cgka.replace_tree(&starting_cgkas[idx].cgka);
            }
            for m in member_cgkas.iter_mut() {
                m.cgka.merge_concurrent_operations(&ordered_ops)?;
            }
        }
        TestMergeStrategy::MergeToOneMemberAndClone => {
            member_cgkas[0].cgka.replace_tree(&starting_cgkas[0].cgka);
            member_cgkas[0].cgka.merge_concurrent_operations(&ordered_ops)?;
            let base_cgka = member_cgkas[0].cgka.clone();
            for m in member_cgkas.iter_mut().skip(1) {
                m.update_cgka_to(&base_cgka)?;
            }
        }
    }

    for m in added_members {
        let new_m_cgka = m.cgka_from(&member_cgkas[0].cgka)?;
        member_cgkas.push(TestMemberCgka::new(m.clone(), new_m_cgka));
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
    let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
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
    let mut member_cgkas = setup_updated_and_synced_member_cgkas(doc_id, member_count)?;
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
    &mut Vec<TestMember>,
    &mut TestConcurrentOperations,
) -> Result<(), CgkaError>;

pub fn add_from_all_members() -> Box<TestOperation> {
    Box::new(move |cgkas, added_members, ops| {
        for m in cgkas.iter_mut() {
            let new_m = TestMember::generate(&mut rand::thread_rng());
            let op = m.cgka.add(new_m.id, new_m.pk)?;
            ops.add(m.id(), op);
            added_members.push(new_m);
        }
        Ok(())
    })
}

pub fn add_from_last_n_members(n: usize) -> Box<TestOperation> {
    Box::new(move |cgkas, added_members, ops| {
        debug_assert!(n < cgkas.len());
        let skip_count = cgkas.len() - n;
        for m in cgkas.iter_mut().skip(skip_count) {
            let new_m = TestMember::generate(&mut rand::thread_rng());
            let op = m.cgka.add(new_m.id, new_m.pk)?;
            ops.add(m.id(), op);
            added_members.push(new_m);
        }
        Ok(())
    })
}

pub fn add_from_first_member() -> Box<TestOperation> {
    Box::new(move |cgkas, added_members, ops| {
        let new_m = TestMember::generate(&mut rand::thread_rng());
        let adder = &mut cgkas[0];
        let op = adder.cgka.add(new_m.id, new_m.pk)?;
        ops.add(adder.id(), op);
        added_members.push(new_m);
        Ok(())
    })
}

pub fn remove_from_left(n: usize) -> Box<TestOperation> {
    Box::new(move |cgkas, _added_members, ops| {
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
            let op = remover.cgka.remove(id)?;
            ops.add(remover.id(), op);
        }
        mem::swap(cgkas, &mut post_remove_cgkas);
        Ok(())
    })
}

pub fn remove_from_right(n: usize) -> Box<TestOperation> {
    Box::new(move |cgkas, _added_members, ops| {
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
            let op = remover.cgka.remove(id)?;
            ops.add(remover.id(), op);
        }
        Ok(())
    })
}

pub fn remove_odd_members() -> Box<TestOperation> {
    Box::new(move |cgkas, _added_members, ops| {
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
            let op = remover.cgka.remove(id)?;
            ops.add(remover.id(), op);
        }
        mem::swap(cgkas, &mut post_remove_cgkas);
        Ok(())
    })
}

pub fn update_all_members() -> Box<TestOperation> {
    Box::new(move |cgkas, _added_members, ops| {
        for m in cgkas.iter_mut() {
            let next_op = m.update(&mut rand::thread_rng())?;
            ops.add(m.id(), next_op);
        }
        Ok(())
    })
}

pub fn update_first_member() -> Box<TestOperation> {
    Box::new(move |cgkas, _added_members, ops| {
        let id = cgkas[0].id();
        ops.add(id, cgkas[0].update(&mut rand::thread_rng())?);
        Ok(())
    })
}

pub fn update_even_members() -> Box<TestOperation> {
    Box::new(move |cgkas, _added_members, ops| {
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

#[allow(dead_code)]
#[cfg(any(feature = "test_utils", test))]
fn check_same_secret(member_cgkas: &mut Vec<TestMemberCgka>) -> Result<(), CgkaError> {
    let secret_bytes = member_cgkas[0].cgka.secret()?.to_bytes();
    for m in member_cgkas.iter_mut().skip(1) {
        assert!(m.cgka.has_pcs_key());
        assert_eq!(m.cgka.secret()?.to_bytes(), secret_bytes)
    }
    Ok(())
}

#[test]
fn test_setup_member_cgkas() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let member_count = 4;
    let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    check_same_secret(&mut member_cgkas)
}

#[test]
fn test_setup_updated_and_synced_member_cgkas() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let member_count = 4;
    let mut member_cgkas = setup_updated_and_synced_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    check_same_secret(&mut member_cgkas)
}

#[test]
fn test_setup_add() -> Result<(), CgkaError> {
    let doc_id = DocumentId::generate(&mut rand::thread_rng());
    let add_count = 2;
    let member_count = 4;
    let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
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

    let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
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
    let mut member_cgkas = setup_member_cgkas(doc_id, member_count)?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    apply_test_operations_and_merge(&mut member_cgkas, &vec![update_first_member()])?;
    assert_eq!(member_cgkas.len(), member_count as usize);
    Ok(())
}
