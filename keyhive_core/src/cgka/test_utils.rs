// use super::{error::CgkaError, operation::CgkaOperation, Cgka};
// use crate::{
//     cgka::keys::ShareKeyMap,
//     crypto::{
//         application_secret::PcsKey,
//         digest::Digest,
//         share_key::{ShareKey, ShareSecretKey},
//         signed::Signed,
//     },
//     principal::{document::id::DocumentId, identifier::Identifier, individual::id::IndividualId},
// };
// use nonempty::{nonempty, NonEmpty};
// use rand::{rngs::OsRng, Rng};
// use std::{
//     collections::{HashMap, HashSet, VecDeque},
//     future::Future,
//     mem,
//     sync::Arc
// };
//
// pub type TestContentRef = u32;
//
// #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
// pub struct TestMember {
//     pub id: IndividualId,
//     pub pk: ShareKey,
//     pub sk: ShareSecretKey,
// }
//
// impl TestMember {
//     pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
//         let id = IndividualId(Identifier::generate(csprng));
//         let sk = ShareSecretKey::generate(csprng);
//         let pk = sk.share_key();
//         Self { id, pk, sk }
//     }
//
//     pub fn cgka_from(&self, cgka: &Cgka) -> Result<Cgka, CgkaError> {
//         let mut sks = ShareKeyMap::new();
//         sks.insert(self.pk, self.sk);
//         cgka.with_new_owner(self.id, sks)
//     }
// }
//
// #[derive(Clone, Debug)]
// pub struct TestMemberCgka {
//     pub m: TestMember,
//     pub cgka: Cgka,
// }
//
// impl TestMemberCgka {
//     pub fn new(m: TestMember, other_cgka: &Cgka) -> Result<Self, CgkaError> {
//         let cgka = m.cgka_from(&other_cgka)?;
//         Ok(Self { m, cgka })
//     }
//
//     pub fn id(&self) -> IndividualId {
//         self.m.id
//     }
//
//     pub async fn update<R: rand::CryptoRng + rand::RngCore>(
//         &mut self,
//         signing_key: &ed25519_dalek::SigningKey,
//         csprng: &mut R,
//     ) -> Result<(PcsKey, Signed<CgkaOperation>), CgkaError> {
//         let sk = ShareSecretKey::generate(csprng);
//         let pk = sk.share_key();
//         self.m.pk = pk;
//         self.m.sk = sk;
//         self.cgka.update(pk, sk, signing_key, csprng).await
//     }
//
//     pub fn update_cgka_to(&mut self, cgka: &Cgka) -> Result<(), CgkaError> {
//         let sks = self.cgka.owner_sks.clone();
//         self.cgka = cgka.with_new_owner(self.id(), sks)?;
//         Ok(())
//     }
// }
//
// #[derive(Debug, Default, Clone)]
// pub struct TestConcurrentOperations {
//     pub ops: HashMap<IndividualId, VecDeque<Signed<CgkaOperation>>>,
//     // This is distinguished so that we can ensure added member ops are ordered after
//     // the ops of members that added them.
//     pub added_member_ops: HashMap<IndividualId, VecDeque<Signed<CgkaOperation>>>,
// }
//
// impl TestConcurrentOperations {
//     pub fn new() -> Self {
//         Self {
//             ops: HashMap::new(),
//             added_member_ops: HashMap::new(),
//         }
//     }
//
//     pub fn add(&mut self, member_id: IndividualId, op: Signed<CgkaOperation>) {
//         self.ops.entry(member_id).or_default().push_back(op);
//     }
//
//     pub fn add_to_added_member_ops(&mut self, member_id: IndividualId, op: Signed<CgkaOperation>) {
//         self.added_member_ops
//             .entry(member_id)
//             .or_default()
//             .push_back(op);
//     }
//
//     /// Interweave concurrent ops from all members while maintaining order within each
//     /// member's ops. The relative ordering of concurrent ops is randomized each time.
//     /// The cancelled adds help simulate the fact that Keyhive will not
//     /// apply operations for a member after removing that member.
//     pub fn simulated_ordering_with_cancelled_adds(
//         &mut self,
//     ) -> (
//         Vec<(IndividualId, Signed<CgkaOperation>)>,
//         HashSet<IndividualId>,
//     ) {
//         let mut cancelled_adds = HashSet::new();
//         let mut member_ops: Vec<(IndividualId, VecDeque<Signed<CgkaOperation>>)> = self
//             .ops
//             .iter()
//             .map(|(id, ops)| (*id, ops.clone()))
//             .collect::<Vec<_>>();
//         let mut ops = Vec::new();
//         let mut removed_ids = HashSet::new();
//         while !member_ops.is_empty() {
//             let idx = OsRng.gen_range(0..member_ops.len());
//             let (m_id, ref mut next_member_ops) = &mut member_ops[idx];
//             if let Some(next_op) = next_member_ops.pop_front() {
//                 if removed_ids.contains(m_id) {
//                     if let CgkaOperation::Add { added_id, .. } = next_op.payload {
//                         cancelled_adds.insert(added_id);
//                     }
//                 } else {
//                     if let CgkaOperation::Remove { id, .. } = next_op.payload {
//                         removed_ids.insert(id);
//                     }
//                     ops.push((*m_id, next_op));
//                 }
//             }
//             if next_member_ops.is_empty() {
//                 member_ops.remove(idx);
//             }
//         }
//         for (id, added_member_ops) in &self.added_member_ops {
//             if !removed_ids.contains(&id) {
//                 for op in added_member_ops {
//                     ops.push((*id, op.clone()))
//                 }
//             }
//         }
//         (ops, cancelled_adds)
//     }
// }
//
// pub fn setup_members(member_count: u32) -> NonEmpty<TestMember> {
//     assert!(member_count > 0);
//     let mut csprng = rand::rngs::OsRng;
//     let mut ms = nonempty![TestMember::generate(&mut csprng)];
//     for _ in 1..member_count {
//         ms.push(TestMember::generate(&mut csprng));
//     }
//     ms
// }
//
// pub async fn setup_cgka(
//     doc_id: DocumentId,
//     members: &NonEmpty<TestMember>,
//     m_idx: usize,
//     signing_key: &ed25519_dalek::SigningKey,
// ) -> (Cgka, Vec<Signed<CgkaOperation>>) {
//     let owner = &members[m_idx];
//     let first = members.first().clone();
//     let mut cgka = Cgka::new(doc_id, first.id, first.pk).expect("CGKA construction failed");
//     let mut ops = Vec::new();
//     if members.len() > 1 {
//         ops = cgka
//             .add_multiple(
//                 NonEmpty::from_vec(
//                     members
//                         .iter()
//                         .skip(1)
//                         .map(|p| (p.id, p.pk))
//                         .collect::<Vec<_>>(),
//                 )
//                 .expect("there to be extra members"),
//                 signing_key,
//             )
//             .await
//             .expect("there to be extra members");
//     }
//
//     let mut owner_sks = ShareKeyMap::new();
//     owner_sks.insert(owner.pk, owner.sk);
//     let mut cgka = cgka
//         .with_new_owner(owner.id, owner_sks)
//         .expect("CGKA construction failed");
//     let (_pcs_key, op) = cgka
//         .update(owner.pk, owner.sk, signing_key, &mut rand::rngs::OsRng)
//         .await
//         .expect("CGKA update to succeed");
//     ops.push(op);
//     (cgka, ops)
// }
//
// /// Set up cgkas for all members with the same secret, but only the initial member
// /// has updated its path.
// pub async fn setup_member_cgkas(
//     doc_id: DocumentId,
//     member_count: u32,
//     signing_key: &ed25519_dalek::SigningKey,
// ) -> Result<(Vec<TestMemberCgka>, Vec<Signed<CgkaOperation>>), CgkaError> {
//     let members = setup_members(member_count);
//     let (initial_cgka, ops) = setup_cgka(doc_id, &members, 0, signing_key).await;
//     let mut member_cgkas = Vec::new();
//     for m in members {
//         member_cgkas.push(TestMemberCgka::new(m.clone(), &initial_cgka)?);
//     }
//     Ok((member_cgkas, ops))
// }
//
// /// Set up cgkas for all members with the same secret, with every member
// /// having updated its path and no conflict keys in the inner nodes.
// pub async fn setup_updated_and_synced_member_cgkas(
//     doc_id: DocumentId,
//     member_count: u32,
//     signing_key: &ed25519_dalek::SigningKey,
// ) -> Result<(Vec<TestMemberCgka>, Vec<Signed<CgkaOperation>>), CgkaError> {
//     let mut members = setup_members(member_count);
//     let (initial_cgka, mut ops) = setup_cgka(doc_id, &members, 0, signing_key).await;
//     let mut member_cgkas = vec![TestMemberCgka::new(members[0].clone(), &initial_cgka)?];
//     for m in members.iter_mut().skip(1) {
//         let mut member_cgka = TestMemberCgka::new(m.clone(), &member_cgkas[0].cgka)?;
//         let (_pcs_key, op) = member_cgka
//             .update(signing_key, &mut rand::rngs::OsRng)
//             .await?;
//         ops.push(op.clone());
//         member_cgkas[0]
//             .cgka
//             .merge_concurrent_operation(Arc::new(op))?;
//         member_cgkas.push(member_cgka);
//     }
//     let base_cgka = member_cgkas[0].cgka.clone();
//     for m in member_cgkas.iter_mut().skip(1) {
//         m.update_cgka_to(&base_cgka)?;
//     }
//
//     Ok((member_cgkas, ops))
// }
//
// #[derive(Debug, Clone)]
// pub enum TestMergeStrategy {
//     MergeToAllMembers,
//     MergeToOneMemberAndClone,
// }
//
// pub async fn apply_test_operations<Fut: Future<Output = Result<(), CgkaError>>>(
//     member_cgkas: &mut Vec<TestMemberCgka>,
//     test_operations: &[Box<TestOperation<Fut>>],
//     test_merge_strategy: TestMergeStrategy,
// ) -> Result<(), CgkaError> {
//     let mut ops = TestConcurrentOperations::new();
//     let mut added_members = Vec::new();
//     for test_op in test_operations {
//         test_op(member_cgkas, &mut added_members, &mut ops).await?;
//     }
//     let (ordered_ops, cancelled_adds) = ops.simulated_ordering_with_cancelled_adds();
//     match test_merge_strategy {
//         TestMergeStrategy::MergeToAllMembers => {
//             for m in member_cgkas.iter_mut().chain(added_members.iter_mut()) {
//                 for (id, op) in &ordered_ops {
//                     if *id != m.id() {
//                         m.cgka.merge_concurrent_operation(Arc::new(op.clone()))?;
//                     }
//                 }
//             }
//         }
//         TestMergeStrategy::MergeToOneMemberAndClone => {
//             let m_id = member_cgkas[0].id();
//             for (id, op) in &ordered_ops {
//                 if *id != m_id {
//                     member_cgkas[0]
//                         .cgka
//                         .merge_concurrent_operation(Arc::new(op.clone()))?;
//                 }
//             }
//             let base_cgka = member_cgkas[0].cgka.clone();
//             for m in member_cgkas.iter_mut().skip(1) {
//                 m.update_cgka_to(&base_cgka)?;
//             }
//         }
//     }
//
//     for m in added_members {
//         if cancelled_adds.contains(&m.id()) {
//             continue;
//         }
//         member_cgkas.push(m.clone());
//     }
//     Ok(())
// }
//
// /// Apply test operations and then rewind all members and merge these
// /// operations in a deterministic order into all of them.
// pub async fn apply_test_operations_and_merge_to_all<Fut: Future<Output = Result<(), CgkaError>>>(
//     member_cgkas: &mut Vec<TestMemberCgka>,
//     test_operations: &[Box<TestOperation<Fut>>],
// ) -> Result<(), CgkaError> {
//     apply_test_operations(
//         member_cgkas,
//         test_operations,
//         TestMergeStrategy::MergeToAllMembers,
//     )
//     .await
// }
//
// /// Apply test operations, merge them into one member, and clone that tree
// /// for other
// pub fn apply_test_operations_and_clone<Fut: Future<Output = Result<(), CgkaError>>>(
//     member_cgkas: &mut Vec<TestMemberCgka>,
//     test_operations: &[Box<TestOperation<Fut>>],
// ) -> Result<(), CgkaError> {
//     apply_test_operations(
//         member_cgkas,
//         test_operations,
//         TestMergeStrategy::MergeToOneMemberAndClone,
//     )
// }
//
// pub async fn setup_member_cgkas_with_maximum_conflict_keys(
//     doc_id: DocumentId,
//     member_count: u32,
//     signing_key: &ed25519_dalek::SigningKey,
// ) -> Result<Vec<TestMemberCgka>, CgkaError> {
//     let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count, signing_key).await?;
//     // Every member concurrently updates its own path. When these are all merged,
//     // the tree will contain the maximum possible number of conflict keys in inner nodes.
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &[update_all_members(signing_key.clone()).await],
//     )?;
//     // The first member updates just its path. There will now be a shared root secret
//     // but inner nodes outside that path will still contain the maximum possible number
//     // of conflict keys.
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &[update_first_member(signing_key.clone())],
//     )?;
//
//     Ok(member_cgkas)
// }
//
// pub async fn setup_member_cgkas_with_all_updated_and_10_adds(
//     doc_id: DocumentId,
//     member_count: u32,
//     signing_key: &ed25519_dalek::SigningKey,
// ) -> Result<Vec<TestMemberCgka>, CgkaError> {
//     let add_count = 10;
//     debug_assert!(member_count > add_count);
//     let member_count = member_count - add_count;
//     let (mut member_cgkas, _ops) =
//         setup_updated_and_synced_member_cgkas(doc_id, member_count, signing_key).await?;
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &[add_from_last_n_members(add_count as usize, signing_key.clone()).await],
//     )?;
//     // Update the first member's path and merge into other members so the trees will
//     // have a shared root secret.
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &[update_first_member(signing_key.clone())],
//     )?;
//     Ok(member_cgkas)
// }
//
// /////////////////////////////
// // Test Operations
// /////////////////////////////
//
// pub type TestOperation<Fut: Future<Output = Result<(), CgkaError>>> = dyn Fn(
//     &mut Vec<TestMemberCgka>,
//     &mut Vec<TestMemberCgka>,
//     &mut TestConcurrentOperations,
// ) -> Fut;
//
// pub async fn add_from_all_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, added_members, ops| async {
//         for m in cgkas.iter_mut() {
//             let new_m = TestMember::generate(&mut rand::rngs::OsRng);
//             let op = m.cgka.add(new_m.id, new_m.pk, &signing_key).await?.unwrap();
//             ops.add(m.id(), op);
//             let new_m_cgka = TestMemberCgka::new(new_m, &m.cgka)?;
//             added_members.push(new_m_cgka);
//         }
//         Ok(())
//     })
// }
//
// pub async fn add_from_last_n_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     n: usize,
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, added_members, ops| async {
//         debug_assert!(n < cgkas.len());
//         let skip_count = cgkas.len() - n;
//         for m in cgkas.iter_mut().skip(skip_count) {
//             let new_m = TestMember::generate(&mut rand::rngs::OsRng);
//             let op = m.cgka.add(new_m.id, new_m.pk, &signing_key).await?.unwrap();
//             ops.add(m.id(), op);
//             let new_m_cgka = TestMemberCgka::new(new_m, &m.cgka)?;
//             added_members.push(new_m_cgka);
//         }
//         Ok(())
//     })
// }
//
// pub fn add_from_first_member<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, added_members, ops| {
//         let new_m = TestMember::generate(&mut rand::rngs::OsRng);
//         let adder = &mut cgkas[0];
//         let op = adder.cgka.add(new_m.id, new_m.pk, &signing_key)?.unwrap();
//         ops.add(adder.id(), op);
//         let new_m_cgka = TestMemberCgka::new(new_m, &adder.cgka)?;
//         added_members.push(new_m_cgka);
//         Ok(())
//     })
// }
//
// pub fn remove_from_left<Fut: Future<Output = Result<(), CgkaError>>>(
//     n: usize,
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         let n = if n >= cgkas.len() - 1 {
//             cgkas.len() - 1
//         } else {
//             n
//         };
//         let mut post_remove_cgkas = Vec::new();
//         let mut ids_to_remove = Vec::new();
//         for m in cgkas.iter().take(n) {
//             ids_to_remove.push(m.id());
//         }
//         for m in cgkas.iter().skip(n) {
//             post_remove_cgkas.push(m.clone());
//         }
//         for id in ids_to_remove {
//             let remover = &mut post_remove_cgkas[0];
//             if let Some(op) = remover.cgka.remove(id, &signing_key)? {
//                 ops.add(remover.id(), op);
//             }
//         }
//         mem::swap(cgkas, &mut post_remove_cgkas);
//         Ok(())
//     })
// }
//
// pub fn remove_from_right<Fut: Future<Output = Result<(), CgkaError>>>(
//     n: usize,
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         let n = if n >= cgkas.len() - 1 {
//             cgkas.len() - 1
//         } else {
//             n
//         };
//         let mut ids_to_remove = Vec::new();
//         for _ in 0..n {
//             let m = cgkas.pop().unwrap();
//             ids_to_remove.push(m.id());
//         }
//         for id in ids_to_remove {
//             let remover = &mut cgkas[0];
//             if let Some(op) = remover.cgka.remove(id, &signing_key)? {
//                 ops.add(remover.id(), op);
//             }
//         }
//         Ok(())
//     })
// }
//
// pub fn remove_odd_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         let mut post_remove_cgkas = Vec::new();
//         let mut ids_to_remove = Vec::new();
//         for (idx, m) in cgkas.iter_mut().enumerate() {
//             if idx % 2 == 0 {
//                 post_remove_cgkas.push(m.clone());
//             } else {
//                 ids_to_remove.push(m.id());
//             }
//         }
//         for id in ids_to_remove {
//             let remover = &mut post_remove_cgkas[0];
//             if let Some(op) = remover.cgka.remove(id, &signing_key)? {
//                 ops.add(remover.id(), op);
//             }
//         }
//         mem::swap(cgkas, &mut post_remove_cgkas);
//         Ok(())
//     })
// }
//
// pub async fn update_all_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         for m in cgkas.iter_mut() {
//             let (_pcs_key, next_op) = m.update(&signing_key, &mut rand::rngs::OsRng)?;
//             ops.add(m.id(), next_op);
//         }
//         Ok(())
//     })
// }
//
// pub fn update_first_member<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         let id = cgkas[0].id();
//         let (_pcs_key, op) = cgkas[0].update(&signing_key, &mut rand::rngs::OsRng)?;
//         ops.add(id, op);
//         Ok(())
//     })
// }
//
// pub fn update_even_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         for (idx, m) in cgkas.iter_mut().enumerate() {
//             if idx % 2 != 0 {
//                 continue;
//             }
//             let (_pcs_key, next_op) = m.update(&signing_key, &mut rand::rngs::OsRng)?;
//             ops.add(m.id(), next_op);
//         }
//         Ok(())
//     })
// }
//
// pub fn update_odd_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |cgkas, _added_members, ops| {
//         for (idx, m) in cgkas.iter_mut().enumerate() {
//             if (idx + 1) % 2 != 0 {
//                 continue;
//             }
//             let (_pcs_key, next_op) = m.update(&signing_key, &mut rand::rngs::OsRng)?;
//             ops.add(m.id(), next_op);
//         }
//         Ok(())
//     })
// }
//
// pub fn update_added_members<Fut: Future<Output = Result<(), CgkaError>>>(
//     signing_key: ed25519_dalek::SigningKey,
// ) -> Box<TestOperation<Fut>> {
//     Box::new(move |_cgkas, added_members, ops| {
//         for m in added_members {
//             let (_pcs_key, next_op) = m.update(&signing_key, &mut rand::rngs::OsRng)?;
//             ops.add_to_added_member_ops(m.id(), next_op);
//         }
//         Ok(())
//     })
// }
//
// #[allow(dead_code)]
// #[cfg(any(feature = "test_utils", test))]
// fn check_same_secret(
//     member_cgkas: &mut Vec<TestMemberCgka>,
//     ops: &Vec<Signed<CgkaOperation>>,
// ) -> Result<(), CgkaError> {
//     let pcs_key = member_cgkas[0].cgka.secret_from_root()?;
//     let pcs_key_hash = Digest::hash(&pcs_key);
//     let op_hash = Digest::hash(ops.last().expect("update op"));
//     for m in member_cgkas.iter_mut().skip(1) {
//         assert_eq!(m.cgka.secret(&pcs_key_hash, &op_hash)?, pcs_key)
//     }
//     Ok(())
// }
//
// #[test]
// fn test_setup_member_cgkas() -> Result<(), CgkaError> {
//     let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//     let doc_id = DocumentId::generate(&mut rand::rngs::OsRng);
//     let member_count = 4;
//     let (mut member_cgkas, ops) = setup_member_cgkas(doc_id, member_count, &signing_key)?;
//     assert_eq!(member_cgkas.len(), member_count as usize);
//     check_same_secret(&mut member_cgkas, &ops)
// }
//
// #[test]
// fn test_setup_updated_and_synced_member_cgkas() -> Result<(), CgkaError> {
//     let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//     let doc_id = DocumentId::generate(&mut rand::rngs::OsRng);
//     let member_count = 4;
//     let (mut member_cgkas, ops) =
//         setup_updated_and_synced_member_cgkas(doc_id, member_count, &signing_key)?;
//     assert_eq!(member_cgkas.len(), member_count as usize);
//     check_same_secret(&mut member_cgkas, &ops)
// }
//
// #[test]
// fn test_setup_add() -> Result<(), CgkaError> {
//     let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//     let doc_id = DocumentId::generate(&mut rand::rngs::OsRng);
//     let add_count = 2;
//     let member_count = 4;
//     let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count, &signing_key)?;
//     assert_eq!(member_cgkas.len(), member_count as usize);
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &vec![add_from_last_n_members(
//             add_count as usize,
//             signing_key.clone(),
//         )],
//     )?;
//     assert_eq!(member_cgkas.len(), (member_count + add_count) as usize);
//     Ok(())
// }
//
// #[test]
// fn test_setup_remove() -> Result<(), CgkaError> {
//     let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//     let doc_id = DocumentId::generate(&mut rand::rngs::OsRng);
//     let remove_count = 2;
//     let member_count = 4;
//
//     let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count, &signing_key)?;
//     assert_eq!(member_cgkas.len(), member_count as usize);
//
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &vec![remove_from_right(
//             remove_count as usize,
//             signing_key.clone(),
//         )],
//     )?;
//
//     assert_eq!(member_cgkas.len(), (member_count - remove_count) as usize);
//     Ok(())
// }
//
// #[test]
// fn test_setup_update() -> Result<(), CgkaError> {
//     let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//     let doc_id = DocumentId::generate(&mut rand::rngs::OsRng);
//     let member_count = 4;
//     let (mut member_cgkas, _ops) = setup_member_cgkas(doc_id, member_count, &signing_key)?;
//     assert_eq!(member_cgkas.len(), member_count as usize);
//     apply_test_operations_and_clone(
//         &mut member_cgkas,
//         &vec![update_first_member(signing_key.clone())],
//     )?;
//     assert_eq!(member_cgkas.len(), member_count as usize);
//     Ok(())
// }
