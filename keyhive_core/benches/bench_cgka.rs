use keyhive_core::crypto::share_key::ShareSecretKey;

fn main() {
    divan::main();
}

#[divan::bench(
    args = [100, 1000]
)]
fn create_key_pairs(n: u32) {
    let mut csprng = rand::rngs::OsRng;
    for _ in 0..n {
        let s = ShareSecretKey::generate(&mut csprng);
        s.share_key();
    }
}

// FIXME
// fn setup_group_and_two_primaries<F>(
//     member_count: u32,
//     paired_idx: usize,
//     setup: F,
// ) -> (TestMemberCgka, TestMemberCgka)
// where
//     F: Fn(u32) -> Result<Vec<TestMemberCgka>, CgkaError>,
// {
//     let mut csprng = rand::rngs::OsRng;
//     let cgkas = setup(member_count).unwrap();
//     let mut first_cgka = cgkas[0].clone();
//     let mut paired_cgka = cgkas[paired_idx].clone();
//     let mut sks = paired_cgka.cgka.owner_sks.clone();
//     sks.insert(paired_cgka.m.pk, paired_cgka.m.sk.clone());
//     paired_cgka.cgka = first_cgka
//         .cgka
//         .with_new_owner(paired_cgka.id(), sks)
//         .unwrap();
//     let (_pcs_key, op) = paired_cgka.update(&mut csprng).unwrap();
//     first_cgka
//         .cgka
//         .merge_concurrent_operation(Rc::new(op))
//         .unwrap();
//     (first_cgka, paired_cgka)
// }
//
// #[divan::bench(
//     args = [31, 255, 511],
//     max_time = Duration::from_secs(120),
// )]
// fn apply_100_updates_and_sibling_decrypt(bencher: Bencher, member_count: u32) {
//     let mut csprng = rand::rngs::OsRng;
//     let doc_id = DocumentId::generate(&mut csprng);
//
//     bencher
//         .with_inputs(|| {
//             let paired_idx = 1;
//             setup_group_and_two_primaries(member_count, paired_idx, |x| {
//                 setup_updated_and_synced_member_cgkas(doc_id, x).map(|(ms, _ops)| ms)
//             })
//         })
//         .bench_local_refs(|(first_cgka, sibling_cgka)| {
//             for _ in 0..100 {
//                 let (_pcs_key, op) = first_cgka.update(&mut csprng).unwrap();
//                 sibling_cgka
//                     .cgka
//                     .merge_concurrent_operation(Rc::new(op))
//                     .unwrap();
//                 sibling_cgka.cgka.secret_from_root().unwrap();
//             }
//         });
// }
//
// #[divan::bench(
//     args = [31, 255, 511],
//     max_time = Duration::from_secs(120),
// )]
// fn apply_100_updates_and_distant_member_decrypt(bencher: Bencher, member_count: u32) {
//     let mut csprng = rand::rngs::OsRng;
//     let doc_id = DocumentId::generate(&mut csprng);
//
//     bencher
//         .with_inputs(|| {
//             let paired_idx = member_count as usize - 1;
//             setup_group_and_two_primaries(member_count, paired_idx, |x| {
//                 setup_updated_and_synced_member_cgkas(doc_id, x).map(|(ms, _ops)| ms)
//             })
//         })
//         .bench_local_refs(|(first_cgka, distant_cgka)| {
//             for _ in 0..100 {
//                 let (_pcs_key, op) = first_cgka.update(&mut csprng).unwrap();
//                 distant_cgka
//                     .cgka
//                     .merge_concurrent_operation(Rc::new(op))
//                     .unwrap();
//                 distant_cgka.cgka.secret_from_root().unwrap();
//             }
//         });
// }
//
// #[divan::bench(
//     args = [31, 255, 511],
//     max_time = Duration::from_secs(120),
// )]
// fn apply_100_updates_and_distant_member_decrypt_with_maximum_conflict_keys(
//     bencher: Bencher,
//     member_count: u32,
// ) {
//     let mut csprng = rand::rngs::OsRng;
//     let doc_id = DocumentId::generate(&mut csprng);
//
//     bencher
//         .with_inputs(|| {
//             let paired_idx = member_count as usize - 1;
//             setup_group_and_two_primaries(member_count, paired_idx, |x| {
//                 setup_member_cgkas_with_maximum_conflict_keys(doc_id, x)
//             })
//         })
//         .bench_local_refs(|(first_cgka, distant_cgka)| {
//             for _ in 0..100 {
//                 let (_pcs_key, op) = first_cgka.update(&mut csprng).unwrap();
//                 distant_cgka
//                     .cgka
//                     .merge_concurrent_operation(Rc::new(op))
//                     .unwrap();
//                 distant_cgka.cgka.secret_from_root().unwrap();
//             }
//         });
// }
//
// #[divan::bench(
//     args = [31, 255, 511],
//     max_time = Duration::from_secs(120),
// )]
// fn apply_100_updates_and_distant_member_decrypt_after_adds(bencher: Bencher, member_count: u32) {
//     let mut csprng = rand::rngs::OsRng;
//     let doc_id = DocumentId::generate(&mut csprng);
//
//     bencher
//         .with_inputs(|| {
//             let paired_idx = member_count as usize - 1;
//             setup_group_and_two_primaries(member_count, paired_idx, |x| {
//                 setup_member_cgkas_with_all_updated_and_10_adds(doc_id, x)
//             })
//         })
//         .bench_local_refs(|(first_cgka, distant_cgka)| {
//             for _ in 0..100 {
//                 let (_pcs_key, op) = first_cgka.update(&mut csprng).unwrap();
//                 distant_cgka
//                     .cgka
//                     .merge_concurrent_operation(Rc::new(op))
//                     .unwrap();
//                 distant_cgka.cgka.secret_from_root().unwrap();
//             }
//         });
// }
//
// #[divan::bench(
//     args = [31, 255, 511],
//     max_time = Duration::from_secs(120),
// )]
// fn apply_100_updates_and_distant_member_decrypt_with_blank_nodes(
//     bencher: Bencher,
//     member_count: u32,
// ) {
//     let mut csprng = rand::rngs::OsRng;
//     let doc_id = DocumentId::generate(&mut csprng);
//
//     bencher
//         .with_inputs(|| {
//             let paired_idx = member_count as usize - 1;
//             setup_group_and_two_primaries(member_count, paired_idx, |x| {
//                 setup_member_cgkas(doc_id, x).map(|(ms, _ops)| ms)
//             })
//         })
//         .bench_local_refs(|(first_cgka, distant_cgka)| {
//             for _ in 0..100 {
//                 let (_pcs_key, op) = first_cgka.update(&mut csprng).unwrap();
//                 distant_cgka
//                     .cgka
//                     .merge_concurrent_operation(Rc::new(op))
//                     .unwrap();
//                 distant_cgka.cgka.secret_from_root().unwrap();
//             }
//         });
// }
