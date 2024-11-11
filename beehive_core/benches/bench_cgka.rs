use std::time::Duration;

use aead::OsRng;
use beehive_core::{cgka::{
    error::CgkaError,
    test_utils::{
        setup_member_cgkas, setup_member_cgkas_with_all_updated_and_10_adds,
        setup_member_cgkas_with_maximum_conflict_keys, setup_updated_and_synced_member_cgkas,
        TestMemberCgka,
    },
}, crypto::{encrypted::NestedEncrypted, share_key::ShareSecretKey}, principal::{document::id::DocumentId, identifier::Identifier}};
use divan::Bencher;
use nonempty::nonempty;
use x25519_dalek::StaticSecret;

fn main() {
    divan::main();
}

#[divan::bench(
    args = [100, 1000]
)]
fn create_key_pairs(n: u32) {
    for _ in 0..n {
        let s = ShareSecretKey::generate();
        s.share_key();
    }
}

#[divan::bench(
    args = [(100, 31), (100, 255), (100, 511)],
    max_time = Duration::from_secs(120),
)]
fn encrypt_and_decrypt_log_2_of_members(iters_and_member_count: (u32, u32)) {
    let verifying_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key();
    let doc_id = DocumentId(Identifier(verifying_key));
    let (iters, member_count) = iters_and_member_count;
    let path_length = (member_count as f32).log2() as u32 + 1;
    for _ in 0..iters {
        for _ in 0..path_length {
            let secret = StaticSecret::random_from_rng(OsRng);
            let s1 = ShareSecretKey::generate();
            let p1 = s1.share_key();
            let s2 = ShareSecretKey::generate();
            let p2 = s2.share_key();
            let encrypt_keys = nonempty![p2];
            let decrypt_keys = vec![s2.derive_symmetric_key(&p1)];
            let encrypted: NestedEncrypted<ShareSecretKey> = NestedEncrypted::try_encrypt(doc_id, secret.to_bytes(), &s1, &encrypt_keys)
                .unwrap();
            encrypted.try_sibling_decrypt(&decrypt_keys).unwrap();
        }
    }
}

fn setup_group_and_two_primaries<F>(
    member_count: u32,
    paired_idx: usize,
    setup: F,
) -> (TestMemberCgka, TestMemberCgka)
where
    F: Fn(u32) -> Result<Vec<TestMemberCgka>, CgkaError>,
{
    let cgkas = setup(member_count).unwrap();
    let mut first_cgka = cgkas[0].clone();
    let mut paired_cgka = cgkas[paired_idx].clone();
    paired_cgka.cgka = first_cgka
        .cgka
        .with_new_owner(paired_cgka.id(), paired_cgka.m.pk, paired_cgka.m.sk.clone())
        .unwrap();
    let Some(op) = paired_cgka.update().unwrap() else {
        panic!();
    };
    first_cgka.cgka.merge(op).unwrap();
    (first_cgka, paired_cgka)
}

#[divan::bench(
    args = [31, 255, 511],
    max_time = Duration::from_secs(120),
)]
fn apply_100_updates_and_sibling_decrypt(bencher: Bencher, member_count: u32) {
    bencher
        .with_inputs(|| {
            let paired_idx = 1;
            setup_group_and_two_primaries(
                member_count,
                paired_idx,
                setup_updated_and_synced_member_cgkas,
            )
        })
        .bench_local_refs(|(first_cgka, sibling_cgka)| {
            for _ in 0..100 {
                let Some(op) = first_cgka.update().unwrap() else {
                    panic!();
                };
                sibling_cgka.cgka.merge(op).unwrap();
                sibling_cgka.cgka.secret().unwrap();
            }
        });
}

#[divan::bench(
    args = [31, 255, 511],
    max_time = Duration::from_secs(120),
)]
fn apply_100_updates_and_distant_member_decrypt(bencher: Bencher, member_count: u32) {
    bencher
        .with_inputs(|| {
            let paired_idx = member_count as usize - 1;
            setup_group_and_two_primaries(
                member_count,
                paired_idx,
                setup_updated_and_synced_member_cgkas,
            )
        })
        .bench_local_refs(|(first_cgka, distant_cgka)| {
            for _ in 0..100 {
                let Some(op) = first_cgka.update().unwrap() else {
                    panic!();
                };
                distant_cgka.cgka.merge(op).unwrap();
                distant_cgka.cgka.secret().unwrap();
            }
        });
}

#[divan::bench(
    args = [31, 255, 511],
    max_time = Duration::from_secs(120),
)]
fn apply_100_updates_and_distant_member_decrypt_with_maximum_conflict_keys(
    bencher: Bencher,
    member_count: u32,
) {
    bencher
        .with_inputs(|| {
            let paired_idx = member_count as usize - 1;
            setup_group_and_two_primaries(
                member_count,
                paired_idx,
                setup_member_cgkas_with_maximum_conflict_keys,
            )
        })
        .bench_local_refs(|(first_cgka, distant_cgka)| {
            for _ in 0..100 {
                let Some(op) = first_cgka.update().unwrap() else {
                    panic!();
                };
                distant_cgka.cgka.merge(op).unwrap();
                distant_cgka.cgka.secret().unwrap();
            }
        });
}

#[divan::bench(
    args = [31, 255, 511],
    max_time = Duration::from_secs(120),
)]
fn apply_100_updates_and_distant_member_decrypt_after_adds(bencher: Bencher, member_count: u32) {
    bencher
        .with_inputs(|| {
            let paired_idx = member_count as usize - 1;
            setup_group_and_two_primaries(
                member_count,
                paired_idx,
                setup_member_cgkas_with_all_updated_and_10_adds,
            )
        })
        .bench_local_refs(|(first_cgka, distant_cgka)| {
            for _ in 0..100 {
                let Some(op) = first_cgka.update().unwrap() else {
                    panic!();
                };
                distant_cgka.cgka.merge(op).unwrap();
                distant_cgka.cgka.secret().unwrap();
            }
        });
}

#[divan::bench(
    args = [31, 255, 511],
    max_time = Duration::from_secs(120),
)]
fn apply_100_updates_and_distant_member_decrypt_with_blank_nodes(
    bencher: Bencher,
    member_count: u32,
) {
    bencher
        .with_inputs(|| {
            let paired_idx = member_count as usize - 1;
            setup_group_and_two_primaries(member_count, paired_idx, setup_member_cgkas)
        })
        .bench_local_refs(|(first_cgka, distant_cgka)| {
            for _ in 0..100 {
                let Some(op) = first_cgka.update().unwrap() else {
                    panic!();
                };
                distant_cgka.cgka.merge(op).unwrap();
                distant_cgka.cgka.secret().unwrap();
            }
        });
}
