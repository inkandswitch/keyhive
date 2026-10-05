use crate::{
    cgka::Cgka,
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::ShareKeyMap,
    test_utils::{member, Group, Member, ADD_AUTH, REMOVE_AUTH},
    transact::{Fork, Merge},
};
use alloc::{sync::Arc, vec::Vec};
use core::hash::{Hash, Hasher};
use future_form::Local;
use keyhive_crypto::{
    digest::Digest, share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
};
use rand::{rngs::StdRng, SeedableRng};
use std::hash::DefaultHasher;

#[tokio::test]
async fn a_group_can_be_emptied_and_refilled() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0001);
    let mut group = Group::new(1, &mut rng).await;
    let owner = group.id(0);
    let signer = group.members[0].signer.clone();
    let cgka = &mut group.replicas[0];

    cgka.remove::<Local, _>(owner, REMOVE_AUTH, &signer)
        .await
        .expect("removing the last member is allowed");
    assert_eq!(
        cgka.group_size(),
        0,
        "removing the last member left members"
    );
    assert!(
        !cgka.has_tree_root_secret(),
        "an empty group reported a tree root secret"
    );

    let sk = ShareSecretKey::generate(&mut rng);
    assert!(
        matches!(
            cgka.update::<Local, _, _>(sk.share_key(), sk, &signer, &mut rng)
                .await,
            Err(CgkaError::NoMembers)
        ),
        "an empty group has no leaf to encrypt a path from"
    );

    let rejoin_pk = ShareSecretKey::generate(&mut rng).share_key();
    cgka.add::<Local, _>(owner, rejoin_pk, ADD_AUTH, &signer)
        .await
        .expect("the owner can rejoin an empty group");
    let rotate = ShareSecretKey::generate(&mut rng);
    cgka.update::<Local, _, _>(rotate.share_key(), rotate, &signer, &mut rng)
        .await
        .expect("a member of a refilled group can encrypt a path");
    assert!(
        cgka.has_tree_root_secret(),
        "a refilled group did not recover a tree root secret"
    );
}

#[tokio::test]
async fn emptying_a_group_converges_across_replicas() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0003);
    let mut group = Group::new(2, &mut rng).await;

    for i in 0..2 {
        let op = group.remove(0, group.id(i)).await;
        group.broadcast(&op);
    }

    assert_eq!(
        group.replicas[1].group_size(),
        0,
        "a replica that received the removal of the last member still has members"
    );
    group.check("after removing every member");
}

#[tokio::test]
async fn an_operation_for_another_document_is_refused() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0004);
    let owner = member(&mut rng);
    let tree_for = |rng: &mut StdRng| {
        Cgka::new(
            TreeId(MemorySigner::generate(rng).verifying_key()),
            owner.id,
            ShareKeyMap::new(),
        )
    };
    let mut here = tree_for(&mut rng);
    let mut elsewhere = tree_for(&mut rng);
    let founding_add = elsewhere
        .add::<Local, _>(owner.id, owner.pk, ADD_AUTH, &owner.signer)
        .await
        .expect("creating the add succeeds")
        .expect("the owner is new to the tree");

    let result = here.merge_concurrent_operation(Arc::new(founding_add));

    assert!(
        matches!(result, Err(CgkaError::WrongDocument)),
        "{result:?}"
    );
    assert_eq!(here.group_size(), 0, "the refused add was applied anyway");
}

#[tokio::test]
async fn a_removed_member_can_merge_a_fork_after_a_rotation() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0006);
    let mut group = Group::new(2, &mut rng).await;
    let removed = group.id(1);
    let remove = group.remove(0, removed).await;
    group.broadcast(&remove);
    let rotate = group.rotate(0, &mut rng).await;
    group.broadcast(&rotate);

    group.assert_trees_match_replay("after the owner was removed and the group rotated");
}

fn cgka_with_no_operations(owner: &Member) -> Cgka {
    Cgka::new(TreeId(owner.id.0), owner.id, ShareKeyMap::new())
}

#[test]
fn a_cgka_with_no_operations_has_no_batches() {
    let owner = member(&mut StdRng::seed_from_u64(0x11fe_0005));
    assert!(
        matches!(
            cgka_with_no_operations(&owner).ops(),
            Err(CgkaError::NotInitialized)
        ),
        "a CGKA with no operations should report that it is not initialized"
    );
}

#[tokio::test]
async fn a_cgka_merges_forks_before_and_after_its_first_operation() {
    let owner = member(&mut StdRng::seed_from_u64(0x11fe_0004));
    let mut cgka = cgka_with_no_operations(&owner);
    let fork = cgka.fork();
    cgka.merge(fork);

    let mut fork = cgka.fork();
    fork.add::<Local, _>(owner.id, owner.pk, ADD_AUTH, &owner.signer)
        .await
        .expect("the owner can add itself to an empty group");
    cgka.merge(fork);
    assert_eq!(
        cgka.group_size(),
        1,
        "merging a fork did not include the member it added"
    );
}

fn hash_of(cgka: &Cgka) -> u64 {
    let mut hasher = DefaultHasher::new();
    cgka.hash(&mut hasher);
    hasher.finish()
}

#[tokio::test]
async fn adding_a_member_changes_the_hash() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0002);
    let mut group = Group::new(2, &mut rng).await;
    let before = hash_of(&group.replicas[0]);

    let joiner = member(&mut rng);
    group.add(0, joiner.id, joiner.pk).await;

    assert_ne!(
        hash_of(&group.replicas[0]),
        before,
        "a replica hashes the same before and after a membership change"
    );
}

#[tokio::test]
async fn a_write_rotates_only_when_there_is_no_current_key() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0007);
    let mut group = Group::new(2, &mut rng).await;
    let signer = group.members[0].signer.clone();

    group.rotate(0, &mut rng).await;
    let (_, op, _) = group.replicas[0]
        .new_app_secret_for::<Local, _, u32, _>(&1, b"content", &Vec::new(), &signer, &mut rng)
        .await
        .expect("a member can write");
    assert!(op.is_none(), "a write should reuse the current key");

    let carol = member(&mut rng);
    group.add(0, carol.id, carol.pk).await;
    let (_, op, _) = group.replicas[0]
        .new_app_secret_for::<Local, _, u32, _>(&2, b"content", &Vec::new(), &signer, &mut rng)
        .await
        .expect("a member can write");
    assert!(
        op.is_some(),
        "an add blanks the root, so the next write should rotate"
    );
}

#[tokio::test]
async fn applying_an_update_records_the_root_secret_it_produced() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0008);
    let mut group = Group::new(2, &mut rng).await;

    let op = group.rotate(0, &mut rng).await;
    let op_hash = Digest::hash(op.as_ref());
    let produced = group.replicas[0]
        .root_secrets
        .get(&op_hash)
        .expect("the author records the secret its own update produced");

    group.deliver(&op, &[1]);

    assert_eq!(
        group.replicas[1].root_secrets.get(&op_hash),
        Some(produced),
        "receiving the update should have recorded the secret it produced"
    );
}

#[tokio::test]
async fn a_secret_is_refused_for_an_update_that_did_not_produce_it() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0009);
    let mut group = Group::new(1, &mut rng).await;
    let first = Digest::hash(group.rotate(0, &mut rng).await.as_ref());
    let second = Digest::hash(group.rotate(0, &mut rng).await.as_ref());
    let cgka = &mut group.replicas[0];
    let current = cgka
        .root_secrets
        .get(&second)
        .expect("the author records the secret its own update produced");

    assert!(
        matches!(
            cgka.root_secret_from_hashes(&Digest::hash(&current), &first),
            Err(CgkaError::UnknownPcsKey)
        ),
        "the current secret was returned for an earlier update that did not produce it"
    );
}

#[tokio::test]
async fn merging_a_fork_keeps_the_root_secrets_it_recorded() {
    let mut rng = StdRng::seed_from_u64(0x11fe_000b);
    let mut group = Group::new(1, &mut rng).await;
    let mut trunk = group.replicas[0].fork();
    let op_hash = Digest::hash(group.rotate(0, &mut rng).await.as_ref());
    group.rotate(0, &mut rng).await;
    let secret = group.replicas[0]
        .root_secrets
        .get(&op_hash)
        .expect("the author records the secret its own update produced");

    trunk.merge(group.replicas[0].fork());

    // The replay after a merge derives only the latest update's secret, so an
    // earlier one survives only by being copied from the fork.
    assert_eq!(
        trunk.root_secrets.get(&op_hash),
        Some(secret),
        "the secret recorded on the fork was lost in the merge"
    );
}

#[tokio::test]
async fn a_merge_records_the_root_secret_for_a_reader_outside_the_tree_through_public() {
    let mut rng = StdRng::seed_from_u64(0x11fe_000e);
    let mut group = Group::new(1, &mut rng).await;
    let public = member(&mut rng);
    group.add(0, MemberId::public(), public.pk).await;
    let mut reader_sks = ShareKeyMap::new();
    reader_sks.insert(public.pk, public.sk);
    let mut reader_view = group.replicas[0]
        .with_new_owner(member(&mut rng).id, reader_sks)
        .unwrap();
    let op_hash = Digest::hash(group.rotate(0, &mut rng).await.as_ref());
    let secret = group.replicas[0]
        .root_secrets
        .get(&op_hash)
        .expect("the author records the secret its own update produced");
    let mut fork = group.replicas[0].fork();
    fork.root_secrets.clear();

    reader_view.merge(fork);

    assert_eq!(
        reader_view.root_secrets.get(&op_hash),
        Some(secret),
        "the replay after a merge should record the secret through Public's leaf"
    );
}

#[tokio::test]
async fn an_earlier_secret_that_was_not_recorded_is_rebuilt() {
    let mut rng = StdRng::seed_from_u64(0x11fe_000c);
    let mut group = Group::new(1, &mut rng).await;
    let first = Digest::hash(group.rotate(0, &mut rng).await.as_ref());
    group.rotate(0, &mut rng).await;
    let cgka = &mut group.replicas[0];
    let earlier = cgka
        .root_secrets
        .get(&first)
        .expect("the author records the secret its own update produced");
    // A secret applied while the root was conflicted is not recorded. The tree
    // has moved on to a later update, so that secret can only be derived via a
    // rebuild.
    cgka.root_secrets.remove(&first);

    assert_eq!(
        cgka.root_secret_from_hashes(&Digest::hash(&earlier), &first)
            .ok(),
        Some(earlier),
        "the earlier update's secret should be rebuilt, not derived from the current tree"
    );
}
