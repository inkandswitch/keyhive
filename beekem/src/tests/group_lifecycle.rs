use crate::{
    cgka::Cgka,
    collections::Set,
    error::CgkaError,
    id::TreeId,
    keys::ShareKeyMap,
    test_utils::{for_each_seed, member, Group, Member, NO_CITATIONS},
    transact::{Fork, Merge},
};
use alloc::{collections::BTreeSet, sync::Arc};
use core::hash::{Hash, Hasher};
use future_form::{FutureForm, Local};
use keyhive_crypto::{
    share_key::ShareSecretKey,
    signer::{async_signer::AsyncSigner, memory::MemorySigner, SigningError},
    verifiable::Verifiable,
};
use nonempty::nonempty;
use rand::{rngs::StdRng, SeedableRng};
use std::hash::DefaultHasher;

#[tokio::test]
async fn a_group_can_be_emptied_and_refilled() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0001);
    let mut group = Group::new(1, &mut rng).await;
    let owner = group.id(0);
    let signer = group.members[0].signer.clone();
    let cgka = &mut group.replicas[0];

    cgka.remove::<Local, _>(owner, NO_CITATIONS, &signer)
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
    cgka.add::<Local, _>(owner, rejoin_pk, None, NO_CITATIONS, &signer)
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
            TreeId::from(&MemorySigner::generate(rng).0),
            owner.id,
            ShareKeyMap::new(),
        )
    };
    let mut here = tree_for(&mut rng);
    let mut elsewhere = tree_for(&mut rng);
    let founding_add = elsewhere
        .add::<Local, _>(owner.id, owner.pk, None, NO_CITATIONS, &owner.signer)
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

#[tokio::test]
async fn add_multiple_adds_each_member() {
    let mut rng = StdRng::seed_from_u64(0x11fe_000a);
    let mut group = Group::new(1, &mut rng).await;
    let (d, e) = (member(&mut rng), member(&mut rng));
    let signer = group.members[0].signer.clone();
    let cgka = &mut group.replicas[0];

    cgka.add_multiple::<Local, _>(
        nonempty![
            (d.id, d.pk, None, NO_CITATIONS),
            (e.id, e.pk, None, NO_CITATIONS)
        ],
        &signer,
    )
    .await
    .expect("adding new members succeeds");
    let members: BTreeSet<_> = cgka.member_ids().expect("no replay is pending").collect();
    assert!(
        members.contains(&d.id) && members.contains(&e.id),
        "add_multiple left out a member"
    );
}

#[tokio::test]
async fn the_last_operation_issued_is_the_head_and_is_found_by_its_digest() {
    let mut rng = StdRng::seed_from_u64(0x11fe_000b);
    let mut group = Group::new(1, &mut rng).await;
    let d = member(&mut rng);
    let signer = group.members[0].signer.clone();
    let cgka = &mut group.replicas[0];

    let add = cgka
        .add::<Local, _>(d.id, d.pk, None, NO_CITATIONS, &signer)
        .await
        .expect("adding a new member succeeds")
        .expect("d is not yet a member");
    let digest = add.digest();
    assert_eq!(cgka.heads(), &Set::from_iter([digest]));
    assert_eq!(cgka.op(&digest).map(AsRef::as_ref), Some(&add));
}

fn cgka_with_no_operations(owner: &Member) -> Cgka {
    Cgka::new(TreeId::from(owner.id.id()), owner.id, ShareKeyMap::new())
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
    fork.add::<Local, _>(owner.id, owner.pk, None, NO_CITATIONS, &owner.signer)
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
    let (_, rotation) = group.replicas[0]
        .new_app_secret_for::<Local, _, u32, _>(&1, &[], &signer, &mut rng)
        .await
        .expect("a member can write");
    assert!(rotation.is_none(), "a write should reuse the current key");

    let carol = member(&mut rng);
    group.add(0, carol.id, carol.pk).await;
    let (_, rotation) = group.replicas[0]
        .new_app_secret_for::<Local, _, u32, _>(&2, &[], &signer, &mut rng)
        .await
        .expect("a member can write");
    assert!(
        rotation.is_some(),
        "an add blanks the root, so the next write should rotate"
    );
}

#[tokio::test]
async fn applying_an_update_records_the_root_secret_it_produced() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0008);
    let mut group = Group::new(2, &mut rng).await;

    let op = group.rotate(0, &mut rng).await;
    let op_hash = op.digest();
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

#[test]
fn a_secret_is_accepted_only_for_the_update_that_produced_it() {
    for_each_seed(|mut rng| async move {
        let mut group = Group::new(1, &mut rng).await;
        let first = group.rotate(0, &mut rng).await.digest();
        let second = group.rotate(0, &mut rng).await.digest();
        let cgka = &mut group.replicas[0];
        let current = cgka
            .root_secrets
            .get(&second)
            .expect("the author records the secret its own update produced");

        assert_eq!(
            cgka.root_secret_from_hashes(&current.digest(), &second)
                .ok(),
            Some(current),
            "a secret was refused for the update that produced it"
        );
        assert!(
            matches!(
                cgka.root_secret_from_hashes(&current.digest(), &first),
                Err(CgkaError::UnknownPcsKey)
            ),
            "a secret was returned for an update that did not produce it"
        );
    });
}

#[test]
fn merging_a_fork_keeps_the_root_secrets_it_recorded() {
    for_each_seed(|mut rng| async move {
        let mut group = Group::new(1, &mut rng).await;
        let mut trunk = group.replicas[0].fork();
        let op_hash = group.rotate(0, &mut rng).await.digest();
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
    });
}

#[test]
fn an_earlier_secret_that_was_not_recorded_is_found() {
    for_each_seed(|mut rng| async move {
        let mut group = Group::new(1, &mut rng).await;
        let first = group.rotate(0, &mut rng).await.digest();
        group.rotate(0, &mut rng).await;
        let cgka = &mut group.replicas[0];
        let earlier = cgka
            .root_secrets
            .get(&first)
            .expect("the author records the secret its own update produced");
        // A secret applied while the root was conflicted is not recorded. The tree
        // has moved on to a later update, so that secret has to be derived again.
        cgka.root_secrets.remove(&first);

        assert_eq!(
            cgka.root_secret_from_hashes(&earlier.digest(), &first).ok(),
            Some(earlier),
            "the earlier update's secret should be derived again, not taken from the current tree"
        );
    });
}

/// A signer that refuses every payload, as a remote or hardware signer might.
struct FailingSigner(MemorySigner);

impl Verifiable for FailingSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}

impl AsyncSigner<Local> for FailingSigner {
    fn try_sign_bytes_async<'a>(
        &'a self,
        _payload_bytes: &'a [u8],
    ) -> <Local as FutureForm>::Future<'a, Result<ed25519_dalek::Signature, SigningError>> {
        Local::ready(Err(SigningError::SigningFailed(
            ed25519_dalek::SignatureError::new(),
        )))
    }
}

/// A group of three whose tree has a root secret and a signer for member 0
/// that always fails.
async fn group_with_a_failing_signer(seed: u64) -> (Group, FailingSigner, StdRng) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut group = Group::new(3, &mut rng).await;
    group.settle(0, &mut rng).await;
    let failing = FailingSigner(group.members[0].signer.clone());
    (group, failing, rng)
}

/// Members 1 and 0 each rotate, then check that every replica agrees on tree and key.
async fn assert_agreement_after_rotations(mut group: Group, rng: &mut StdRng, context: &str) {
    group.settle(1, rng).await;
    group.settle(0, rng).await;
    group.check(context);
    group.assert_key_agreement(context);
}

#[tokio::test]
async fn an_add_whose_signing_fails_does_not_change_the_tree() {
    let (mut group, failing, mut rng) = group_with_a_failing_signer(0x5167_0001).await;
    let fresh = member(&mut rng);
    let result = group.replicas[0]
        .add::<Local, _>(fresh.id, fresh.pk, None, NO_CITATIONS, &failing)
        .await;
    assert!(
        matches!(result, Err(CgkaError::SigningError(_))),
        "{result:?}"
    );
    assert_agreement_after_rotations(group, &mut rng, "after a failed add").await;
}

#[tokio::test]
async fn a_removal_whose_signing_fails_does_not_change_the_tree() {
    let (mut group, failing, mut rng) = group_with_a_failing_signer(0x5167_0002).await;
    let target = group.id(2);
    let result = group.replicas[0]
        .remove::<Local, _>(target, NO_CITATIONS, &failing)
        .await;
    assert!(
        matches!(result, Err(CgkaError::SigningError(_))),
        "{result:?}"
    );
    assert_agreement_after_rotations(group, &mut rng, "after a failed removal").await;
}

#[tokio::test]
async fn a_rotation_whose_signing_fails_does_not_change_the_tree() {
    let (mut group, failing, mut rng) = group_with_a_failing_signer(0x5167_0003).await;
    let before = group.replicas[0].tree.clone();
    let sk = ShareSecretKey::generate(&mut rng);
    let result = group.replicas[0]
        .update::<Local, _, StdRng>(sk.share_key(), sk, &failing, &mut rng)
        .await;
    assert!(
        matches!(result, Err(CgkaError::SigningError(_))),
        "{result:?}"
    );
    assert!(
        group.replicas[0].tree == before,
        "the failed rotation's path is still in the tree"
    );
    assert_agreement_after_rotations(group, &mut rng, "after a failed rotation").await;
}

#[tokio::test]
async fn a_first_add_whose_signing_fails_can_be_retried() {
    let mut rng = StdRng::seed_from_u64(0x5167_0004);
    let owner = member(&mut rng);
    let mut cgka = cgka_with_no_operations(&owner);
    let failing = FailingSigner(owner.signer.clone());
    let result = cgka
        .add::<Local, _>(owner.id, owner.pk, None, NO_CITATIONS, &failing)
        .await;
    assert!(
        matches!(result, Err(CgkaError::SigningError(_))),
        "{result:?}"
    );
    let retried = cgka
        .add::<Local, _>(owner.id, owner.pk, None, NO_CITATIONS, &owner.signer)
        .await
        .expect("the add succeeds");
    assert!(retried.is_some(), "the retried add created no operation");
}

#[tokio::test]
async fn a_member_who_lacks_its_leaf_secret_rotates_its_leaf_to_write() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0002);
    let mut group = Group::new(3, &mut rng).await;
    group.settle(0, &mut rng).await;

    // As if another instance of this identity rotated the leaf and has not
    // shared the new secret yet.
    let mut stranded = group.replicas[1].clone();
    stranded.owner_sks = ShareKeyMap::new();
    stranded.root_secrets = Default::default();
    let signer = group.members[1].signer.clone();
    let leaf = stranded.owner_leaf_key();
    let (_, rotation) = stranded
        .new_app_secret_for::<Local, _, [u8; 32], _>(&[0; 32], &[], &signer, &mut rng)
        .await
        .expect("a member who lacks its leaf secret still writes");

    assert!(rotation.is_some(), "writing rotated");
    assert_ne!(stranded.owner_leaf_key(), leaf, "the leaf was replaced");
}
