//! Tests concurrent membership changes.

use crate::{
    cgka::Cgka,
    error::CgkaError,
    id::MemberId,
    keys::{NodeKey, ShareKeyMap},
    operation::CgkaOperation,
    test_utils::{member, Group, Member},
};
use alloc::{
    boxed::Box,
    collections::BTreeSet,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use bolero::{gen, TypeGenerator, ValueGenerator};
use future_form::{Local, Sendable};
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{
    rngs::{OsRng, StdRng},
    CryptoRng, RngCore, SeedableRng,
};

#[tokio::test]
async fn duplicate_adds_fill_one_leaf() {
    let mut rng = StdRng::seed_from_u64(0xd00b_1111);
    let mut group = Group::new(3, &mut rng).await;
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());
    // Distinct prekeys, so the two adds are distinguishable.
    let other_pk = ShareSecretKey::generate(&mut rng).share_key();

    let by_a = group.add(0, d.id, d.pk).await;
    let by_b = group.add(1, d.id, other_pk).await;
    group.broadcast(&by_a);
    group.broadcast(&by_b);
    group.settle(0, &mut rng).await;

    let context = "after two concurrent adds of the same member";
    group.check(context);
    group.assert_members(context, &["a", "b", "c", "d"]);

    // Once `d` is removed, no leaf anywhere may still hold `d`'s key.
    let remove_d = group.remove(0, d.id).await;
    group.broadcast(&remove_d);
    group.settle(0, &mut rng).await;

    let context = "after removing a concurrently double-added member";
    group.check(context);
    group.assert_members(context, &["a", "b", "c"]);
    group.assert_key_agreement(context);
}

#[tokio::test]
async fn local_add_sees_a_pending_concurrent_add() {
    let mut rng = StdRng::seed_from_u64(0xb0f0_0000);
    let mut group = Group::new(3, &mut rng).await;
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());

    // `a` rotates first, so `b`'s add reaches it as concurrent and is pending.
    let add_by_b = group.add(1, d.id, d.pk).await;
    let rotation = group.rotate(0, &mut rng).await;
    group.deliver(&add_by_b, &[0]);

    let local = group.replicas[0]
        .add::<Local, _>(d.id, d.pk, &group.members[0].signer)
        .await
        .expect("creating the add succeeds");
    assert!(
        local.is_none(),
        "`a` placed `d` again, though a concurrent add of `d` was already in its graph"
    );

    for op in [&add_by_b, &rotation] {
        group.broadcast(op);
    }
    group.settle(0, &mut rng).await;

    let context = "after adding a member whom a pending concurrent add already covers";
    group.check(context);
    group.assert_members(context, &["a", "b", "c", "d"]);
    group.assert_key_agreement(context);
}

#[tokio::test]
async fn local_remove_sees_a_pending_concurrent_remove() {
    let mut rng = StdRng::seed_from_u64(0xb0f1_1111);
    let mut group = Group::new(3, &mut rng).await;
    let c = group.id(2);

    let remove_by_b = group.remove(1, c).await;
    let rotation = group.rotate(0, &mut rng).await;
    group.deliver(&remove_by_b, &[0]);

    let local = group.replicas[0]
        .remove::<Local, _>(c, &group.members[0].signer)
        .await;
    assert!(
        matches!(local, Ok(None)),
        "removing a member whom a pending concurrent removal already covers should be \
         a no-op, got {local:?}"
    );

    for op in [&remove_by_b, &rotation] {
        group.broadcast(op);
    }
    group.settle(0, &mut rng).await;

    let context = "after removing a member whom a pending concurrent removal already covers";
    group.check(context);
    group.assert_members(context, &["a", "b"]);
    group.assert_key_agreement(context);
}

#[tokio::test]
async fn local_remove_sees_a_pending_concurrent_add() {
    let mut rng = StdRng::seed_from_u64(0xb0f2_2222);
    let mut group = Group::new(3, &mut rng).await;
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());

    // `a` rotates first, so `b`'s add reaches it as concurrent and is pending.
    let add_by_b = group.add(1, d.id, d.pk).await;
    let rotation = group.rotate(0, &mut rng).await;
    group.deliver(&add_by_b, &[0]);

    // `a`'s tree does not place `d` yet, but its graph holds the add that will.
    let local = group.replicas[0]
        .remove::<Local, _>(d.id, &group.members[0].signer)
        .await
        .expect("authoring the removal succeeds");
    let removal = local.map(Arc::new).unwrap_or_else(|| {
        panic!(
            "`a`'s removal of `d` was reported as a no-op, though a concurrent add \
             of `d` was already in `a`'s graph, so nothing in the history removes `d`"
        )
    });

    for op in [&add_by_b, &rotation, &removal] {
        group.broadcast(op);
    }
    group.settle(0, &mut rng).await;

    let context = "after removing a member whom a pending concurrent add was about to place";
    group.check(context);
    group.assert_members(context, &["a", "b", "c"]);
    group.assert_key_agreement(context);
}

async fn rotation_before_merge_scenario(seed: u64) -> bool {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut group = Group::new(3, &mut rng).await;
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());
    let pk_from_a = d.pk;
    let sk_from_b = ShareSecretKey::generate(&mut rng);
    let pk_from_b = sk_from_b.share_key();

    let add_by_a = group.add(0, d.id, pk_from_a).await;
    let add_by_b = group.add(1, d.id, pk_from_b).await;
    let rot_a = group.rotate(0, &mut rng).await;

    // Replica 0 applies its own add and rotation before `b`'s add reaches it, so
    // `rot_a` is authored against a tree that places `d` at `a`'s prekey.
    group.deliver(&add_by_b, &[2]);
    group.deliver(&add_by_a, &[1, 2]);
    group.deliver(&add_by_b, &[0]);
    group.deliver(&rot_a, &[1, 2]);

    // A membership change forces the merge without re-encrypting any path, so
    // the rotation above is the only writer to `d`'s ancestors.
    let e = member(&mut rng);
    group.names.insert(e.id, "e".to_string());
    let add_e = group.add(2, e.id, e.pk).await;
    group.broadcast(&add_e);

    let merged = format!("seed {seed:#x}, after merging two adds of d and a rotation");
    group.check(&merged);
    group.assert_members(&merged, &["a", "b", "c", "d", "e"]);

    let d_leaf_key = group.replicas[0].tree.node_key_for_id(d.id);
    let (winning_pk, winning_sk) = match d_leaf_key {
        Ok(NodeKey::ShareKey(k)) if k == pk_from_a => (pk_from_a, d.sk),
        Ok(NodeKey::ShareKey(k)) if k == pk_from_b => (pk_from_b, sk_from_b),
        other => panic!("{merged}: `d`'s leaf holds {other:?}, not one of its two added prekeys"),
    };
    let winner_is_a = winning_pk == pk_from_a;

    group.settle(2, &mut rng).await;

    let settled = format!("seed {seed:#x}, after a rotation re-established a root key");
    group.check(&settled);
    group.assert_key_agreement(&settled);

    let mut only_winner = ShareKeyMap::new();
    only_winner.insert(winning_pk, winning_sk);
    group.assert_reads_group_key(
        d.id,
        only_winner,
        &settled,
        "`d` holds the prekey the merge kept and still cannot read the group, so a \
         node is encrypted to the prekey it dropped.",
    );

    winner_is_a
}

#[tokio::test]
async fn a_rotation_before_the_merge_does_not_lock_out_the_added_member() {
    const ROTATION_SEED_BASE: u64 = 0x0170_0000;
    const ROTATION_SEEDS: u64 = 8;

    let mut outcomes = BTreeSet::new();
    for offset in 0..ROTATION_SEEDS {
        outcomes.insert(rotation_before_merge_scenario(ROTATION_SEED_BASE + offset).await);
    }
    assert!(
        outcomes.len() == 2,
        "over {ROTATION_SEEDS} seeds the merge always kept the same one of `d`'s \
         two prekeys, so the sweep never covered the case where it drops the one \
         the rotation encrypted to"
    );
}

/// One operation as created by the generator.
#[derive(Clone, Copy, Debug, TypeGenerator)]
enum CgkaOp {
    Add { joiner: u8 },
    Remove { target: u8 },
    Update,
}

/// One step of a run. The operation created and whether everything authored so far is
/// synced to every replica before the next step.
#[derive(Clone, Copy, Debug, TypeGenerator)]
struct Step {
    op: CgkaOp,
    deliver_after: bool,
}

/// A randomly generated run of concurrent operations.
///
/// `seed` determines key generation only. The operations themselves come from the
/// generator.
#[derive(Debug)]
struct Scenario {
    seed: u64,
    extra_members: u8,
    ops: Vec<Step>,
}

/// Deliver `undelivered` to every replica, retrying until nothing more applies.
fn deliver_all(
    group: &mut Group,
    undelivered: &mut Vec<Arc<Signed<CgkaOperation>>>,
    everyone: &[usize],
) {
    let synced = undelivered.len();
    loop {
        let before = undelivered.len();
        undelivered.retain(|op| !group.try_deliver(op, everyone).is_empty());
        if undelivered.is_empty() {
            break;
        }
        assert!(
            undelivered.len() < before,
            "{} of {synced} operations never became deliverable",
            undelivered.len(),
        );
    }
}

const MIN_OPS: usize = 3;
const MAX_OPS: usize = 12;
const JOINERS: usize = 3;

/// Every member creates concurrent operations. Then every operation is delivered
/// to every replica and they are made to settle. The replicas must then have the
/// same tree and every member still in the tree must derive the same root key.
///
/// Member 0 is never a removal target so the scenario always ends with a member
/// who can create the settling rotation and a key the others must agree with.
async fn run(scenario: &Scenario) {
    use rand::{rngs::StdRng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(scenario.seed);

    let member_count = 2 + scenario.extra_members as usize % 4;
    let mut group = Group::new(member_count, &mut rng).await;
    let joiners: Vec<Member> = (0..JOINERS).map(|_| member(&mut rng)).collect();

    let everyone: Vec<usize> = (0..member_count).collect();
    let mut undelivered = Vec::new();
    let mut applied = 0usize;
    for (position, step) in scenario.ops.iter().enumerate() {
        let author = position % member_count;
        let op = match step.op {
            CgkaOp::Add { joiner } => {
                let joiner = &joiners[joiner as usize % JOINERS];
                let (id, pk) = (joiner.id, joiner.pk);
                group.try_add(author, id, pk).await
            }
            CgkaOp::Remove { target } => {
                // Targets start at 1 so member 0 survives every scenario.
                // Nobody removes themselves so a member can always keep
                // operating on its own replica.
                let target = 1 + target as usize % (member_count - 1);
                if target == author {
                    None
                } else {
                    let target = group.id(target);
                    group.try_remove(author, target).await
                }
            }
            CgkaOp::Update => group.try_rotate(author, &mut rng).await,
        };
        applied += op.is_some() as usize;
        undelivered.extend(op);
        if step.deliver_after {
            deliver_all(&mut group, &mut undelivered, &everyone);
        }
    }
    deliver_all(&mut group, &mut undelivered, &everyone);
    assert!(
        applied > 0,
        "every generated operation was a no-op, so this run observed nothing: {scenario:?}"
    );

    // Deliver everything to everyone, retrying until nothing more applies. An
    // operation is refused until its predecessors arrive, and every operation
    // here is offered to every replica.
    // Delivery only queues an operation. A replica replays its graph when a
    // later structural change forces it so the trees are compared after the
    // settling rotation rather than here.
    group.settle(0, &mut rng).await;

    let context = "after a rotation re-established a root key";
    group.check(context);
    group.assert_key_agreement(context);
}

#[test]
fn replicas_converge_over_random_concurrent_operations() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("building a runtime succeeds");
    bolero::check!()
        .with_generator(
            (
                gen::<u64>(),
                gen::<u8>(),
                gen::<Vec<Step>>().with().len(MIN_OPS..=MAX_OPS),
            )
                .map_gen(|(seed, extra_members, ops)| Scenario {
                    seed,
                    extra_members,
                    ops,
                }),
        )
        .for_each(|scenario| runtime.block_on(run(scenario)));
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A fresh member identity and the share key it joins with.
fn joiner<R: CryptoRng + RngCore>(rng: &mut R) -> (MemberId, ShareKey) {
    let signer = MemorySigner::generate(rng);
    let sk = ShareSecretKey::generate(rng);
    (MemberId::from(signer.verifying_key()), sk.share_key())
}

/// Build a `Cgka` with an owner and `extra` further members.
async fn cgka_with<R: CryptoRng + RngCore>(
    rng: &mut R,
    extra: usize,
) -> Result<(Cgka, MemorySigner, Vec<MemberId>)> {
    let signer = MemorySigner::generate(rng);
    let (owner_id, owner_pk) = joiner(rng);
    let tree_id = crate::id::TreeId::from(signer.verifying_key());
    let mut cgka = Cgka::new::<Sendable, _>(tree_id, owner_id, owner_pk, &signer).await?;

    let mut members = Vec::new();
    for _ in 0..extra {
        let (id, pk) = joiner(rng);
        cgka.add::<Sendable, _>(id, pk, &signer).await?;
        members.push(id);
    }
    Ok((cgka, signer, members))
}

fn ids(cgka: &Cgka) -> Vec<String> {
    let mut v: Vec<String> = cgka.member_ids().map(|m| format!("{m}")).collect();
    v.sort();
    v
}

fn has(list: &[String], id: MemberId) -> bool {
    list.contains(&format!("{id}"))
}

/// Force both replicas to apply everything they have queued, then return their
/// members. Adding a new probe member forces replay.
async fn settle<R: CryptoRng + RngCore>(
    left: &mut Cgka,
    right: &mut Cgka,
    signer: &MemorySigner,
    rng: &mut R,
) -> Result<(Vec<String>, Vec<String>)> {
    let (probe, probe_pk) = joiner(rng);
    left.add::<Sendable, _>(probe, probe_pk, signer).await?;
    right.add::<Sendable, _>(probe, probe_pk, signer).await?;
    Ok((ids(left), ids(right)))
}

/// Adding a new member while a different member is concurrently removed should
/// not cause the new member to be lost.
#[tokio::test]
async fn a_concurrent_add_and_remove_retains_the_add() -> Result<()> {
    for round in 0..40 {
        let (mut left, signer, members) = cgka_with(&mut OsRng, 3).await?;
        let mut right = left.clone();

        // Left removes an existing member; right concurrently adds a new one.
        let member_to_remove = members[round % members.len()];
        let Some(remove_op) = left
            .remove::<Sendable, _>(member_to_remove, &signer)
            .await?
        else {
            continue;
        };
        let (new_id, new_pk) = joiner(&mut OsRng);
        let Some(add_op) = right.add::<Sendable, _>(new_id, new_pk, &signer).await? else {
            continue;
        };

        left.merge_concurrent_operation(Arc::new(add_op))?;
        right.merge_concurrent_operation(Arc::new(remove_op))?;

        let (l, r) = settle(&mut left, &mut right, &signer, &mut OsRng).await?;
        assert_eq!(
            l, r,
            "round {round}: replicas disagree after a concurrent add and remove"
        );
        assert!(
            has(&l, new_id),
            "round {round}: the concurrently added member was lost: {l:?}"
        );
        assert!(
            !has(&l, member_to_remove),
            "round {round}: the removed member is still present: {l:?}"
        );
    }
    Ok(())
}

/// Adding multiple new members while a different member is concurrently removed should
/// not cause the new members to be lost.
#[tokio::test]
async fn a_remove_concurrent_with_several_adds_retains_the_adds() -> Result<()> {
    for round in 0..30 {
        let (mut left, signer, members) = cgka_with(&mut OsRng, 4).await?;
        let mut right = left.clone();

        let member_to_remove = members[round % members.len()];
        let Some(remove_op) = left
            .remove::<Sendable, _>(member_to_remove, &signer)
            .await?
        else {
            continue;
        };

        let mut add_ops = Vec::new();
        let mut added = Vec::new();
        for _ in 0..3 {
            let (id, pk) = joiner(&mut OsRng);
            if let Some(op) = right.add::<Sendable, _>(id, pk, &signer).await? {
                add_ops.push(op);
                added.push(id);
            }
        }

        for op in &add_ops {
            left.merge_concurrent_operation(Arc::new(op.clone()))?;
        }
        right.merge_concurrent_operation(Arc::new(remove_op))?;

        let (l, r) = settle(&mut left, &mut right, &signer, &mut OsRng).await?;
        assert_eq!(
            l, r,
            "round {round}: replicas disagree after a remove concurrent with three adds"
        );
        for id in &added {
            assert!(
                has(&l, *id),
                "round {round}: an added member was lost: {l:?}"
            );
        }
        assert!(
            !has(&l, member_to_remove),
            "round {round}: the removed member survived: {l:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_duplicate_remove_should_not_create_an_invalid_state() -> Result<()> {
    let (mut left, signer, members) = cgka_with(&mut OsRng, 2).await?;
    let mut right = left.clone();
    let member_to_remove = members[0];

    // Left: remove a member.
    let rm_left = left
        .remove::<Sendable, _>(member_to_remove, &signer)
        .await?
        .expect("the removed member is present");

    // Right: add someone else, then remove the same member removed above.
    let (extra, extra_pk) = joiner(&mut OsRng);
    let add_right = right
        .add::<Sendable, _>(extra, extra_pk, &signer)
        .await?
        .expect("a fresh member is added");
    let rm_right = right
        .remove::<Sendable, _>(member_to_remove, &signer)
        .await?
        .expect("the removed member is present here too");

    // Exchange everything, retrying so ordering is not the issue.
    for (replica, incoming) in [
        (&mut left, vec![add_right.clone(), rm_right.clone()]),
        (&mut right, vec![rm_left.clone()]),
    ] {
        let mut pending = incoming;
        loop {
            let before = pending.len();
            pending.retain(|op| {
                replica
                    .merge_concurrent_operation(Arc::new(op.clone()))
                    .is_err()
            });
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        assert!(pending.is_empty(), "an operation could never be applied");
    }

    let (probe, probe_pk) = joiner(&mut OsRng);
    left.add::<Sendable, _>(probe, probe_pk, &signer)
        .await
        .map_err(|e| format!("left could not add a member afterwards: {e:?}"))?;
    right
        .add::<Sendable, _>(probe, probe_pk, &signer)
        .await
        .map_err(|e| format!("right could not add a member afterwards: {e:?}"))?;

    assert_eq!(ids(&left), ids(&right), "replicas disagree");
    Ok(())
}

#[tokio::test]
async fn a_group_can_be_emptied_and_refilled() -> Result<()> {
    let (mut cgka, signer, _) = cgka_with(&mut OsRng, 0).await?;
    let owner = cgka.member_ids().next().expect("the owner");

    cgka.remove::<Sendable, _>(owner, &signer).await?;
    assert_eq!(
        cgka.group_size(),
        0,
        "removing the last member left members"
    );
    assert!(!cgka.has_pcs_key(), "an empty group reported a PCS key");

    let sk = ShareSecretKey::generate(&mut OsRng);
    assert!(
        matches!(
            cgka.update::<Sendable, _, _>(sk.share_key(), sk, &signer, &mut OsRng)
                .await,
            Err(CgkaError::NoMembers)
        ),
        "an empty group has no leaf to encrypt a path from"
    );

    let rejoin_pk = ShareSecretKey::generate(&mut OsRng).share_key();
    cgka.add::<Sendable, _>(owner, rejoin_pk, &signer).await?;
    let rotate = ShareSecretKey::generate(&mut OsRng);
    cgka.update::<Sendable, _, _>(rotate.share_key(), rotate, &signer, &mut OsRng)
        .await?;
    assert!(
        cgka.has_pcs_key(),
        "a refilled group did not recover a PCS key"
    );

    Ok(())
}
