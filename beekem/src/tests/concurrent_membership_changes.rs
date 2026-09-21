//! Tests concurrent membership changes.

use crate::{
    keys::{NodeKey, ShareKeyMap},
    operation::CgkaOperation,
    test_utils::{member, Group, Member},
};
use alloc::{collections::BTreeSet, format, string::ToString, sync::Arc, vec::Vec};
use bolero::{gen, TypeGenerator, ValueGenerator};
use future_form::Local;
use keyhive_crypto::{share_key::ShareSecretKey, signed::Signed};
use rand::{rngs::StdRng, SeedableRng};

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
