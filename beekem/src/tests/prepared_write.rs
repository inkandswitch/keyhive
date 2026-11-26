//! Laws for preparing a write and applying it later.
//!
//! 1. Preparing changes nothing: the group after a prepare, dropped, equals the
//!    group before.
//! 2. Prepare then apply is the one-shot `group_secret_for_write`: same secret,
//!    same origin, same rotation, same resulting group.
//! 3. A plan made from an older graph is refused at apply and the refusal
//!    changes nothing.
//! 4. Of any number of plans made from one state, at most one rotation lands.
//!
//! The oracle for 2 is the one-shot call itself, run on a copy of the same group
//! with an identically seeded generator. The proptest drives both through random
//! sequences of rotations, deliveries and writes among concurrent replicas, and
//! compares every step and the final replicas.

use crate::{
    cgka::{Cgka, NoImplicitRemoves},
    error::CgkaError,
    operation::CgkaOperation,
    test_utils::Group,
};
use alloc::{sync::Arc, vec::Vec};
use future_form::Local;
use keyhive_crypto::{digest::Digest, verified::Verified};
use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

type Replica = Cgka<NoImplicitRemoves>;
type Op = Arc<Verified<CgkaOperation>>;

const MEMBERS: usize = 3;

#[derive(Clone, Copy, Debug)]
enum Step {
    /// The member rotates without a write, producing an op that is not delivered yet.
    Rotate(usize),
    /// Deliver the pooled op (index modulo the pool) to a replica, if its
    /// predecessors are there and it has not got it.
    Deliver(usize, usize),
    /// The member writes, rotating if it has to.
    Write(usize),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (0..MEMBERS).prop_map(Step::Rotate),
        (0..16usize, 0..MEMBERS).prop_map(|(op, to)| Step::Deliver(op, to)),
        (0..MEMBERS).prop_map(Step::Write),
    ]
}

/// What a write returned, minus the secrets that cannot be compared directly.
#[derive(Debug, PartialEq, Eq)]
struct Written {
    pcs_key: Digest<crate::pcs_key::PcsKey>,
    origin: Digest<CgkaOperation>,
    rotation: Option<Digest<CgkaOperation>>,
}

/// A group of three, settled, as replicas and their signers.
async fn start() -> (Group<NoImplicitRemoves>, Vec<Replica>) {
    let mut rng = StdRng::seed_from_u64(0x9e_0001);
    let mut group = Group::new(MEMBERS, &mut rng).await;
    group.settle(0, &mut rng).await;
    let replicas = group.replicas.clone();
    (group, replicas)
}

/// Run `steps`, writing in one shot or by prepare and apply. Returns what each
/// write gave and the final replicas.
async fn run(steps: &[Step], prepared: bool) -> (Vec<Written>, Vec<Replica>) {
    let (group, mut replicas) = start().await;
    let mut rng = StdRng::seed_from_u64(0x9e_0002);
    // Racing plans draw from their own generator so the writes' stream is the
    // same in both modes.
    let mut racing_rng = StdRng::seed_from_u64(0x9e_0003);
    let mut pool: Vec<Op> = Vec::new();
    let mut written = Vec::new();
    for step in steps {
        match *step {
            Step::Rotate(m) => {
                let sk = keyhive_crypto::share_key::ShareSecretKey::generate(&mut rng);
                let (_, op, _) = replicas[m]
                    .update::<Local, _, _>(sk.share_key(), sk, &group.members[m].signer, &mut rng)
                    .await
                    .unwrap();
                pool.push(Arc::new(op));
            }
            Step::Deliver(i, to) => {
                if pool.is_empty() {
                    continue;
                }
                let op = pool[i % pool.len()].clone();
                let ready = replicas[to].contains_all(op.payload().predecessors.iter());
                if ready && !replicas[to].contains_all([&op.digest()]) {
                    replicas[to].merge_concurrent_operation(op).unwrap();
                }
            }
            Step::Write(m) => {
                let signer = &group.members[m].signer;
                let (pcs_key, origin, rotation) = if prepared {
                    let before = replicas[m].clone();
                    // A plan that is dropped leaves no trace.
                    let dropped = replicas[m]
                        .prepare_write::<Local, _, _>(signer, &mut racing_rng)
                        .await
                        .unwrap();
                    drop(dropped);
                    assert!(replicas[m] == before, "a dropped plan changed the group");
                    let plan = replicas[m]
                        .prepare_write::<Local, _, _>(signer, &mut rng)
                        .await
                        .unwrap();
                    let racing = replicas[m]
                        .prepare_write::<Local, _, _>(signer, &mut racing_rng)
                        .await
                        .unwrap();
                    let (pcs_key, origin) = (plan.pcs_key().clone(), plan.origin());
                    let rotation = replicas[m].apply_write(plan).unwrap().map(|(op, _)| op);
                    // At most one of the racing plans lands.
                    let after = replicas[m].clone();
                    match (rotation.is_some(), replicas[m].apply_write(racing)) {
                        (true, Err(CgkaError::StaleWrite)) | (false, Ok(None)) => {}
                        (rotated, other) => panic!(
                            "a racing plan after a write that rotated={rotated} gave {:?}",
                            other.map(|r| r.map(|(op, _)| op.digest()))
                        ),
                    }
                    assert!(replicas[m] == after, "the racing plan changed the group");
                    (pcs_key, origin, rotation)
                } else {
                    let (pcs_key, origin, rotation) = replicas[m]
                        .group_secret_for_write::<Local, _, _>(signer, &mut rng)
                        .await
                        .unwrap();
                    (pcs_key, origin, rotation.map(|(op, _)| op))
                };
                written.push(Written {
                    pcs_key: pcs_key.digest(),
                    origin,
                    rotation: rotation.as_ref().map(|op| op.digest()),
                });
                pool.extend(rotation.map(Arc::new));
            }
        }
    }
    (written, replicas)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    /// Laws 1, 2 and 4 over random sequences: every write and every replica
    /// agrees between one-shot and prepare+apply.
    #[test]
    fn prepare_and_apply_equals_one_shot_over_random_sequences(
        steps in prop::collection::vec(step(), 0..24)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let (one_shot, one_shot_replicas) = runtime.block_on(run(&steps, false));
        let (prepared, prepared_replicas) = runtime.block_on(run(&steps, true));
        prop_assert_eq!(one_shot, prepared);
        prop_assert!(one_shot_replicas == prepared_replicas, "final replicas differ");
    }
}

/// Law 3: a plan refused as stale changes nothing, and preparing again works.
#[tokio::test]
async fn law_3_a_plan_from_an_older_graph_is_refused_and_changes_nothing() {
    let (mut group, mut replicas) = start().await;
    let mut rng = StdRng::seed_from_u64(0x9e_0004);
    let plan = replicas[1]
        .prepare_write::<Local, _, _>(&group.members[1].signer, &mut rng)
        .await
        .unwrap();

    // Another member's update reaches member 1 after the plan was made.
    let concurrent = group.rotate(2, &mut rng).await;
    replicas[1].merge_concurrent_operation(concurrent).unwrap();
    let before = replicas[1].clone();

    assert!(matches!(
        replicas[1].apply_write(plan),
        Err(CgkaError::StaleWrite)
    ));
    assert!(replicas[1] == before, "a refused plan changed the group");

    let fresh = replicas[1]
        .prepare_write::<Local, _, _>(&group.members[1].signer, &mut rng)
        .await
        .unwrap();
    replicas[1].apply_write(fresh).unwrap();
}
