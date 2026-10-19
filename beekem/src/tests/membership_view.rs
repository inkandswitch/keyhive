use super::concurrent_membership_changes::{learn_from, new_path};
use crate::{
    cgka::{Cgka, MembershipView},
    error::CgkaError,
    id::MemberId,
    keys::ShareKeyMap,
    operation::{CgkaOperation, CitationId},
    test_utils::{member, Group, Member},
    tree::PathChange,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    sync::Arc,
    vec::Vec,
};
use bolero::{gen, TypeGenerator};
use future_form::Local;
use keyhive_crypto::signed::Signed;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::sync::Mutex;

/// A view in which each citation revokes a fixed set of members.
#[derive(Debug)]
struct Revocations(BTreeMap<CitationId, BTreeSet<MemberId>>);

impl MembershipView for Revocations {
    fn non_members(
        &self,
        cited: &BTreeSet<CitationId>,
        leaves: &BTreeSet<MemberId>,
    ) -> Option<BTreeSet<MemberId>> {
        Some(
            cited
                .iter()
                .filter_map(|c| self.0.get(c))
                .flatten()
                .filter(|id| leaves.contains(id))
                .copied()
                .collect(),
        )
    }
}

#[tokio::test]
async fn a_member_added_concurrently_with_its_adders_revocation_is_removed_and_excluded_from_the_heal(
) {
    let mut rng = StdRng::seed_from_u64(0xd00b_2222);
    let mut group = Group::new(3, &mut rng).await;
    let (a, b, m) = (0, 1, 2);
    let fresh = member(&mut rng);
    group.names.insert(fresh.id, "fresh".to_string());
    // Revoking `m` also revokes everyone whose access `m` granted, which here is `fresh`.
    let revoke_m = CitationId([1; 32]);
    let grant_fresh = CitationId([2; 32]);
    group.set_membership_view(Arc::new(Revocations(BTreeMap::from([(
        revoke_m,
        BTreeSet::from([group.id(m), fresh.id]),
    )]))));
    group.settle(a, &mut rng).await;

    let remove_m = group
        .remove_by_citations(a, BTreeSet::from([revoke_m]))
        .await;
    group.deliver(&remove_m, &[b]);
    // `m` has not seen its removal, so these are concurrent with it.
    let add_fresh = group
        .add_with(m, fresh.id, fresh.pk, BTreeSet::from([grant_fresh]))
        .await;
    let rotation_by_m = group.rotate(m, &mut rng).await;
    for op in [&add_fresh, &rotation_by_m] {
        group.deliver(op, &[a, b]);
    }
    group.deliver(&remove_m, &[m]);
    let heal = group.rotate(b, &mut rng).await;
    group.broadcast(&heal);

    let context = "after a heal following a concurrent add by a revoked member";
    group.check(context);
    group.assert_members(context, &["a", "b"]);

    let mut adversary = group.replicas[m].owner_sks.clone();
    let mut fresh_sks = ShareKeyMap::new();
    fresh_sks.insert(fresh.pk, fresh.sk);
    adversary.extend(&fresh_sks);
    let paths: Vec<&PathChange> = [&rotation_by_m, &heal]
        .into_iter()
        .map(|op| new_path(op))
        .collect();
    let learned = learn_from(adversary, &paths);
    for (idx, node) in &new_path(&heal).path {
        for version in node.versions() {
            assert!(
                !learned.contains_key(&version.pk),
                "{context}: m and fresh learned the secret at inner node {idx} of the heal"
            );
        }
    }
}

/// [`Revocations`] that answers only for the sets passed to `fetch_only` or for every
/// set until it is called.
#[derive(Debug)]
struct Fetched {
    revocations: Revocations,
    fetched: Mutex<Option<BTreeSet<BTreeSet<CitationId>>>>,
}

impl Fetched {
    fn fetch_only(&self, sets: impl IntoIterator<Item = BTreeSet<CitationId>>) {
        *self.fetched.lock().unwrap() = Some(sets.into_iter().collect());
    }
}

impl MembershipView for Fetched {
    fn non_members(
        &self,
        cited: &BTreeSet<CitationId>,
        leaves: &BTreeSet<MemberId>,
    ) -> Option<BTreeSet<MemberId>> {
        if let Some(fetched) = &*self.fetched.lock().unwrap() {
            if !fetched.contains(cited) {
                return None;
            }
        }
        self.revocations.non_members(cited, leaves)
    }
}

#[tokio::test]
async fn a_removal_without_an_answer_waits_for_a_replay() {
    let mut rng = StdRng::seed_from_u64(0xd00b_3333);
    let mut group = Group::new(3, &mut rng).await;
    let (a, m) = (0, 2);
    let revoke_m = CitationId([1; 32]);
    let view = Arc::new(Fetched {
        revocations: Revocations(BTreeMap::from([(revoke_m, BTreeSet::from([group.id(m)]))])),
        fetched: Mutex::new(None),
    });
    group.set_membership_view(view.clone());
    group.settle(a, &mut rng).await;

    view.fetch_only([]);
    group
        .remove_by_citations(a, BTreeSet::from([revoke_m]))
        .await;
    let before = group.replicas[a].clone();
    let lacking = group.replicas[a].member_ids().map(|ids| ids.count());
    assert!(
        matches!(lacking, Err(CgkaError::MembershipUnknown(_))),
        "{lacking:?}"
    );
    assert_eq!(
        group.replicas[a], before,
        "a replay without an answer changed the tree"
    );

    view.fetch_only(group.replicas[a].membership_sets().unwrap());
    let members: BTreeSet<MemberId> = group.replicas[a]
        .member_ids()
        .expect("the sets a replay asks about are answered")
        .collect();
    assert!(!members.contains(&group.id(m)), "m was not removed");
}

/// One step of a random run. An operation, then possibly a sync.
#[derive(Clone, Copy, Debug, TypeGenerator)]
struct Step {
    op: StepOp,
    deliver_after: bool,
}

#[derive(Clone, Copy, Debug, TypeGenerator)]
enum StepOp {
    /// Add a joiner, citing a certificate that revokes no one.
    Add {
        joiner: u8,
    },
    /// Remove without explicit removal target, citing a revocation of one or more members.
    Revoke {
        revocation: u8,
    },
    Update,
}

const JOINERS: usize = 3;
const REVOCATIONS: usize = 3;

/// Deliver `undelivered` to each replica in its own shuffled order, retrying
/// what is not yet causally ready.
fn deliver_shuffled(
    group: &mut Group,
    undelivered: &mut Vec<Arc<Signed<CgkaOperation>>>,
    rng: &mut StdRng,
) {
    for replica in 0..group.replicas.len() {
        let mut pending = undelivered.clone();
        pending.shuffle(rng);
        while !pending.is_empty() {
            let before = pending.len();
            pending.retain(|op| !group.try_deliver(op, &[replica]).is_empty());
            assert!(
                pending.len() < before,
                "an operation never became deliverable"
            );
        }
    }
    undelivered.clear();
}

async fn run(
    seed: u64,
    steps: &[Step],
) -> (
    Group,
    Arc<Revocations>,
    Vec<Member>,
    Arc<Signed<CgkaOperation>>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let member_count = 4;
    let mut group = Group::new(member_count, &mut rng).await;
    let joiners: Vec<_> = (0..JOINERS).map(|_| member(&mut rng)).collect();
    // Revocation `i` revokes a member other than 0 and possibly a joiner, as a
    // revocation cascades to the access its target granted.
    let revoked: Vec<BTreeSet<MemberId>> = (0..REVOCATIONS)
        .map(|i| BTreeSet::from([group.id(1 + i % (member_count - 1)), joiners[i].id]))
        .collect();
    let revocation = |i: usize| CitationId([1 + i as u8; 32]);
    let grant = CitationId([0xff; 32]);
    let view = Arc::new(Revocations(
        (0..REVOCATIONS)
            .map(|i| (revocation(i), revoked[i].clone()))
            .collect(),
    ));
    group.set_membership_view(view.clone());

    let mut undelivered = Vec::new();
    for (position, step) in steps.iter().enumerate() {
        let author = position % member_count;
        let op = match step.op {
            StepOp::Add { joiner } => {
                let joiner = &joiners[joiner as usize % JOINERS];
                group.replicas[author]
                    .add::<Local, _>(
                        joiner.id,
                        joiner.pk,
                        None,
                        BTreeSet::from([grant]),
                        &group.members[author].signer,
                    )
                    .await
                    .expect("creating the add succeeds")
                    .map(Arc::new)
            }
            StepOp::Revoke { revocation: i } => Some(
                group
                    .remove_by_citations(
                        author,
                        BTreeSet::from([revocation(i as usize % REVOCATIONS)]),
                    )
                    .await,
            ),
            StepOp::Update => group.try_rotate(author, &mut rng).await,
        };
        undelivered.extend(op);
        if step.deliver_after {
            deliver_shuffled(&mut group, &mut undelivered, &mut rng);
        }
    }
    deliver_shuffled(&mut group, &mut undelivered, &mut rng);
    let final_rotation = group.rotate(0, &mut rng).await;
    group.broadcast(&final_rotation);
    (group, view, joiners, final_rotation)
}

/// Every certificate the history of `replica` cites.
fn cited(replica: &Cgka) -> BTreeSet<CitationId> {
    replica
        .ops_graph
        .cgka_ops
        .iter()
        .flat_map(|(_, op)| op.payload.citations().iter().copied())
        .collect()
}

/// Run `check` over 200 random runs.
fn for_random_runs(
    check: impl Fn(Group, Arc<Revocations>, Vec<Member>, Arc<Signed<CgkaOperation>>)
        + core::panic::RefUnwindSafe,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("building a runtime succeeds");
    bolero::check!()
        .with_iterations(200)
        .with_generator((gen::<u64>(), gen::<Vec<Step>>().with().len(3..=12usize)))
        .for_each(|(seed, steps)| {
            let (group, view, joiners, final_rotation) = runtime.block_on(run(*seed, steps));
            check(group, view, joiners, final_rotation);
        });
}

#[test]
fn replicas_converge_on_the_same_removes_whatever_the_delivery_order() {
    for_random_runs(|group, view, _, _| {
        let context = "after every operation reached every replica";
        group.check(context);
        group.assert_trees_match_replay(context);
        let replica = &group.replicas[0];
        let leaves: BTreeSet<MemberId> = replica.tree.member_ids().collect();
        let revoked_leaves = view
            .non_members(&cited(replica), &leaves)
            .expect("the view answers every set");
        assert!(
            revoked_leaves.is_empty(),
            "{context}: a revoked member is still in the tree"
        );
    });
}

#[test]
fn revoked_members_learn_nothing_of_a_rotation_after_their_removal() {
    for_random_runs(|group, view, joiners, final_rotation| {
        let replica = &group.replicas[0];
        let everyone: BTreeSet<MemberId> =
            group.members.iter().chain(&joiners).map(|m| m.id).collect();
        let revoked = view
            .non_members(&cited(replica), &everyone)
            .expect("the view answers every set");
        let mut known = ShareKeyMap::new();
        for (member, member_replica) in group.members.iter().zip(&group.replicas) {
            if revoked.contains(&member.id) {
                known.extend(&member_replica.owner_sks);
            }
        }
        for joiner in joiners.iter().filter(|j| revoked.contains(&j.id)) {
            known.insert(joiner.pk, joiner.sk);
        }
        let paths: Vec<&PathChange> = replica
            .ops_graph
            .cgka_ops
            .iter()
            .filter_map(|(_, op)| match op.payload() {
                CgkaOperation::Update { new_path, .. } => Some(&**new_path),
                _ => None,
            })
            .collect();
        let learned = learn_from(known, &paths);
        for (idx, node) in &new_path(&final_rotation).path {
            for version in node.versions() {
                assert!(
                    !learned.contains_key(&version.pk),
                    "revoked members learned inner node {idx} of the final rotation"
                );
            }
        }
    });
}
