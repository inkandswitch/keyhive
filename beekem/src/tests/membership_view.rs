use super::concurrent_membership_changes::{learn_from, new_path};
use crate::{
    cgka::{Cgka, MembershipView},
    error::CgkaError,
    id::MemberId,
    keys::ShareKeyMap,
    operation::{CgkaChange, CgkaOperation, CitationId},
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
use keyhive_crypto::verified::Verified;
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
    let add_fresh = group.add(m, fresh.id, fresh.pk).await;
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
    let learned = learn_from(group.replicas[m].doc_id, adversary, &paths);
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
async fn a_replay_lacking_a_membership_answer_doesnt_make_changes_until_answered() {
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
    /// Add a joiner, with a citation that doesn't also revoke anyone.
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
    undelivered: &mut Vec<Arc<Verified<CgkaOperation>>>,
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
    Arc<Verified<CgkaOperation>>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let member_count = 4;
    let mut group = Group::new(member_count, &mut rng).await;
    let joiners: Vec<_> = (0..JOINERS).map(|_| member(&mut rng)).collect();
    // Revocation `i` revokes member `1 + i % 3` and joiner `i`, as a revocation
    // also revokes the access its target granted. Member 0 is never revoked, so
    // it can author the final rotation.
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

/// Every citation in the history of `replica`.
fn cited(replica: &Cgka) -> BTreeSet<CitationId> {
    replica
        .ops_graph
        .cgka_ops
        .iter()
        .flat_map(|(_, op)| op.payload().citations().iter().copied())
        .collect()
}

/// Run `check` over 200 random runs.
fn for_random_runs(
    check: impl Fn(Group, Arc<Revocations>, Vec<Member>, Arc<Verified<CgkaOperation>>)
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
fn replicas_converge_and_remove_every_revoked_member_whatever_the_delivery_order() {
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
            known.insert(joiner.pk, joiner.sk.clone());
        }
        let paths: Vec<&PathChange> = replica
            .ops_graph
            .cgka_ops
            .iter()
            .filter_map(|(_, op)| match &op.payload().change {
                CgkaChange::Update { new_path, .. } => Some(&**new_path),
                _ => None,
            })
            .collect();
        let learned = learn_from(replica.doc_id, known, &paths);
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

#[tokio::test]
async fn a_view_changes_a_cgka_only_by_scheduling_a_replay_of_its_history() {
    let mut rng = StdRng::seed_from_u64(0xd00b_4444);
    let group = Group::new(2, &mut rng).await;
    let view = Arc::new(Revocations(BTreeMap::new()));

    let empty = Cgka::new(group.replicas[0].doc_id, group.id(0), ShareKeyMap::new());
    let mut viewed = empty.clone();
    viewed.set_membership_view(view.clone());
    assert_eq!(viewed, empty, "a view changed a CGKA with no history");

    let mut viewed = group.replicas[0].clone();
    viewed.set_membership_view(view);
    assert_ne!(
        viewed, group.replicas[0],
        "a view did not schedule a replay of the history"
    );
}

/// A view in which `revoke` removes `member` unless `regrant` is also cited.
#[derive(Debug)]
struct RevokedUnlessRegranted {
    revoke: CitationId,
    regrant: CitationId,
    member: MemberId,
}

impl MembershipView for RevokedUnlessRegranted {
    fn non_members(
        &self,
        cited: &BTreeSet<CitationId>,
        leaves: &BTreeSet<MemberId>,
    ) -> Option<BTreeSet<MemberId>> {
        let revoked = cited.contains(&self.revoke)
            && !cited.contains(&self.regrant)
            && leaves.contains(&self.member);
        Some(revoked.then_some(self.member).into_iter().collect())
    }
}

#[tokio::test]
async fn a_member_kept_by_a_concurrent_grant_can_read_the_next_update() {
    let mut rng = StdRng::seed_from_u64(0xd00b_3333);
    let mut group = Group::new(4, &mut rng).await;
    let (a, c, d) = (0, 2, 3);
    let revoke_c = CitationId([1; 32]);
    let regrant_c = CitationId([2; 32]);
    group.set_membership_view(Arc::new(RevokedUnlessRegranted {
        revoke: revoke_c,
        regrant: regrant_c,
        member: group.id(c),
    }));
    group.settle(a, &mut rng).await;

    // d sees c revoked and rotates with c's leaf blank, while a concurrently
    // cites a grant that keeps c in.
    let remove_c = group
        .remove_by_citations(d, BTreeSet::from([revoke_c]))
        .await;
    let rotation_by_d = group.rotate(d, &mut rng).await;
    let regrant = group
        .remove_by_citations(a, BTreeSet::from([regrant_c]))
        .await;
    for op in [&remove_c, &rotation_by_d] {
        group.deliver(op, &[0, 1, 2]);
    }
    group.deliver(&regrant, &[1, 2, 3]);
    let heal = group.rotate(a, &mut rng).await;
    group.broadcast(&heal);

    assert_everyone_kept_and_c_reads_heal_from_a(
        &mut group,
        a,
        c,
        "after a heal merging a revocation and a concurrent grant",
    );
}

/// Revokes `member` when both `r1` and `r2` are cited and `regrant` is not.
#[derive(Debug)]
struct RevokedByBoth {
    r1: CitationId,
    r2: CitationId,
    regrant: CitationId,
    member: MemberId,
}

impl MembershipView for RevokedByBoth {
    fn non_members(
        &self,
        cited: &BTreeSet<CitationId>,
        leaves: &BTreeSet<MemberId>,
    ) -> Option<BTreeSet<MemberId>> {
        let revoked = cited.contains(&self.r1)
            && cited.contains(&self.r2)
            && !cited.contains(&self.regrant)
            && leaves.contains(&self.member);
        Some(revoked.then_some(self.member).into_iter().collect())
    }
}

#[tokio::test]
async fn a_member_its_updater_dropped_under_two_concurrent_revocations_can_read_the_next_update() {
    let mut rng = StdRng::seed_from_u64(0xd00b_3335);
    let mut group = Group::new(4, &mut rng).await;
    let (a, b, c, d) = (0, 1, 2, 3);
    let r1 = CitationId([1; 32]);
    let r2 = CitationId([2; 32]);
    let regrant_c = CitationId([3; 32]);
    group.set_membership_view(Arc::new(RevokedByBoth {
        r1,
        r2,
        regrant: regrant_c,
        member: group.id(c),
    }));
    group.settle(a, &mut rng).await;

    // d merges b's revocation with its own, which drops c, then cites the
    // grant and rotates. a rotates concurrently with all of it.
    let by_d = group.remove_by_citations(d, BTreeSet::from([r1])).await;
    let by_b = group.remove_by_citations(b, BTreeSet::from([r2])).await;
    let rotation_by_a = group.rotate(a, &mut rng).await;
    group.deliver(&by_b, &[d]);
    let regrant = group
        .remove_by_citations(d, BTreeSet::from([regrant_c]))
        .await;
    let rotation_by_d = group.rotate(d, &mut rng).await;
    group.deliver(&by_d, &[a, b, c]);
    group.deliver(&by_b, &[a, c]);
    for op in [&regrant, &rotation_by_d] {
        group.deliver(op, &[a, b, c]);
    }
    group.deliver(&rotation_by_a, &[b, c, d]);
    let heal = group.rotate(a, &mut rng).await;
    group.broadcast(&heal);

    assert_everyone_kept_and_c_reads_heal_from_a(
        &mut group,
        a,
        c,
        "after a heal merging two revocations that together dropped a member",
    );
}

/// Checks that the replicas pass [`Group::check`] and keep all four members,
/// and that `c` derives the root secret of `a`'s last update.
fn assert_everyone_kept_and_c_reads_heal_from_a(
    group: &mut Group,
    a: usize,
    c: usize,
    context: &str,
) {
    group.check(context);
    group.assert_members(context, &["a", "b", "c", "d"]);
    let expected = group.replicas[a].decrypt_current_group_secret().unwrap();
    assert_eq!(
        group.replicas[c].decrypt_current_group_secret().ok(),
        Some(expected),
        "{context}: c is in the tree but cannot derive the root secret"
    );
}
