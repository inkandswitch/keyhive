//! Regression tests for concurrent membership changes. They cover seven defects,
//! three of which were reported as inkandswitch/keyhive#218, #219 and #220, plus
//! one control test for the sequential case.
//!
//! This has to be a child module of `cgka`, because `Cgka::tree` and
//! `Cgka::pcs_key_from_tree_root` are private.
//!
//! Two of these defects panic in a debug build and corrupt the tree silently in
//! a release build, from the same statement, so matching on panic text would
//! catch neither the release case nor the difference between the defects. Every
//! test here asserts tree state instead, via [`Group::check`].
//!
//! Where a defect only shows up under one of the two digest-determined orders
//! for an epoch, the test sweeps seeds and asserts that both orders came up.
//! Otherwise passing would only mean the ordering never picked the bad branch.

use crate::{
    cgka::Cgka,
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::ShareKeyMap,
    operation::CgkaOperation,
    pcs_key::PcsKey,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use future_form::Local;
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{rngs::StdRng, SeedableRng};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Member {
    id: MemberId,
    signer: MemorySigner,
    pk: ShareKey,
    sk: ShareSecretKey,
}

fn member(rng: &mut StdRng) -> Member {
    let signer = MemorySigner::generate(rng);
    let id = MemberId(signer.verifying_key());
    let sk = ShareSecretKey::generate(rng);
    let pk = sk.share_key();
    Member { id, signer, pk, sk }
}

/// Replicas of one tree, each holding its own [`Cgka`]. Operations are authored
/// once and delivered explicitly, so digests match as they would on the wire and
/// a replica lags by exactly the operations withheld from it.
struct Group {
    members: Vec<Member>,
    replicas: Vec<Cgka>,
    /// Short names, for readable failures.
    names: BTreeMap<MemberId, String>,
}

impl Group {
    async fn found(n: usize, rng: &mut StdRng) -> Group {
        let doc_signer = MemorySigner::generate(rng);
        let doc_id = TreeId(doc_signer.verifying_key());
        let members: Vec<Member> = (0..n).map(|_| member(rng)).collect();

        let mut founder =
            Cgka::new::<Local, _>(doc_id, members[0].id, members[0].pk, &members[0].signer)
                .await
                .expect("founding the tree succeeds");
        founder.owner_sks.insert(members[0].pk, members[0].sk);
        let init_add_op = founder.init_add_op();

        let mut replicas = vec![founder];
        for m in &members[1..] {
            let mut sks = ShareKeyMap::new();
            sks.insert(m.pk, m.sk);
            replicas.push(
                Cgka::new_from_init_add(doc_id, members[0].id, members[0].pk, init_add_op.clone())
                    .expect("seeding a replica from the init add succeeds")
                    .with_new_owner(m.id, sks)
                    .expect("re-owning a replica succeeds"),
            );
        }

        let names = members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.id, name_for(i)))
            .collect();
        let mut group = Group {
            members,
            replicas,
            names,
        };
        for i in 1..n {
            let op = group.add(0, group.members[i].id, group.members[i].pk).await;
            group.broadcast(&op);
        }
        group
    }

    /// Author an add on `author`'s replica without delivering it.
    async fn add(
        &mut self,
        author: usize,
        id: MemberId,
        pk: ShareKey,
    ) -> Arc<Signed<CgkaOperation>> {
        let signer = &self.members[author].signer;
        let op = self.replicas[author]
            .add::<Local, _>(id, pk, signer)
            .await
            .expect("authoring the add succeeds")
            .expect("the added member is new");
        Arc::new(op)
    }

    /// Author a removal on `author`'s replica without delivering it.
    async fn remove(&mut self, author: usize, victim: MemberId) -> Arc<Signed<CgkaOperation>> {
        let signer = &self.members[author].signer;
        let op = self.replicas[author]
            .remove::<Local, _>(victim, signer)
            .await
            .expect("authoring the removal succeeds")
            .expect("the removed member is present");
        Arc::new(op)
    }

    /// Author a key rotation on `author`'s replica. Rotating is what makes a
    /// replica replay a buffered concurrent epoch.
    async fn rotate(
        &mut self,
        author: usize,
        rng: &mut StdRng,
    ) -> Result<Arc<Signed<CgkaOperation>>, CgkaError> {
        let sk = ShareSecretKey::generate(rng);
        let pk = sk.share_key();
        let signer = &self.members[author].signer;
        let (_pcs_key, op) = self.replicas[author]
            .update::<Local, _, StdRng>(pk, sk, signer, rng)
            .await?;
        Ok(Arc::new(op))
    }

    fn deliver(&mut self, op: &Arc<Signed<CgkaOperation>>, to: &[usize]) {
        for &i in to {
            self.replicas[i]
                .merge_concurrent_operation(op.clone())
                .expect("operations are delivered in causal order");
        }
    }

    fn broadcast(&mut self, op: &Arc<Signed<CgkaOperation>>) {
        self.deliver(op, &Vec::from_iter(0..self.replicas.len()));
    }

    fn id(&self, i: usize) -> MemberId {
        self.members[i].id
    }

    fn label(&self, id: &MemberId) -> String {
        self.names
            .get(id)
            .cloned()
            .unwrap_or_else(|| format!("{id:?}"))
    }

    /// Who sits at which leaf on `replica`, as a string like `"a@0 b@1 d@2"`.
    fn seating(&self, replica: usize) -> String {
        let mut seats: Vec<(u32, String)> = self.replicas[replica]
            .tree
            .seating()
            .into_iter()
            .map(|(id, idx)| (idx, self.label(&id)))
            .collect();
        seats.sort();
        seats
            .iter()
            .map(|(idx, name)| format!("{name}@{idx}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every replica's tree holds together, and they all agree. Convergence is
    /// what these reports are about, and what a single-replica assertion misses.
    fn check(&self, context: &str) {
        for (i, replica) in self.replicas.iter().enumerate() {
            let violations = replica.tree.invariant_violations();
            assert!(
                violations.is_empty(),
                "{context}: replica {i}'s tree is corrupt. {}",
                violations.join(". ")
            );
        }
        for i in 1..self.replicas.len() {
            assert!(
                self.replicas[i].tree == self.replicas[0].tree,
                "{context}: replicas diverged. Replica 0 seats {}, replica {i} seats {}",
                self.seating(0),
                self.seating(i)
            );
        }
    }

    fn assert_members(&self, context: &str, expected: &[&str]) {
        let mut want: Vec<&str> = expected.to_vec();
        want.sort();
        let mut got: Vec<String> = self.replicas[0]
            .tree
            .seating()
            .into_iter()
            .map(|(id, _)| self.label(&id))
            .collect();
        got.sort();
        assert_eq!(
            got.join(" "),
            want.join(" "),
            "{context}: wrong membership, seated as {}",
            self.seating(0)
        );
    }

    /// Every replica whose owner is still a member derives the same root key, and
    /// no replica whose owner was removed derives one. A tree can satisfy every
    /// structural invariant and still be useless, so this is what callers need.
    fn assert_key_agreement(&mut self, context: &str) {
        let mut agreed: Option<PcsKey> = None;
        for i in 0..self.replicas.len() {
            let owner = self.replicas[i].owner_id;
            let is_member = self.replicas[i].tree.contains_id(&owner);
            let key = self.replicas[i].pcs_key_from_tree_root();
            let name = self.label(&owner);
            if !is_member {
                assert!(
                    key.is_err(),
                    "{context}: {name} was removed but still derives the root key"
                );
                continue;
            }
            let key = key.unwrap_or_else(|e| {
                panic!("{context}: {name} is still a member but cannot derive the root key. {e:?}")
            });
            match agreed {
                None => agreed = Some(key),
                Some(first) => assert!(
                    key == first,
                    "{context}: {name} derived a different root key"
                ),
            }
        }
        assert!(
            agreed.is_some(),
            "{context}: no replica was left to derive a key"
        );
    }
}

fn name_for(i: usize) -> String {
    ["a", "b", "c", "d", "e", "f", "g", "h"][i].to_string()
}

// ---------------------------------------------------------------------------
// #218: concurrent removals must not wedge the operation graph
// ---------------------------------------------------------------------------

/// Each member of a three-member group concurrently removes one other, so the
/// merged history accounts for everyone.
///
/// Replaying that used to fail. `apply_epochs` applies an epoch's removals one at
/// a time, so the tree passes through a one-member state, and `BeeKem::remove_id`
/// refused to remove the last member. Since `add`, `remove` and `update` all
/// replay first and the graph is durable, the group could never make progress
/// again. Emptying the group is the only reading of that history which does not
/// keep someone the history removed.
#[tokio::test]
async fn concurrent_removals_empty_the_group() {
    let mut rng = StdRng::seed_from_u64(0xd1ff_0000);
    let mut group = Group::found(3, &mut rng).await;
    let (a, b, c) = (group.id(0), group.id(1), group.id(2));

    let mut removals = Vec::new();
    for (author, victim) in [(0usize, b), (1, c), (2, a)] {
        removals.push(group.remove(author, victim).await);
    }
    for op in removals.iter() {
        group.broadcast(op);
    }

    let joiner = member(&mut rng);
    let repair = group.replicas[0]
        .add::<Local, _>(joiner.id, joiner.pk, &group.members[0].signer)
        .await
        .unwrap_or_else(|e| {
            panic!("three concurrent removals left the tree unmaterializable. {e:?}")
        })
        .expect("the joiner is new");

    // This add causally follows all three removals, so delivering it also
    // makes the other two replicas replay.
    group.broadcast(&Arc::new(repair));

    group.names.insert(joiner.id, "joiner".to_string());
    let context = "after three concurrent removals and a repair";
    group.check(context);
    group.assert_members(context, &["joiner"]);
}

/// Control for the test above. Applied one at a time, the authoring guard refuses
/// the last removal and the group stays usable, which is what the concurrent case
/// used to lose.
#[tokio::test]
async fn sequential_removals_stop_at_the_last_member() {
    let mut rng = StdRng::seed_from_u64(0xd1ff_0000);
    let mut group = Group::found(3, &mut rng).await;
    let (a, b, c) = (group.id(0), group.id(1), group.id(2));

    for victim in [b, c] {
        let op = group.remove(0, victim).await;
        group.broadcast(&op);
    }

    let refused = group.replicas[0]
        .remove::<Local, _>(a, &group.members[0].signer)
        .await;
    assert!(
        matches!(refused, Err(CgkaError::RemoveLastMember)),
        "expected the authoring guard to refuse, got {refused:?}"
    );

    let joiner = member(&mut rng);
    group.replicas[0]
        .add::<Local, _>(joiner.id, joiner.pk, &group.members[0].signer)
        .await
        .expect("the group still makes progress after a refused removal");
}

// ---------------------------------------------------------------------------
// Duplicate concurrent membership changes
// ---------------------------------------------------------------------------

/// Two members concurrently remove the same third member. Replay applied both,
/// and the second found nothing to remove, so `remove_id` returned
/// `IdentifierNotFound` and wedged the graph the same way #218 did.
#[tokio::test]
async fn duplicate_removals_do_not_wedge() {
    let mut rng = StdRng::seed_from_u64(0xd00b_0000);
    let mut group = Group::found(3, &mut rng).await;
    let c = group.id(2);

    let by_a = group.remove(0, c).await;
    let by_b = group.remove(1, c).await;
    group.broadcast(&by_a);
    group.broadcast(&by_b);

    let rotation = group.rotate(0, &mut rng).await.unwrap_or_else(|e| {
        panic!("two concurrent removals of one member left the tree unmaterializable. {e:?}")
    });
    group.broadcast(&rotation);

    let context = "after two concurrent removals of the same member";
    group.check(context);
    group.assert_members(context, &["a", "b"]);
    group.assert_key_agreement(context);
}

/// Two members concurrently add the same new member. Replay applied both adds
/// with `push_leaf`, so `d` held two leaves while `id_to_leaf_idx` pointed at
/// one. Removing `d` later blanked that one and left the other holding `d`'s
/// public key.
///
/// A non-blank leaf is in the resolution of its ancestors' siblings, so every
/// later rotation encrypts new path secrets to that leaf's key, which `d` still
/// holds. A removed member kept read access to the group.
#[tokio::test]
async fn duplicate_adds_leave_one_leaf() {
    let mut rng = StdRng::seed_from_u64(0xd00b_1111);
    let mut group = Group::found(3, &mut rng).await;
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());
    // Distinct prekeys, so the two adds are distinguishable. Whichever the digest
    // order applies second is dropped, and an orphan leaf would hold the loser.
    let other_pk = ShareSecretKey::generate(&mut rng).share_key();

    let by_a = group.add(0, d.id, d.pk).await;
    let by_b = group.add(1, d.id, other_pk).await;
    group.broadcast(&by_a);
    group.broadcast(&by_b);
    let rotation = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.broadcast(&rotation);

    let context = "after two concurrent adds of the same member";
    group.check(context);
    group.assert_members(context, &["a", "b", "c", "d"]);

    // The consequence worth testing: once `d` is removed, no leaf anywhere
    // may still hold `d`'s key.
    let remove_d = group.remove(0, d.id).await;
    group.broadcast(&remove_d);
    let rotation = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.broadcast(&rotation);

    let context = "after removing a concurrently double-added member";
    group.check(context);
    group.assert_members(context, &["a", "b", "c"]);
    group.assert_key_agreement(context);
}

/// `Cgka::add` used to ask whether the member was already seated before replaying,
/// so a concurrent add of the same id still sitting unapplied in the graph did not
/// count. The replay then seated the member and the local push seated them again,
/// leaving the orphan leaf that `duplicate_adds_leave_one_leaf` describes. This
/// reaches it through authoring rather than through the merge rule.
#[tokio::test]
async fn local_add_sees_a_buffered_concurrent_add() {
    let mut rng = StdRng::seed_from_u64(0xb0f0_0000);
    let mut group = Group::found(3, &mut rng).await;
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());

    // `b` adds `d`, and `a` rotates first, so the add reaches `a` as concurrent
    // and is buffered rather than applied.
    let add_by_b = group.add(1, d.id, d.pk).await;
    let rotation = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.deliver(&add_by_b, &[0]);

    let local = group.replicas[0]
        .add::<Local, _>(d.id, d.pk, &group.members[0].signer)
        .await
        .expect("authoring the add succeeds");
    assert!(
        local.is_none(),
        "a seated d again, though a concurrent add of d was already in its graph"
    );

    for op in [&add_by_b, &rotation] {
        group.broadcast(op);
    }
    let settle = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.broadcast(&settle);

    let context = "after adding a member a buffered concurrent add already covered";
    group.check(context);
    group.assert_members(context, &["a", "b", "c", "d"]);
    group.assert_key_agreement(context);
}

/// `Cgka::remove` had the same ordering problem, and failed harder. A concurrent
/// removal of the same member left the local removal calling `remove_id` on
/// someone the replay had already taken out, which returned
/// `CgkaError::IdentifierNotFound`. `keyhive_core` propagates that with `?`, so a
/// document-level revoke failed outright.
#[tokio::test]
async fn local_remove_sees_a_buffered_concurrent_remove() {
    let mut rng = StdRng::seed_from_u64(0xb0f1_1111);
    let mut group = Group::found(3, &mut rng).await;
    let c = group.id(2);

    let remove_by_b = group.remove(1, c).await;
    let rotation = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.deliver(&remove_by_b, &[0]);

    let local = group.replicas[0]
        .remove::<Local, _>(c, &group.members[0].signer)
        .await;
    assert!(
        matches!(local, Ok(None)),
        "removing a member a buffered concurrent removal already covered should be \
         a no-op, got {local:?}"
    );

    for op in [&remove_by_b, &rotation] {
        group.broadcast(op);
    }
    let settle = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.broadcast(&settle);

    let context = "after removing a member a buffered concurrent removal already covered";
    group.check(context);
    group.assert_members(context, &["a", "b"]);
    group.assert_key_agreement(context);
}

// ---------------------------------------------------------------------------
// #220: a concurrent add must survive a concurrent trailing removal
// ---------------------------------------------------------------------------
//
// `b` adds `d` while `a` removes trailing member `c`, from the same state. When
// the digest order applied the removal first, `remove_id` freed the trailing
// slot, `push_leaf` gave it to `d`, and the merge rule then blanked the removed
// member's index, which `d` now held. `d` stayed in `id_to_leaf_idx` with a blank
// leaf, with no error and no divergence, since every replica reached the same
// corrupted state.

const TRAILING_SEED_BASE: u64 = 0x5107_0000;
const TRAILING_SEEDS: u64 = 64;

/// Returns the leaf `d` ends up at, which says which order the epoch took. The
/// removal ran first if `d` reused `c`'s freed slot 2, and the add ran first if
/// `d` was pushed past it to slot 3.
async fn trailing_remove_scenario(seed: u64) -> u32 {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut group = Group::found(3, &mut rng).await;
    let c = group.id(2);
    let d = member(&mut rng);
    group.names.insert(d.id, "d".to_string());

    let add_d = group.add(1, d.id, d.pk).await;
    let remove_c = group.remove(0, c).await;
    group.broadcast(&add_d);
    group.broadcast(&remove_c);

    let rotation = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");
    group.broadcast(&rotation);

    let context = format!("seed {seed:#x}");
    group.check(&context);
    group.assert_members(&context, &["a", "b", "d"]);
    group.assert_key_agreement(&context);

    group.replicas[0]
        .tree
        .leaf_index_for_id(d.id)
        .expect("d is a member")
        .u32()
}

#[tokio::test]
async fn trailing_remove_keeps_concurrent_add() {
    let mut seats_reached: BTreeSet<u32> = BTreeSet::new();
    for offset in 0..TRAILING_SEEDS {
        seats_reached.insert(trailing_remove_scenario(TRAILING_SEED_BASE + offset).await);
    }
    for (seat, order) in [(2, "the removal first"), (3, "the add first")] {
        assert!(
            seats_reached.contains(&seat),
            "no seed out of {TRAILING_SEEDS} applied {order}, so the sweep only \
             covered one order. Seeds seated d at leaves {seats_reached:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// #219: a removal's recorded leaf index must not be used against another tree
// ---------------------------------------------------------------------------
//
// `CgkaOperation::Remove` records the `leaf_idx` its author saw, and
// `apply_epochs` used to pass that straight to the merge rule, which re-blanks
// that index without checking it against the tree it is merging into.
//
// A recorded index only means something in the tree its author held. Two ordinary
// things move it. `remove_id` collects trailing tombstones and lowers
// `next_leaf_idx` so a later `push_leaf` reuses those slots, and the merge
// re-packs concurrently added leaves. A replica that has not seen a removal yet
// assigns a higher index than the merged history does, possibly past the end of
// the merged tree's `leaves`.

const STALE_SEED_BASE: u64 = 0x5ca1_e000;
const STALE_SEEDS: u64 = 64;

/// Four members at leaves 0 to 3.
///
///   1. `a` removes middle member `c`. Leaf 2 becomes a hole, and `d` still
///      holds trailing slot 3, so no tombstones are collected.
///   2. Concurrently `a` removes trailing member `d`, which does collect them,
///      while `b`, who has not seen that removal, adds `e` at the higher slot
///      its own tree still has free.
///   3. Still unaware, `b` removes `e` again, recording that higher index.
///   4. Concurrently `a` adds `f`, so `b`'s removal shares an epoch with a
///      membership change and the merge rule runs.
///   5. Everything reaches `a`, which replays.
///
/// Returns the index `b` recorded for `e` and how many leaf slots the merged
/// tree ended up with. Whether the merged tree has a slot at that index depends
/// on which order the earlier epoch took.
async fn stale_index_scenario(seed: u64) -> (u32, usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut group = Group::found(4, &mut rng).await;
    let (c, d) = (group.id(2), group.id(3));

    let remove_c = group.remove(0, c).await;
    group.broadcast(&remove_c);

    let remove_d = group.remove(0, d).await;
    let e = member(&mut rng);
    group.names.insert(e.id, "e".to_string());
    let add_e = group.add(1, e.id, e.pk).await;
    group.deliver(&remove_d, &[0]);
    group.deliver(&add_e, &[0, 1]);

    let remove_e = group.remove(1, e.id).await;
    let CgkaOperation::Remove { leaf_idx, .. } = remove_e.payload else {
        panic!("removing e should produce a Remove operation");
    };

    let f = member(&mut rng);
    group.names.insert(f.id, "f".to_string());
    let add_f = group.add(0, f.id, f.pk).await;

    group.deliver(&remove_e, &[0]);
    let rotation = group
        .rotate(0, &mut rng)
        .await
        .expect("the rotation succeeds");

    // Bring every replica up to the same history, in causal order.
    for op in [&remove_d, &add_e, &remove_e, &add_f, &rotation] {
        group.broadcast(op);
    }

    let context = format!("seed {seed:#x}");
    group.check(&context);
    group.assert_members(&context, &["a", "b", "f"]);
    group.assert_key_agreement(&context);

    (leaf_idx, group.replicas[0].tree.leaf_slot_count())
}

#[tokio::test]
async fn stale_recorded_leaf_index() {
    let mut reached_out_of_bounds = false;
    for offset in 0..STALE_SEEDS {
        let (recorded_idx, slots) = stale_index_scenario(STALE_SEED_BASE + offset).await;
        reached_out_of_bounds |= recorded_idx as usize >= slots;
    }
    assert!(
        reached_out_of_bounds,
        "the index b recorded for e was inside the merged tree on all \
         {STALE_SEEDS} seeds, so the sweep never used a stale index against a \
         shorter tree"
    );
}
