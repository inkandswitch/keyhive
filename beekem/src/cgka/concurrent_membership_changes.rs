use crate::{
    cgka::Cgka,
    id::{MemberId, TreeId},
    keys::{NodeKey, ShareKeyMap},
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
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{rngs::StdRng, SeedableRng};

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

struct Group {
    members: Vec<Member>,
    replicas: Vec<Cgka>,
    /// Short names for readable failures.
    names: BTreeMap<MemberId, String>,
    doc_id: TreeId,
    init_add_op: Signed<CgkaOperation>,
    /// Every operation delivered so far, in causal order, so a member who was
    /// added part way through can be given a replica of their own.
    log: Vec<Arc<Signed<CgkaOperation>>>,
    logged: BTreeSet<Digest<Signed<CgkaOperation>>>,
}

impl Group {
    async fn new(n: usize, rng: &mut StdRng) -> Group {
        let doc_signer = MemorySigner::generate(rng);
        let doc_id = TreeId(doc_signer.verifying_key());
        let members: Vec<Member> = (0..n).map(|_| member(rng)).collect();

        let mut creator =
            Cgka::new::<Local, _>(doc_id, members[0].id, members[0].pk, &members[0].signer)
                .await
                .expect("creating the tree succeeds");
        creator.owner_sks.insert(members[0].pk, members[0].sk);
        let init_add_op = creator.init_add_op();

        let mut replicas = vec![creator];
        for m in &members[1..] {
            let mut sks = ShareKeyMap::new();
            sks.insert(m.pk, m.sk);
            replicas.push(
                Cgka::new_from_init_add(doc_id, members[0].id, members[0].pk, init_add_op.clone())
                    .expect("creating a replica from the init add succeeds")
                    .with_new_owner(m.id, sks)
                    .expect("taking ownership of a replica succeeds"),
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
            doc_id,
            init_add_op,
            log: Vec::new(),
            logged: BTreeSet::new(),
        };
        for i in 1..n {
            let op = group.add(0, group.members[i].id, group.members[i].pk).await;
            group.broadcast(&op);
        }
        group
    }

    /// Create an add on `author`'s replica without delivering it.
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
            .expect("creating the add succeeds")
            .expect("the added member is new");
        Arc::new(op)
    }

    /// Create a removal on `author`'s replica without delivering it.
    async fn remove(&mut self, author: usize, target: MemberId) -> Arc<Signed<CgkaOperation>> {
        let signer = &self.members[author].signer;
        let op = self.replicas[author]
            .remove::<Local, _>(target, signer)
            .await
            .expect("creating the removal succeeds")
            .expect("the removed member is present");
        Arc::new(op)
    }

    /// Create a rotation on `author`'s replica without delivering it.
    async fn rotate(&mut self, author: usize, rng: &mut StdRng) -> Arc<Signed<CgkaOperation>> {
        let sk = ShareSecretKey::generate(rng);
        let pk = sk.share_key();
        let signer = &self.members[author].signer;
        let (_pcs_key, op) = self.replicas[author]
            .update::<Local, _, StdRng>(pk, sk, signer, rng)
            .await
            .expect("creating the rotation succeeds");
        Arc::new(op)
    }

    /// Rotate and deliver everywhere, causing every replica to play pending
    /// operations.
    async fn settle(&mut self, author: usize, rng: &mut StdRng) {
        let op = self.rotate(author, rng).await;
        self.broadcast(&op);
    }

    fn deliver(&mut self, op: &Arc<Signed<CgkaOperation>>, to: &[usize]) {
        if self.logged.insert(Digest::hash(op.as_ref())) {
            self.log.push(op.clone());
        }
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

    /// Every replica's tree satisfies its own invariants and they all agree.
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
            if self.replicas[i].tree != self.replicas[0].tree {
                let (theirs, ours) = (self.seating(i), self.seating(0));
                let detail = if theirs == ours {
                    format!(
                        "they seat everyone the same, at {ours}, so they differ \
                         somewhere other than the seating"
                    )
                } else {
                    format!("replica 0 seats {ours}, replica {i} seats {theirs}")
                };
                panic!("{context}: replicas diverged. {detail}");
            }
        }
    }

    fn assert_members(&self, context: &str, expected: &[&str]) {
        let mut want: Vec<&str> = expected.to_vec();
        want.sort();
        let mut got: Vec<String> = self.replicas[0]
            .tree
            .member_ids()
            .map(|id| self.label(&id))
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
    /// no replica whose owner was removed derives one.
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

    /// A replica owned by `id`, applying every operation delivered so far.
    fn replica_for(&self, id: MemberId, sks: ShareKeyMap) -> Cgka {
        let mut replica = Cgka::new_from_init_add(
            self.doc_id,
            self.members[0].id,
            self.members[0].pk,
            self.init_add_op.clone(),
        )
        .expect("creating a replica from the init add succeeds")
        .with_new_owner(id, sks)
        .expect("taking ownership of a replica succeeds");
        for op in &self.log {
            replica
                .merge_concurrent_operation(op.clone())
                .expect("the log is in causal order");
        }
        replica
    }

    /// `id`, using `sks`, derives the same root key as the rest of the group.
    fn assert_reads_group_key(
        &mut self,
        id: MemberId,
        sks: ShareKeyMap,
        context: &str,
        on_failure: &str,
    ) {
        let mut replica = self.replica_for(id, sks);
        let key = replica
            .pcs_key_from_tree_root()
            .unwrap_or_else(|e| panic!("{context}: {on_failure} {e:?}"));
        let group_key = self.replicas[0]
            .pcs_key_from_tree_root()
            .expect("replica 0's owner is a member");
        assert!(
            key == group_key,
            "{context}: {} derived a different root key from the rest of the group",
            self.label(&id)
        );
    }
}

/// A one-letter name for member `i`. Panics past `h`, which no scenario reaches.
fn name_for(i: usize) -> String {
    ["a", "b", "c", "d", "e", "f", "g", "h"][i].to_string()
}

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
        "`a` seated `d` again, though a concurrent add of `d` was already in its graph"
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

    // `a`'s tree does not seat `d` yet, but its graph holds the add that will.
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

    let context = "after removing a member whom a pending concurrent add was about to seat";
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
    // `rot_a` is authored against a tree that seats `d` at `a`'s prekey.
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

    let seated = group.replicas[0].tree.node_key_for_id(d.id);
    let (winning_pk, winning_sk) = match seated {
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
