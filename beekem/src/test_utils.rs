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
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::rngs::StdRng;

/// A member of a test group, holding everything needed to act as one.
pub struct Member {
    pub id: MemberId,
    pub signer: MemorySigner,
    pub pk: ShareKey,
    pub sk: ShareSecretKey,
}

/// A new member, with a fresh signer and a fresh prekey.
pub fn member(rng: &mut StdRng) -> Member {
    let signer = MemorySigner::generate(rng);
    let id = MemberId(signer.verifying_key());
    let sk = ShareSecretKey::generate(rng);
    let pk = sk.share_key();
    Member { id, signer, pk, sk }
}

/// One replica of a tree per member, with delivery between them under the
/// test's control.
pub struct Group {
    pub members: Vec<Member>,
    pub replicas: Vec<Cgka>,
    /// Short names for readable failures.
    pub names: BTreeMap<MemberId, String>,
    doc_id: TreeId,
    init_add_op: Signed<CgkaOperation>,
    /// Every operation delivered so far, in causal order, so a member who was
    /// added part way through can be given a replica of their own.
    log: Vec<Arc<Signed<CgkaOperation>>>,
    logged: BTreeSet<Digest<Signed<CgkaOperation>>>,
}

impl Group {
    /// `n` members, each with a replica that has every add applied.
    pub async fn new(n: usize, rng: &mut StdRng) -> Group {
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
    pub async fn add(
        &mut self,
        author: usize,
        id: MemberId,
        pk: ShareKey,
    ) -> Arc<Signed<CgkaOperation>> {
        self.try_add(author, id, pk)
            .await
            .expect("the added member is new")
    }

    /// Create an add on `author`'s replica without delivering it, or `None` if
    /// `author`'s history already covers seating `id`.
    pub async fn try_add(
        &mut self,
        author: usize,
        id: MemberId,
        pk: ShareKey,
    ) -> Option<Arc<Signed<CgkaOperation>>> {
        let signer = &self.members[author].signer;
        self.replicas[author]
            .add::<Local, _>(id, pk, signer)
            .await
            .expect("creating the add succeeds")
            .map(Arc::new)
    }

    /// Create a removal on `author`'s replica without delivering it.
    pub async fn remove(&mut self, author: usize, target: MemberId) -> Arc<Signed<CgkaOperation>> {
        self.try_remove(author, target)
            .await
            .expect("the removed member is present")
    }

    /// Create a removal on `author`'s replica without delivering it, or `None`
    /// if `author`'s history already removes `target`.
    pub async fn try_remove(
        &mut self,
        author: usize,
        target: MemberId,
    ) -> Option<Arc<Signed<CgkaOperation>>> {
        let signer = &self.members[author].signer;
        self.replicas[author]
            .remove::<Local, _>(target, signer)
            .await
            .expect("creating the removal succeeds")
            .map(Arc::new)
    }

    /// Create a rotation on `author`'s replica without delivering it.
    pub async fn rotate(&mut self, author: usize, rng: &mut StdRng) -> Arc<Signed<CgkaOperation>> {
        self.try_rotate(author, rng)
            .await
            .expect("the rotating member is present")
    }

    /// Create a rotation on `author`'s replica without delivering it or `None`
    /// if `author` is no longer in the tree.
    pub async fn try_rotate(
        &mut self,
        author: usize,
        rng: &mut StdRng,
    ) -> Option<Arc<Signed<CgkaOperation>>> {
        let sk = ShareSecretKey::generate(rng);
        let pk = sk.share_key();
        let signer = &self.members[author].signer;
        match self.replicas[author]
            .update::<Local, _, StdRng>(pk, sk, signer, rng)
            .await
        {
            Ok((_pcs_key, op, _)) => Some(Arc::new(op)),
            Err(CgkaError::IdentifierNotFound) => None,
            Err(e) => panic!("creating the rotation succeeds: {e:?}"),
        }
    }

    /// Rotate and deliver everywhere, causing every replica to play pending
    /// operations.
    pub async fn settle(&mut self, author: usize, rng: &mut StdRng) {
        let op = self.rotate(author, rng).await;
        self.broadcast(&op);
    }

    /// Deliver `op` to the replicas named by `to`, recording it in the log.
    pub fn deliver(&mut self, op: &Arc<Signed<CgkaOperation>>, to: &[usize]) {
        let held = self.try_deliver(op, to);
        assert!(
            held.is_empty(),
            "operations are delivered in causal order, but replicas {held:?} could not apply one"
        );
    }

    /// Deliver `op` to the replicas named by `to`, recording it in the log, and
    /// report which of them could not apply it.
    ///
    /// A replica refuses an operation whose predecessors it has not seen, so a
    /// caller delivering in an arbitrary order should expect to retry.
    pub fn try_deliver(&mut self, op: &Arc<Signed<CgkaOperation>>, to: &[usize]) -> Vec<usize> {
        if self.logged.insert(Digest::hash(op.as_ref())) {
            self.log.push(op.clone());
        }
        to.iter()
            .copied()
            .filter(|&i| {
                self.replicas[i]
                    .merge_concurrent_operation(op.clone())
                    .is_err()
            })
            .collect()
    }

    /// Deliver `op` to every replica.
    pub fn broadcast(&mut self, op: &Arc<Signed<CgkaOperation>>) {
        self.deliver(op, &Vec::from_iter(0..self.replicas.len()));
    }

    /// Member `i`'s id.
    pub fn id(&self, i: usize) -> MemberId {
        self.members[i].id
    }

    fn label(&self, id: &MemberId) -> String {
        self.names
            .get(id)
            .cloned()
            .unwrap_or_else(|| format!("{id:?}"))
    }

    /// The tree members on `replica`, by ascending leaf index.
    fn tree_members(&self, replica: usize) -> Vec<(u32, MemberId)> {
        let mut tree_members: Vec<(u32, MemberId)> = self.replicas[replica]
            .tree
            .tree_members()
            .into_iter()
            .map(|(id, idx)| (idx, id))
            .collect();
        tree_members.sort();
        tree_members
    }

    /// A string for a failure message, like `"a@0 b@1 d@2"`.
    fn tree_members_string(&self, tree_members: &[(u32, MemberId)]) -> String {
        tree_members
            .iter()
            .map(|(idx, id)| format!("{}@{idx}", self.label(id)))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every replica's tree satisfies its own invariants and they all agree.
    pub fn check(&self, context: &str) {
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
                let (theirs, ours) = (self.tree_members(i), self.tree_members(0));
                let detail = if theirs == ours {
                    format!(
                        "they place everyone the same in the tree, at {}, so they differ \
                         somewhere other than the placements",
                        self.tree_members_string(&ours)
                    )
                } else {
                    format!(
                        "replica 0 places {}, replica {i} places {}",
                        self.tree_members_string(&ours),
                        self.tree_members_string(&theirs)
                    )
                };
                panic!("{context}: replicas diverged. {detail}");
            }
        }
    }

    /// Replica 0 places exactly `expected`.
    pub fn assert_members(&self, context: &str, expected: &[&str]) {
        let mut want: Vec<String> = expected.iter().map(|name| name.to_string()).collect();
        want.sort();
        let mut got: Vec<String> = self.replicas[0]
            .tree
            .member_ids()
            .map(|id| self.label(&id))
            .collect();
        got.sort();
        assert_eq!(
            got,
            want,
            "{context}: wrong membership, placed as {}",
            self.tree_members_string(&self.tree_members(0))
        );
    }

    /// Every replica whose owner is still a member derives the same root key, and
    /// no replica whose owner was removed derives one.
    pub fn assert_key_agreement(&mut self, context: &str) {
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
    pub fn assert_reads_group_key(
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
