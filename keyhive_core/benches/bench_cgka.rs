//! BeeKEM costs: key generation, and a member following 100 updates from
//! another member and decrypting the root after each, across tree shapes
//! that make decryption cheap (a synced tree) or costly (conflict keys,
//! blank nodes, concurrent adds).

use beekem::{
    cgka::Cgka,
    id::TreeId,
    keys::ShareKeyMap,
    operation::CgkaOperation,
    test_utils::{member, Member, NO_CITATIONS},
};
use divan::Bencher;
use future_form::Local;
use futures::executor::block_on;
use keyhive_crypto::{share_key::ShareSecretKey, signer::memory::MemorySigner, verified::Verified};
use nonempty::NonEmpty;
use rand::{rngs::StdRng, SeedableRng};
use std::{sync::Arc, time::Duration};

fn main() {
    divan::main();
}

#[divan::bench(args = [100, 1000])]
fn create_key_pairs(n: u32) {
    let mut csprng = rand::rngs::OsRng;
    for _ in 0..n {
        let s = ShareSecretKey::generate(&mut csprng);
        s.share_key();
    }
}

/// One tree that every operation is merged into, and each member's secrets
/// for its leaf, from which any member's replica can be cloned.
struct Fixture {
    tree: Cgka,
    members: Vec<Member>,
    secrets: Vec<ShareKeyMap>,
    rng: StdRng,
}

impl Fixture {
    /// `count` members, all added by the first. Only the first has updated
    /// its path, so every other leaf's path is blank.
    fn with_blank_nodes(count: usize) -> Self {
        let mut rng = StdRng::from_entropy();
        let doc_id = TreeId::from(&MemorySigner::generate(&mut rng).0);
        let members: Vec<Member> = (0..count).map(|_| member(&mut rng)).collect();
        let secrets: Vec<ShareKeyMap> = members.iter().map(leaf_secret).collect();
        let mut tree = Cgka::new(doc_id, members[0].id, secrets[0].clone());
        let adds = NonEmpty::from_vec(
            members
                .iter()
                .map(|m| (m.id, m.pk, None, NO_CITATIONS))
                .collect::<Vec<_>>(),
        )
        .expect("at least one member");
        block_on(tree.add_multiple::<Local, _>(adds, &members[0].signer))
            .expect("adding new members succeeds");
        let mut fixture = Fixture {
            tree,
            members,
            secrets,
            rng,
        };
        fixture.update_in_turn(&[0]);
        fixture
    }

    /// Every member has updated its path in turn, so no inner node holds
    /// conflict keys.
    fn synced(count: usize) -> Self {
        let mut fixture = Self::with_blank_nodes(count);
        fixture.update_in_turn(&Vec::from_iter(1..count));
        fixture
    }

    /// Every member updated concurrently, leaving the most conflict keys an
    /// inner node can hold, then the first updated once: the root is shared,
    /// but nodes off its path still hold every conflict key.
    fn with_maximum_conflict_keys(count: usize) -> Self {
        let mut fixture = Self::with_blank_nodes(count);
        let ops: Vec<_> = (0..count).map(|i| fixture.update_from(i).0).collect();
        fixture.merge_all(ops);
        fixture.update_in_turn(&[0]);
        fixture
    }

    /// `count - adds` synced members, then `adds` of them each add a new
    /// member concurrently, then the first updates.
    fn synced_then_concurrent_adds(count: usize, adds: usize) -> Self {
        let existing = count - adds;
        let mut fixture = Self::synced(existing);
        let ops: Vec<_> = (existing - adds..existing)
            .map(|author| {
                let added = member(&mut fixture.rng);
                let mut replica = fixture.replica(author);
                let op = block_on(replica.add::<Local, _>(
                    added.id,
                    added.pk,
                    None,
                    NO_CITATIONS,
                    &fixture.members[author].signer,
                ))
                .expect("adding succeeds")
                .expect("the member is new");
                fixture.secrets.push(leaf_secret(&added));
                fixture.members.push(added);
                Arc::new(op)
            })
            .collect();
        fixture.merge_all(ops);
        fixture.update_in_turn(&[0]);
        fixture
    }

    /// Member `i`'s replica of the tree as it stands.
    fn replica(&self, i: usize) -> Cgka {
        self.tree
            .with_new_owner(self.members[i].id, self.secrets[i].clone())
            .expect("the member is in the tree")
    }

    /// An update by member `i` from the tree as it stands, without merging
    /// it, and the replica that made it. Member `i` keeps its new secret.
    fn update_from(&mut self, i: usize) -> (Arc<Verified<CgkaOperation>>, Cgka) {
        let mut replica = self.replica(i);
        let sk = ShareSecretKey::generate(&mut self.rng);
        let (_pcs_key, op, _key_pair) = block_on(replica.update::<Local, _, _>(
            sk.share_key(),
            sk,
            &self.members[i].signer,
            &mut self.rng,
        ))
        .expect("a member can update");
        self.secrets[i].insert(sk.share_key(), sk);
        (Arc::new(op), replica)
    }

    /// Each of `who` updates in turn, each from the tree with the last
    /// update merged.
    fn update_in_turn(&mut self, who: &[usize]) {
        for &i in who {
            let (op, _) = self.update_from(i);
            self.merge_all([op]);
        }
    }

    fn merge_all<I: IntoIterator<Item = Arc<Verified<CgkaOperation>>>>(&mut self, ops: I) {
        for op in ops {
            self.tree
                .merge_concurrent_operation(op)
                .expect("operations arrive in causal order");
        }
    }

    /// The first member and member `paired`, after `paired` updates and the
    /// first merges it: the writer and the reader of the benchmarks.
    fn writer_and_reader(mut self, paired: usize) -> (Writer, Cgka) {
        let (op, reader) = self.update_from(paired);
        let mut tree = self.replica(0);
        tree.merge_concurrent_operation(op)
            .expect("the update follows the tree");
        let writer = Writer {
            tree,
            signer: self.members[0].signer.clone(),
            rng: self.rng,
        };
        (writer, reader)
    }
}

/// `m`'s secret for the key it joins with.
fn leaf_secret(m: &Member) -> ShareKeyMap {
    let mut secrets = ShareKeyMap::new();
    secrets.insert(m.pk, m.sk);
    secrets
}

/// The member whose updates the reader follows.
struct Writer {
    tree: Cgka,
    signer: MemorySigner,
    rng: StdRng,
}

/// The writer updates 100 times; after each, the reader merges the update
/// and decrypts the root.
fn follow_100_updates(writer: &mut Writer, reader: &mut Cgka) {
    for _ in 0..100 {
        let sk = ShareSecretKey::generate(&mut writer.rng);
        let (_pcs_key, op, _key_pair) = block_on(writer.tree.update::<Local, _, _>(
            sk.share_key(),
            sk,
            &writer.signer,
            &mut writer.rng,
        ))
        .expect("the writer can update");
        reader
            .merge_concurrent_operation(Arc::new(op))
            .expect("the update follows the reader's tree");
        reader
            .decrypt_tree_root_secret()
            .expect("the reader can decrypt the root");
    }
}

#[divan::bench(args = [31, 255, 511], sample_count = 10, max_time = Duration::from_secs(120))]
fn apply_100_updates_and_sibling_decrypt(bencher: Bencher, member_count: usize) {
    bencher
        .with_inputs(|| Fixture::synced(member_count).writer_and_reader(1))
        .bench_local_refs(|(writer, reader)| follow_100_updates(writer, reader));
}

#[divan::bench(args = [31, 255, 511], sample_count = 10, max_time = Duration::from_secs(120))]
fn apply_100_updates_and_distant_member_decrypt(bencher: Bencher, member_count: usize) {
    bencher
        .with_inputs(|| Fixture::synced(member_count).writer_and_reader(member_count - 1))
        .bench_local_refs(|(writer, reader)| follow_100_updates(writer, reader));
}

#[divan::bench(args = [31, 255, 511], sample_count = 10, max_time = Duration::from_secs(120))]
fn apply_100_updates_and_distant_member_decrypt_with_maximum_conflict_keys(
    bencher: Bencher,
    member_count: usize,
) {
    bencher
        .with_inputs(|| {
            Fixture::with_maximum_conflict_keys(member_count).writer_and_reader(member_count - 1)
        })
        .bench_local_refs(|(writer, reader)| follow_100_updates(writer, reader));
}

#[divan::bench(args = [31, 255, 511], sample_count = 10, max_time = Duration::from_secs(120))]
fn apply_100_updates_and_distant_member_decrypt_after_adds(bencher: Bencher, member_count: usize) {
    bencher
        .with_inputs(|| {
            Fixture::synced_then_concurrent_adds(member_count, 10)
                .writer_and_reader(member_count - 1)
        })
        .bench_local_refs(|(writer, reader)| follow_100_updates(writer, reader));
}

#[divan::bench(args = [31, 255, 511], sample_count = 10, max_time = Duration::from_secs(120))]
fn apply_100_updates_and_distant_member_decrypt_with_blank_nodes(
    bencher: Bencher,
    member_count: usize,
) {
    bencher
        .with_inputs(|| Fixture::with_blank_nodes(member_count).writer_and_reader(member_count - 1))
        .bench_local_refs(|(writer, reader)| follow_100_updates(writer, reader));
}
