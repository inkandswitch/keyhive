//! Tests concurrent updates.

use crate::{
    cgka::{Cgka, NoImplicitRemoves},
    encrypted::EncryptedSecret,
    id::MemberId,
    operation::{CgkaChange, CgkaOperation},
    test_utils::{assert_chain_bookkeeping, causal_past, for_each_seed, Group},
    treemath::{InnerNodeIndex, LeafNodeIndex, TreeNodeIndex},
};
use alloc::{format, sync::Arc, vec, vec::Vec};
use future_form::Local;
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{share_key::ShareSecretKey, signer::memory::MemorySigner, verified::Verified};
use rand::{rngs::StdRng, SeedableRng};

#[tokio::test]
async fn replicas_converge_over_concurrent_updates_in_either_order() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1234);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let by_a = group.rotate(0, &mut rng).await;
    let by_b = group.rotate(1, &mut rng).await;

    // `a` and `c` see `a`'s rotation first, `b` and `d` see `b`'s.
    group.try_deliver(&by_a, &[2]);
    group.try_deliver(&by_b, &[0, 2]);
    group.try_deliver(&by_b, &[3]);
    group.try_deliver(&by_a, &[1, 3]);

    group.check("after concurrent updates delivered in opposite orders");
}

#[tokio::test]
async fn a_concurrent_update_is_merged_on_arrival() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1235);
    let mut group = Group::new(2, &mut rng).await;
    group.settle(0, &mut rng).await;

    group.rotate(0, &mut rng).await;
    let by_b = group.rotate(1, &mut rng).await;
    group.deliver(&by_b, &[0]);

    group.assert_trees_match_replay("after a concurrent update arrived");
}

#[test]
fn a_concurrent_updates_secret_is_decrypted_from_its_own_path() {
    for_each_seed(|mut rng| async move {
        let mut group = Group::new(4, &mut rng).await;
        group.settle(0, &mut rng).await;

        let by_a = group.rotate(0, &mut rng).await;
        let by_b = group.rotate(1, &mut rng).await;
        group.broadcast(&by_a);
        group.broadcast(&by_b);

        // Each reader listed received that update while it had another head.
        for (author, op, readers) in [(0, &by_a, vec![1]), (1, &by_b, vec![0, 2, 3])] {
            let op_hash = op.digest();
            let secret = group.replicas[author]
                .root_secrets
                .get(&op_hash)
                .expect("the author records the secret its own update produced");
            for reader in readers {
                let cgka = &mut group.replicas[reader];
                assert_eq!(
                    cgka.root_secrets.get(&op_hash),
                    None,
                    "precondition: the conflicted root left the secret unrecorded"
                );
                assert_eq!(
                    cgka.root_secret_from_update_path(&op_hash),
                    Some(secret),
                    "replica {reader} should decrypt the secret from the update's own path"
                );
            }
        }
    });
}

#[test]
fn a_secret_neither_its_path_nor_the_chain_reaches_is_rebuilt() {
    for_each_seed(|mut rng| async move {
        let mut group = Group::new(4, &mut rng).await;
        group.settle(0, &mut rng).await;

        // `d` receives `c`'s update while it has its own, so it never decrypts the
        // node `c` set above them, and `a` encrypts its new root to that node.
        let by_c = group.rotate(2, &mut rng).await;
        group.rotate(3, &mut rng).await;
        group.deliver(&by_c, &[0, 3]);
        let by_a = group.rotate(0, &mut rng).await;
        group.deliver(&by_a, &[3]);
        let a_hash = by_a.digest();
        let secret = group.replicas[0]
            .root_secrets
            .get(&a_hash)
            .expect("the author records the secret its own update produced");

        let d = &mut group.replicas[3];
        assert!(
            d.root_secrets.get(&a_hash).is_none(),
            "precondition: d has not recorded the secret"
        );
        assert!(
            d.ops_graph
                .nearest_update_ancestors(&d.ops_graph.cgka_op_heads)
                .len()
                > 1,
            "precondition: d has more than one nearest update, so it cannot record the tree's secret"
        );
        assert!(
            d.clone().root_secret_from_update_path(&a_hash).is_none(),
            "precondition: d cannot decrypt the secret from the update's path"
        );
        assert!(
            !d.ops_graph.is_chainable(&a_hash),
            "precondition: no later update can wrap the secret in the chain"
        );
        assert_eq!(
            d.group_secret_from_hashes(&secret.digest(), &a_hash).ok(),
            Some(secret),
            "a rebuild from d's earlier leaf key should derive the secret"
        );
    });
}

/// Rotate `cgka`'s leaf to `sk`.
async fn rotate_to(
    cgka: &mut Cgka<NoImplicitRemoves>,
    signer: &MemorySigner,
    sk: ShareSecretKey,
    rng: &mut StdRng,
) -> Arc<Verified<CgkaOperation>> {
    let (_, op, _) = cgka
        .update::<Local, _, _>(sk.share_key(), sk, signer, rng)
        .await
        .expect("the owner can rotate");
    Arc::new(op)
}

#[tokio::test]
async fn one_identitys_concurrent_rotations_leave_every_replica_with_the_same_leaf_keys() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1236);
    let mut group = Group::new(3, &mut rng).await;
    group.settle(0, &mut rng).await;
    let mut sks: Vec<ShareSecretKey> = (0..3).map(|_| ShareSecretKey::generate(&mut rng)).collect();
    sks.sort_by_key(|sk| sk.share_key());
    let [lowest, middle, highest] = [sks[0], sks[1], sks[2]];

    // A second instance of `b` rotates to the middle key while the first
    // rotates to the lowest and then the highest. `c` receives the second
    // instance's rotation first, `a` and `b` last.
    let signer = group.members[1].signer.clone();
    let mut second_instance = group.replicas[1].clone();
    let by_second = rotate_to(&mut second_instance, &signer, middle, &mut rng).await;
    let first = rotate_to(&mut group.replicas[1], &signer, lowest, &mut rng).await;
    let then = rotate_to(&mut group.replicas[1], &signer, highest, &mut rng).await;
    group.deliver(&by_second, &[2]);
    for op in [&first, &then] {
        group.deliver(op, &[0, 2]);
    }
    group.deliver(&by_second, &[0, 1]);

    group.check("after one identity rotated its leaf from two instances");
    group.assert_trees_match_replay("after one identity rotated its leaf from two instances");
}

/// `op` with its change edited by `edit` and signed again by `signer`.
async fn resigned(
    op: &Verified<CgkaOperation>,
    signer: &MemorySigner,
    edit: impl FnOnce(&mut CgkaChange),
) -> Arc<Verified<CgkaOperation>> {
    let mut payload = op.payload().clone();
    edit(&mut payload.change);
    Arc::new(
        Verified::sign::<Local, _>(&payload, signer)
            .await
            .expect("signing succeeds"),
    )
}

#[tokio::test]
async fn replicas_converge_when_an_update_reuses_a_key_a_causally_unrelated_update_removes() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1239);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    // `b`'s update, concurrent with `a`'s, writes the key `a` wrote at the
    // node above them. `a`'s next update removes that key.
    let by_a = group.rotate(0, &mut rng).await;
    let CgkaChange::Update {
        new_path: a_path, ..
    } = &by_a.payload().change
    else {
        unreachable!("a rotation is an update")
    };
    let a_key = a_path.path[0].1.versions().head.pk;
    let signer = group.members[1].signer.clone();
    let by_b = rotate_to(
        &mut group.replicas[1].clone(),
        &signer,
        ShareSecretKey::generate(&mut rng),
        &mut rng,
    )
    .await;
    let by_b = resigned(&by_b, &signer, |change| {
        let CgkaChange::Update { new_path, .. } = change else {
            unreachable!("a rotation is an update")
        };
        new_path.path[0].1.head_mut().pk = a_key;
    })
    .await;
    group.deliver(&by_b, &[1]);
    group.deliver(&by_a, &[1, 2, 3]);
    let then_by_a = group.rotate(0, &mut rng).await;

    // `b` and `c` apply `b`'s update before `a`'s second, `a` and `d` after it.
    group.deliver(&by_b, &[2]);
    group.deliver(&then_by_a, &[1, 2, 3]);
    group.deliver(&by_b, &[0, 3]);

    group.check("after an update reused a key a causally unrelated update removes");
    group.assert_trees_match_replay(
        "after an update reused a key a causally unrelated update removes",
    );
}

/// An update and a copy of it, re-signed by its author, that differ only in the secret
/// sealed to `entry`. Both contain the same keys, and neither is causally after the other.
async fn an_update_and_its_resealed_twin(
    group: &mut Group<NoImplicitRemoves>,
    author: usize,
    entry: TreeNodeIndex,
    rng: &mut StdRng,
) -> (Arc<Verified<CgkaOperation>>, Arc<Verified<CgkaOperation>>) {
    let update = group.rotate(author, rng).await;
    let twin = resigned(&update, &group.members[author].signer, |change| {
        let CgkaChange::Update { new_path, .. } = change else {
            unreachable!("a rotation is an update")
        };
        let sealed = new_path.path[0]
            .1
            .head_mut()
            .sk
            .get_mut(&entry)
            .expect("the path's first node seals a secret to that child");
        let mut bytes = sealed.encode().as_bytes().to_vec();
        bytes[10] ^= 1;
        *sealed = EncryptedSecret::decode(&bytes).expect("a flipped ciphertext byte still decodes");
    })
    .await;
    (update, twin)
}

#[tokio::test]
async fn a_resealed_twin_arriving_after_a_covering_update_leaves_replicas_matching_a_replay() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1241);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let (update, twin) = an_update_and_its_resealed_twin(
        &mut group,
        1,
        TreeNodeIndex::Leaf(LeafNodeIndex::new(1)),
        &mut rng,
    )
    .await;
    group.broadcast(&update);
    // `a`'s update covers `b`'s, so it removes the keys the twin also contains.
    let by_a = group.rotate(0, &mut rng).await;
    group.broadcast(&by_a);
    group.broadcast(&twin);

    group.check("after the twin arrives behind a covering update");
    group.assert_trees_match_replay("after the twin arrives behind a covering update");
    group.settle(2, &mut rng).await;
    group.assert_key_agreement("after an update that has the twin in its past");
}

#[tokio::test]
async fn a_rotation_keeping_the_leaf_key_converges_with_a_concurrent_rotation_by_another_instance()
{
    let mut rng = StdRng::seed_from_u64(0x0cd0_1237);
    let mut group = Group::new(3, &mut rng).await;

    // As in a document's genesis, `a` rotates with the prekey its add
    // contained, while a second instance of `a` rotates to a fresh key. `b`
    // receives the genesis rotation first, `c` the other.
    let signer = group.members[0].signer.clone();
    let prekey = group.members[0].sk;
    let mut second_instance = group.replicas[0].clone();
    let fresh = ShareSecretKey::generate(&mut rng);
    let by_second = rotate_to(&mut second_instance, &signer, fresh, &mut rng).await;
    let genesis = rotate_to(&mut group.replicas[0], &signer, prekey, &mut rng).await;
    group.deliver(&genesis, &[1]);
    group.deliver(&by_second, &[0, 1, 2]);
    group.deliver(&genesis, &[2]);

    group.check("after a rotation keeping the leaf key and a concurrent one by another instance");
    group.assert_trees_match_replay(
        "after a rotation keeping the leaf key and a concurrent one by another instance",
    );
}

/// One author in [`replicas_converge_over_every_causal_delivery_order`]: a member's
/// signer and one replica of that member.
struct Author {
    signer: MemorySigner,
    replica: Cgka<NoImplicitRemoves>,
}

/// Merge `op` into `replica`, and assert that the versions it removed are
/// exactly those at the nodes it writes whose origins are in its causal past.
fn merge_removing_only_its_past(
    replica: &mut Cgka<NoImplicitRemoves>,
    op: &Arc<Verified<CgkaOperation>>,
) {
    let CgkaChange::Update { new_path, .. } = &op.payload().change else {
        unreachable!("these ops are rotations")
    };
    let issuer = MemberId::from(op.issuer());
    // Only updates are applied, so every path is valid.
    let written: vec::Vec<TreeNodeIndex> = [TreeNodeIndex::Leaf(
        *replica
            .tree
            .leaf_index_for_id(issuer)
            .expect("the issuer is in the tree"),
    )]
    .into_iter()
    .chain(
        new_path
            .path
            .iter()
            .map(|(idx, _)| TreeNodeIndex::Inner(InnerNodeIndex::new(*idx))),
    )
    .collect();
    let past = causal_past(&replica.ops_graph, &op.payload().predecessors);
    let before = replica.tree.origins_by_node();
    replica
        .merge_concurrent_operation(op.clone())
        .expect("the op's predecessors are applied");
    let after = replica.tree.origins_by_node();
    for (node, origin) in before.iter().filter(|version| !after.contains(version)) {
        assert!(
            past.contains(origin) && written.contains(node),
            "merging {} removed a version at {node:?} written by {origin}, which is not a node \
             it writes or not in its past",
            op.digest()
        );
    }
    let kept = replica.tree.origins_at(issuer, new_path);
    assert!(
        kept.is_disjoint(&past),
        "merging {} kept a version written in its past at a node it writes",
        op.digest()
    );
}

/// Apply to `replica` every op in `ops` it lacks, choosing at random among
/// those whose predecessors it has, until `limit` are applied or none is left.
fn deliver_in_random_causal_order(
    replica: &mut Cgka<NoImplicitRemoves>,
    ops: &[Arc<Verified<CgkaOperation>>],
    limit: usize,
    rng: &mut StdRng,
) {
    use rand::seq::IteratorRandom;
    for _ in 0..limit {
        let Some(op) = ops
            .iter()
            .filter(|op| {
                !replica.ops_graph.contains_op_hash(&op.digest())
                    && replica.contains_predecessors(&op.payload().predecessors())
            })
            .choose(rng)
        else {
            return;
        };
        merge_removing_only_its_past(replica, op);
    }
}

/// A rotation by `author`, edited at random so that it reuses another op's key
/// at a node they share, or is a resealed twin of one of `author`'s earlier
/// ops. The author's replica applies it.
async fn a_rotation_that_may_misbehave(
    author: &mut Author,
    published: &[Arc<Verified<CgkaOperation>>],
    rng: &mut StdRng,
) -> Arc<Verified<CgkaOperation>> {
    use rand::{seq::SliceRandom, Rng};
    let paths: vec::Vec<_> = published
        .iter()
        .filter_map(|op| match &op.payload().change {
            CgkaChange::Update { new_path, .. } => Some(new_path.as_ref()),
            _ => None,
        })
        .collect();
    let own: vec::Vec<_> = published
        .iter()
        .filter(|op| {
            MemberId::from(op.issuer()) == MemberId::from(&author.signer.0)
                && author.replica.ops_graph.contains_op_hash(&op.digest())
        })
        .collect();
    let choice = rng.gen_range(0..3);
    if choice == 2 {
        if let Some(original) = own.choose(rng) {
            let twin = resigned(original, &author.signer, |change| {
                let CgkaChange::Update { new_path, .. } = change else {
                    unreachable!("an author's ops are rotations")
                };
                if let Some(sealed) = new_path
                    .path
                    .first_mut()
                    .and_then(|(_, node)| node.head_mut().sk.values_mut().next())
                {
                    let mut bytes = sealed.encode().as_bytes().to_vec();
                    bytes[10] ^= 1;
                    *sealed = EncryptedSecret::decode(&bytes)
                        .expect("a flipped ciphertext byte still decodes");
                }
            })
            .await;
            author
                .replica
                .merge_concurrent_operation(twin.clone())
                .expect("the twin's predecessors are applied");
            return twin;
        }
    }
    let sk = ShareSecretKey::generate(rng);
    let op = rotate_to(&mut author.replica.clone(), &author.signer, sk, rng).await;
    let op = resigned(&op, &author.signer, |change| {
        let CgkaChange::Update { new_path, .. } = change else {
            unreachable!("a rotation is an update")
        };
        if choice == 1 {
            let shared: vec::Vec<_> = new_path
                .path
                .iter()
                .enumerate()
                .flat_map(|(i, (idx, _))| {
                    paths.iter().flat_map(move |path| {
                        path.path
                            .iter()
                            .filter(move |(other_idx, _)| other_idx == idx)
                            .map(move |(_, node)| (i, node.versions().head.pk))
                    })
                })
                .collect();
            if let Some((i, pk)) = shared.choose(rng) {
                new_path.path[*i].1.head_mut().pk = *pk;
            }
        }
    })
    .await;
    author
        .replica
        .merge_concurrent_operation(op.clone())
        .expect("the author has the rotation's predecessors");
    op
}

#[test]
fn replicas_converge_over_every_causal_delivery_order() {
    for_each_seed(|mut rng| async move {
        use rand::Rng;
        let mut group = Group::new(3, &mut rng).await;
        group.settle(0, &mut rng).await;
        let start = group.replicas.clone();

        // Each member, and a second instance of `a`, rotates after receiving
        // some of the ops published so far.
        let mut authors: vec::Vec<Author> = (0..3)
            .map(|i| Author {
                signer: group.members[i].signer.clone(),
                replica: start[i].clone(),
            })
            .chain([Author {
                signer: group.members[0].signer.clone(),
                replica: start[0].clone(),
            }])
            .collect();
        let mut published = vec::Vec::new();
        for _ in 0..10 {
            let author = &mut authors[rng.gen_range(0..4)];
            let limit = rng.gen_range(0..=published.len());
            deliver_in_random_causal_order(&mut author.replica, &published, limit, &mut rng);
            let op = a_rotation_that_may_misbehave(author, &published, &mut rng).await;
            published.push(op);
        }

        let mut replicas: vec::Vec<_> = authors.into_iter().map(|a| a.replica).collect();
        replicas.extend(start.iter().cloned());
        for replica in &mut replicas {
            deliver_in_random_causal_order(replica, &published, usize::MAX, &mut rng);
        }
        // A rotation that reuses another op's key at a shared node leaves that
        // node's parent encrypted to a key the node no longer contains.
        // `Group::check` reports that as a corrupt tree whatever the merge
        // rule, so this test compares the trees and checks chain bookkeeping
        // instead.
        for (i, replica) in replicas.iter().enumerate() {
            assert_chain_bookkeeping(replica, &format!("replica {i}"));
            assert!(
                replica.tree == replicas[0].tree,
                "replica {i} applied the same ops as replica 0 and has a different tree"
            );
        }
        group.replicas = replicas;
        group.assert_trees_match_replay("after every replica applied every op");
    });
}
