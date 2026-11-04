//! Path secrets contained in an update operation.

use crate::{
    cgka::NoImplicitRemoves,
    collections::Set,
    encrypted::encrypt_secret,
    error::CgkaError,
    keys::ShareKeyMap,
    operation::{CgkaChange, CgkaOperation},
    secret_store::SecretStore,
    test_utils::Group,
    tree::PathChange,
    treemath::{InnerNodeIndex, LeafNodeIndex, TreeNodeIndex},
};
use alloc::{collections::BTreeMap, sync::Arc};
use future_form::Local;
use keyhive_crypto::{share_key::ShareSecretKey, verified::Verified};
use rand::{rngs::StdRng, SeedableRng};

/// An update by `author` whose every path node is encrypted to its
/// recipients as a random secret that is not that node's correct
/// secret for this rotation, signed by `author`.
async fn forged_update(
    group: &mut Group<NoImplicitRemoves>,
    author: usize,
    rng: &mut StdRng,
) -> Arc<Verified<CgkaOperation>> {
    let doc_id = group.replicas[author].doc_id;
    tampered_update(group, author, rng, |new_path, sks, rng| {
        for (_, node) in new_path.path.iter_mut() {
            let version = node.head_mut();
            let encrypter_sk = sks
                .get(&version.encrypter_pk)
                .expect("the author has its path secrets");
            let incorrect_secret = ShareSecretKey::generate(rng);
            for encrypted in version.sk.values_mut() {
                *encrypted = encrypt_secret(
                    doc_id,
                    &incorrect_secret,
                    encrypter_sk,
                    &encrypted.paired_pk,
                )
                .expect("encryption succeeds");
            }
        }
    })
    .await
}

/// An honest rotation by `author`, changed by `tamper` and then signed by
/// `author`. `tamper` is given the author's secrets.
async fn tampered_update(
    group: &mut Group<NoImplicitRemoves>,
    author: usize,
    rng: &mut StdRng,
    tamper: impl FnOnce(&mut PathChange, &ShareKeyMap, &mut StdRng),
) -> Arc<Verified<CgkaOperation>> {
    // Made on a copy, so the author's own replica receives it like everyone
    // else's.
    let mut copy = group.replicas[author].clone();
    let sk = ShareSecretKey::generate(rng);
    let signer = &group.members[author].signer;
    let (_, op, _) = copy
        .update::<Local, _, _>(sk.share_key(), sk, signer, rng)
        .await
        .expect("the author can update");
    group.replicas[author].owner_sks.extend(&copy.owner_sks);
    let mut payload = op.payload().clone();
    let CgkaChange::Update { new_path, .. } = &mut payload.change else {
        unreachable!("an update")
    };
    tamper(new_path, &copy.owner_sks, rng);
    Arc::new(
        Verified::sign::<Local, _>(&payload, signer)
            .await
            .expect("signing succeeds"),
    )
}

/// Removes the entry for `node` from the version at position `at` in `path`.
fn drop_entry(path: &mut PathChange, at: usize, node: TreeNodeIndex) {
    path.path[at]
        .1
        .head_mut()
        .sk
        .remove(&node)
        .expect("the path node has an entry for that node");
}

#[tokio::test]
async fn a_member_who_receives_forged_path_secrets_still_agrees_on_later_keys() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0001);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let forged = forged_update(&mut group, 0, &mut rng).await;
    group.broadcast(&forged);
    // Each other member finds that the forged update's path does not match
    // its keys, rather than keeping what it decrypted.
    for replica in &mut group.replicas[1..] {
        let root = replica.decrypt_current_group_secret();
        assert!(
            matches!(root, Err(CgkaError::PathSecretMismatch)),
            "{root:?}"
        );
    }
    // An honest update from the other half of the tree is encrypted to the
    // node the forgery wrote on its author's side, which it does not replace.
    group.settle(2, &mut rng).await;

    // The member on the forged node's side can still write by rotating.
    let signer = group.members[1].signer.clone();
    let (_, _, rotation) = group.replicas[1]
        .group_secret_for_write::<Local, _, _>(&signer, &mut rng)
        .await
        .expect("a member who cannot derive the root secret still writes");
    let (op, _) = rotation.expect("writing rotated");
    group.broadcast(&Arc::new(op));

    group.assert_key_agreement("after a forged update, an honest update and write");
}

#[tokio::test]
async fn a_member_an_update_leaves_out_reads_the_next_update_by_another_member() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0002);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let b_leaf = TreeNodeIndex::from(LeafNodeIndex::new(1));
    let leaves_out_b = tampered_update(&mut group, 0, &mut rng, |path, _, _| {
        drop_entry(path, 0, b_leaf)
    })
    .await;
    group.broadcast(&leaves_out_b);
    let by_c = group.rotate(2, &mut rng).await;
    group.broadcast(&by_c);
    group.assert_trees_match_replay("after an update leaving b out");

    let root = group.replicas[2]
        .root_secrets
        .get(&by_c.digest())
        .expect("an updater records the root secret of its own update");
    assert_eq!(
        group.replicas[1]
            .group_secret_from_hashes(&root.digest(), &by_c.digest())
            .ok(),
        Some(root),
        "b cannot derive the root secret of c's update"
    );
}

#[tokio::test]
async fn an_update_leaving_a_member_out_converges_with_a_concurrent_one_in_either_order() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0005);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let d_leaf = TreeNodeIndex::from(LeafNodeIndex::new(3));
    let leaves_out_d = tampered_update(&mut group, 0, &mut rng, |path, _, _| {
        drop_entry(path, 1, d_leaf)
    })
    .await;
    let by_c = group.rotate(2, &mut rng).await;
    group.deliver(&leaves_out_d, &[0, 1]);
    group.deliver(&by_c, &[0, 1, 3]);
    group.deliver(&leaves_out_d, &[2, 3]);
    for replica in &mut group.replicas {
        replica
            .replay_if_pending()
            .expect("no membership is unknown");
    }

    group.check("after an update leaving d out and a concurrent one");
    group.assert_trees_match_replay("after an update leaving d out and a concurrent one");
}

#[tokio::test]
async fn an_update_whose_path_is_cut_short_converges_with_concurrent_and_later_updates() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0008);
    let mut group = Group::new(3, &mut rng).await;
    group.settle(0, &mut rng).await;

    let cut_short = tampered_update(&mut group, 0, &mut rng, |path, _, _| {
        path.path.pop();
    })
    .await;
    let by_c = group.rotate(2, &mut rng).await;
    group.deliver(&cut_short, &[1]);
    let by_b = group.rotate(1, &mut rng).await;
    for op in [&cut_short, &by_c, &by_b] {
        group.broadcast(op);
    }
    for replica in &mut group.replicas {
        replica
            .replay_if_pending()
            .expect("no membership is unknown");
    }

    group.check("after an update cut short, a concurrent update and a later one");
    group.assert_trees_match_replay(
        "after an update cut short, a concurrent update and a later one",
    );
}

#[tokio::test]
async fn an_update_cut_short_keeping_its_leaf_key_converges_with_a_concurrent_one() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_000d);
    let mut group = Group::new(2, &mut rng).await;
    group.settle(0, &mut rng).await;
    let leaf_pk = group.replicas[0].owner_leaf_key().expect("a member");

    let cut_short = tampered_update(&mut group, 0, &mut rng, |path, _, _| {
        path.path.pop();
        path.leaf_pk = leaf_pk;
        path.removed_keys.clear();
    })
    .await;
    let by_b = group.rotate(1, &mut rng).await;
    // A replay applies a batch in digest order, so this order is the
    // reverse of the one `b`'s replica applies them in.
    assert!(
        cut_short.digest() < by_b.digest(),
        "the seed no longer makes a replay apply the update cut short first"
    );
    group.deliver(&cut_short, &[0]);
    group.broadcast(&by_b);
    group.broadcast(&cut_short);
    for replica in &mut group.replicas {
        replica
            .replay_if_pending()
            .expect("no membership is unknown");
    }

    group.check("after an update cut short and a concurrent one");
    group.assert_trees_match_replay("after an update cut short and a concurrent one");
}

/// The path of an honest rotation in a group of four, which has two nodes.
async fn honest_path(rng: &mut StdRng) -> PathChange {
    honest_path_of(0, rng).await
}

/// The path of `author`'s honest rotation in a group of four.
async fn honest_path_of(author: usize, rng: &mut StdRng) -> PathChange {
    let mut group = Group::<NoImplicitRemoves>::new(4, rng).await;
    group.settle(0, rng).await;
    let op = group.rotate(author, rng).await;
    let CgkaChange::Update { new_path, .. } = &op.payload().change else {
        unreachable!("a rotation is an update")
    };
    (**new_path).clone()
}

#[tokio::test]
async fn a_path_node_without_an_entry_for_its_encrypting_child_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0003);
    let mut path = honest_path(&mut rng).await;
    let first = TreeNodeIndex::from(InnerNodeIndex::new(path.path[0].0));
    path.path[1]
        .1
        .head_mut()
        .sk
        .remove(&first)
        .expect("a node has an entry for the child that encrypted it");

    assert!(!path.is_well_formed());
}

#[tokio::test]
async fn a_path_node_with_two_versions_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0004);
    let mut path = honest_path(&mut rng).await;
    let stranger = ShareSecretKey::generate(&mut rng).share_key();
    path.path[0].1.merge(
        &SecretStore::new(stranger, stranger, BTreeMap::new()),
        &Set::new(),
    );

    assert!(!path.is_well_formed());
}

#[tokio::test]
async fn a_path_node_whose_encrypter_is_not_the_child_below_it_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0006);
    let honest = honest_path(&mut rng).await;
    let sibling = TreeNodeIndex::from(LeafNodeIndex::new(1));
    let mut at_first = honest.clone();
    let version = at_first.path[0].1.head_mut();
    version.encrypter_pk = version.sk[&sibling].paired_pk;
    let mut at_second = honest.clone();
    at_second.path[1].1.head_mut().encrypter_pk = honest.leaf_pk;

    assert!(!at_first.is_well_formed());
    assert!(!at_second.is_well_formed());
}

#[tokio::test]
async fn a_path_node_whose_key_the_update_removes_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0007);
    let mut path = honest_path(&mut rng).await;
    let root = path.path[1].1.versions().head.pk;
    path.removed_keys.insert(root);

    assert!(!path.is_well_formed());
}

#[tokio::test]
async fn a_path_node_whose_key_repeats_another_new_key_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0008);
    let mut path = honest_path(&mut rng).await;
    let mut repeats_leaf = path.clone();
    repeats_leaf.path[1].1.head_mut().pk = path.leaf_pk;
    path.path[1].1.head_mut().pk = path.path[0].1.versions().head.pk;

    assert!(!repeats_leaf.is_well_formed());
    assert!(!path.is_well_formed());
}

#[tokio::test]
async fn a_path_with_an_index_of_2_pow_31_or_more_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0005);
    let honest = honest_path(&mut rng).await;
    let mut leaf_beyond = honest.clone();
    leaf_beyond.leaf_idx += 1 << 31;
    let mut node_beyond = honest.clone();
    node_beyond.path[0].0 += 1 << 31;
    let mut root_beyond = honest.clone();
    root_beyond.path[1].0 += 1 << 31;
    let mut leaf_beyond_without_nodes = leaf_beyond.clone();
    leaf_beyond_without_nodes.path.clear();

    assert!(!leaf_beyond.is_well_formed());
    assert!(!node_beyond.is_well_formed());
    assert!(!root_beyond.is_well_formed());
    assert!(!leaf_beyond_without_nodes.is_well_formed());
}

#[tokio::test]
async fn a_path_that_is_not_a_chain_from_the_leaf_to_a_root_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0009);
    let honest = honest_path(&mut rng).await;
    let mut empty = honest.clone();
    empty.path.clear();
    let mut skips_a_node = honest.clone();
    skips_a_node.path.truncate(1);
    skips_a_node.path[0].0 = honest.path[1].0;
    // Leaf 2's parent is not a root at any tree size, unlike leaf 0's.
    let mut stops_below_a_root = honest_path_of(2, &mut rng).await;
    stops_below_a_root.path.truncate(1);

    assert!(!empty.is_well_formed());
    assert!(!skips_a_node.is_well_formed());
    assert!(!stops_below_a_root.is_well_formed());
}

/// A chain of `len` nodes up from leaf 0, well-formed apart from its length:
/// the inner indices 2^j - 1, each the root of a tree of some size.
async fn chain_from_leaf_zero(len: u32, rng: &mut StdRng) -> PathChange {
    let mut path = honest_path(rng).await;
    let leaf = TreeNodeIndex::from(LeafNodeIndex::new(path.leaf_idx));
    let entry = path.path[0].1.versions().head.sk[&leaf].clone();
    let mut child = leaf;
    let mut encrypter = path.leaf_pk;
    path.path = (0..len)
        .map(|j| {
            let idx = (1u32 << j) - 1;
            let pk = ShareSecretKey::generate(rng).share_key();
            let node = SecretStore::new(pk, encrypter, BTreeMap::from([(child, entry.clone())]));
            child = TreeNodeIndex::from(InnerNodeIndex::new(idx));
            encrypter = pk;
            (idx, node)
        })
        .collect();
    path
}

/// The tallest tree, of 2^31 leaves, has 31 inner levels.
#[tokio::test]
async fn a_path_may_be_as_long_as_the_tallest_tree_and_no_longer() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_000a);
    assert!(chain_from_leaf_zero(31, &mut rng).await.is_well_formed());
    assert!(!chain_from_leaf_zero(32, &mut rng).await.is_well_formed());
}
