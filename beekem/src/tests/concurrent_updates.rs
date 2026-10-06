//! Tests concurrent updates.

use crate::test_utils::Group;
use alloc::vec;
use keyhive_crypto::digest::Digest;
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

#[tokio::test]
async fn a_concurrent_updates_secret_is_decrypted_from_its_own_path() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1236);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let by_a = group.rotate(0, &mut rng).await;
    let by_b = group.rotate(1, &mut rng).await;
    group.broadcast(&by_a);
    group.broadcast(&by_b);

    // Each reader listed received that update while it had another head.
    for (author, op, readers) in [(0, &by_a, vec![1]), (1, &by_b, vec![0, 2, 3])] {
        let op_hash = Digest::hash(op.as_ref());
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
}

#[tokio::test]
async fn a_secret_neither_its_path_nor_the_chain_reaches_is_rebuilt() {
    let mut rng = StdRng::seed_from_u64(0x0cd0_1237);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    // `d` receives `c`'s update while it has its own, so it never decrypts the
    // node `c` set above them, and `a` encrypts its new root to that node.
    let by_c = group.rotate(2, &mut rng).await;
    group.rotate(3, &mut rng).await;
    group.deliver(&by_c, &[0, 3]);
    let by_a = group.rotate(0, &mut rng).await;
    group.deliver(&by_a, &[3]);
    let a_hash = Digest::hash(by_a.as_ref());
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
        d.root_secret_from_hashes(&Digest::hash(&secret), &a_hash)
            .ok(),
        Some(secret),
        "a rebuild from d's earlier leaf key should derive the secret"
    );
}
