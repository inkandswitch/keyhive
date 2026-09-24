//! Tests concurrent updates.

use crate::test_utils::Group;
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
