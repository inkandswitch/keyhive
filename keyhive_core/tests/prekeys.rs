mod facade;

use facade::{Result, TestContext, TestPrekeyOp};
use keyhive_core::access::Access::Read;

#[tokio::test]
async fn expanding_prekeys_adds_a_distinct_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let before = ctx.prekey_ops(&alice, &alice).await?;
    let added = ctx.expand_prekeys(&alice).await?;
    let after = ctx.prekey_ops(&alice, &alice).await?;

    assert_eq!(after.len(), before.len() + 1, "exactly one op was recorded");
    assert!(
        !before.iter().any(|op| op.new_key() == added),
        "the key is new"
    );
    assert!(
        after.contains(&TestPrekeyOp::Added { new: added }),
        "and it was recorded as an addition"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_a_prekey_records_what_it_replaced() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let old = ctx.expand_prekeys(&alice).await?;
    let new = ctx.rotate_prekey(&alice, &old).await?;

    assert_ne!(new, old, "a rotation produces a different key");
    let ops = ctx.prekey_ops(&alice, &alice).await?;
    assert!(
        ops.contains(&TestPrekeyOp::Rotated { old, new }),
        "the rotation records the key it replaced and its replacement"
    );
    assert!(
        ops.contains(&TestPrekeyOp::Added { new: old }),
        "and the op that introduced the old key is still in the log"
    );
    Ok(())
}

#[tokio::test]
async fn a_prekey_rotation_reaches_a_peer() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let old = ctx.expand_prekeys(&alice).await?;
    let new = ctx.rotate_prekey(&alice, &old).await?;
    assert!(
        !ctx.prekey_ops(&bob, &alice)
            .await?
            .contains(&TestPrekeyOp::Rotated { old, new }),
        "bob hasn't seen alice's rotation yet"
    );

    ctx.sync_all_unsent().await?;

    assert!(
        ctx.prekey_ops(&bob, &alice)
            .await?
            .contains(&TestPrekeyOp::Rotated { old, new }),
        "bob sees alice's rotation"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_a_prekey_replaces_the_old_one() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let old = ctx.expand_prekeys(&alice).await?;
    assert!(ctx.prekeys(&alice, &alice).await?.contains(&old));

    let new = ctx.rotate_prekey(&alice, &old).await?;
    let live = ctx.prekeys(&alice, &alice).await?;

    assert!(live.contains(&new), "the replacement is live");
    assert!(!live.contains(&old), "the replaced key is not");
    Ok(())
}

#[tokio::test]
async fn a_rotated_away_intermediate_prekey_does_not_survive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let k1 = ctx.expand_prekeys(&alice).await?;
    let k2 = ctx.rotate_prekey(&alice, &k1).await?;
    let k3 = ctx.rotate_prekey(&alice, &k2).await?;

    let live = ctx.prekeys(&alice, &alice).await?;
    assert!(live.contains(&k3), "the last key is live");
    assert!(!live.contains(&k2), "the intermediate is not");
    assert!(!live.contains(&k1), "and neither is the original");
    Ok(())
}

#[tokio::test]
async fn two_concurrent_rotations_of_one_key_both_survive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;

    let k1 = ctx.expand_prekeys(&alice).await?;
    ctx.sync_all_unsent().await?;
    assert!(
        ctx.prekeys(&alice_worker, &alice).await?.contains(&k1),
        "both instances start from the same key"
    );

    // Neither rotation has heard of the other.
    let from_first = ctx.rotate_prekey(&alice, &k1).await?;
    let from_worker = ctx.rotate_prekey(&alice_worker, &k1).await?;
    assert_ne!(from_first, from_worker);

    ctx.sync_all_unsent().await?;

    for observer in [&alice, &alice_worker] {
        let live = ctx.prekeys(observer, &alice).await?;
        assert!(
            live.contains(&from_first) && live.contains(&from_worker),
            "{} lost one of the two concurrent replacements",
            observer.name()
        );
        assert!(
            !live.contains(&k1),
            "{} kept the key both rotations replaced",
            observer.name()
        );
    }
    Ok(())
}
