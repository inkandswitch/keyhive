use keyhive_core::{
    access::Access::Read,
    test_utils::{PrekeyOp, TestContext, TestResult as Result},
};

#[tokio::test]
async fn expanding_prekeys_adds_a_distinct_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let before = ctx.prekey_ops_of(&alice, alice.id()).await?;
    let added = alice.expand_prekeys().await?.payload().share_key;
    let after = ctx.prekey_ops_of(&alice, alice.id()).await?;

    assert_eq!(after.len(), before.len() + 1, "exactly one op was recorded");
    assert!(
        !before.iter().any(|op| op.new_key() == added),
        "the key is new"
    );
    assert!(
        after.contains(&PrekeyOp::Added { new: added }),
        "and it was recorded as an addition"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_a_prekey_records_what_it_replaced() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let old = alice.expand_prekeys().await?.payload().share_key;
    let new = alice.rotate_prekey(old).await?.payload().new;

    assert_ne!(new, old, "a rotation produces a different key");
    let ops = ctx.prekey_ops_of(&alice, alice.id()).await?;
    assert!(
        ops.contains(&PrekeyOp::Rotated { old, new }),
        "the rotation records the key it replaced and its replacement"
    );
    assert!(
        ops.contains(&PrekeyOp::Added { new: old }),
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
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;

    let old = alice.expand_prekeys().await?.payload().share_key;
    let new = alice.rotate_prekey(old).await?.payload().new;
    assert!(
        !ctx.prekey_ops_of(&bob, alice.id())
            .await?
            .contains(&PrekeyOp::Rotated { old, new }),
        "bob hasn't seen alice's rotation yet"
    );

    ctx.sync_all_unsent().await?;

    assert!(
        ctx.prekey_ops_of(&bob, alice.id())
            .await?
            .contains(&PrekeyOp::Rotated { old, new }),
        "bob sees alice's rotation"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_a_prekey_replaces_the_old_one() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let old = alice.expand_prekeys().await?.payload().share_key;
    assert!(ctx.prekeys_of(&alice, alice.id()).await?.contains(&old));

    let new = alice.rotate_prekey(old).await?.payload().new;
    let live = ctx.prekeys_of(&alice, alice.id()).await?;

    assert!(live.contains(&new), "the replacement is live");
    assert!(!live.contains(&old), "the replaced key is not");
    Ok(())
}

#[tokio::test]
async fn a_rotated_away_intermediate_prekey_does_not_survive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let k1 = alice.expand_prekeys().await?.payload().share_key;
    let k2 = alice.rotate_prekey(k1).await?.payload().new;
    let k3 = alice.rotate_prekey(k2).await?.payload().new;

    let live = ctx.prekeys_of(&alice, alice.id()).await?;
    assert!(live.contains(&k3), "the last key is live");
    assert!(!live.contains(&k2), "the intermediate is not");
    assert!(!live.contains(&k1), "and neither is the original");
    Ok(())
}

#[tokio::test]
async fn two_concurrent_rotations_of_one_key_both_survive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;

    let k1 = alice.expand_prekeys().await?.payload().share_key;
    ctx.sync_all_unsent().await?;
    assert!(
        ctx.prekeys_of(&alice_worker, alice.id())
            .await?
            .contains(&k1),
        "both instances start from the same key"
    );

    // Neither rotation has heard of the other.
    let from_first = alice.rotate_prekey(k1).await?.payload().new;
    let from_worker = alice_worker.rotate_prekey(k1).await?.payload().new;
    assert_ne!(from_first, from_worker);

    ctx.sync_all_unsent().await?;

    for observer in [&alice, &alice_worker] {
        let live = ctx.prekeys_of(observer, alice.id()).await?;
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
