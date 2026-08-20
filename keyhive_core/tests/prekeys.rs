mod facade;

use facade::{Result, TestContext, TestPrekeyOp};
use keyhive_core::access::Access::Read;

#[tokio::test]
async fn expanding_prekeys_adds_a_distinct_key() -> Result<()> {
    let mut ctx = TestContext::with_seed(0x9e0).await;
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
    let mut ctx = TestContext::with_seed(0x9e0).await;
    let alice = ctx.individual("alice").await?;

    let old = ctx.expand_prekeys(&alice).await?;
    let new = ctx.rotate_prekey(&alice, &old).await?;

    assert_ne!(new, old, "a rotation produces a different key");
    let ops = ctx.prekey_ops(&alice, &alice).await?;
    assert!(
        ops.contains(&TestPrekeyOp::Rotated { old, new }),
        "the rotation names both keys"
    );
    assert!(
        ops.contains(&TestPrekeyOp::Added { new: old }),
        "and the op that introduced the old key is still in the log"
    );
    Ok(())
}

#[tokio::test]
async fn a_prekey_rotation_reaches_a_peer() -> Result<()> {
    let mut ctx = TestContext::with_seed(0x9e0).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all().await?;

    let old = ctx.expand_prekeys(&alice).await?;
    let new = ctx.rotate_prekey(&alice, &old).await?;
    assert!(
        !ctx.prekey_ops(&bob, &alice)
            .await?
            .contains(&TestPrekeyOp::Rotated { old, new }),
        "bob hasn't seen alice's rotation yet"
    );

    ctx.sync_all().await?;

    assert!(
        ctx.prekey_ops(&bob, &alice)
            .await?
            .contains(&TestPrekeyOp::Rotated { old, new }),
        "bob sees alice's rotation"
    );
    Ok(())
}
