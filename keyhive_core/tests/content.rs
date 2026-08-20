mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::Read;

#[tokio::test]
async fn a_member_added_before_a_write_can_derive_its_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"hello world").await?;
    ctx.sync_all().await?;

    assert!(ctx.can_decrypt(&bob, &ct).await?);
    Ok(())
}

#[tokio::test]
async fn a_member_added_after_a_write_cannot_derive_its_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let ct = ctx.encrypt(&alice, &design_doc, b"before bob").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all().await?;

    assert!(
        ctx.can_decrypt(&alice, &ct).await?,
        "the author can still read"
    );
    assert!(!ctx.can_decrypt(&bob, &ct).await?, "bob should not be able to derive the key");
    Ok(())
}
