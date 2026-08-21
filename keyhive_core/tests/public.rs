mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Edit, Read};

#[tokio::test]
async fn delegating_to_public_records_a_public_delegation() -> Result<()> {
    for level in [Read, Edit, Admin] {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        let public = ctx.public();

        assert_eq!(ctx.effective_access(&public, &design_doc).await?, None);
        ctx.delegate(&alice, &public, &design_doc, level).await?;

        assert_eq!(
            ctx.effective_access(&public, &design_doc).await?,
            Some(level)
        );
        assert_eq!(
            ctx.transitive_members_of(&design_doc).await?.get("public"),
            Some(&level),
            "the public delegation should add public as a member"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_public_delegation_raises_best_access_and_not_effective_access() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let public = ctx.public();

    ctx.delegate(&alice, &public, &design_doc, Read).await?;

    assert_eq!(
        ctx.effective_access(&bob, &design_doc).await?,
        None,
        "nobody delegated anything to bob"
    );
    assert_eq!(
        ctx.best_access(&bob, &design_doc).await?,
        Some(Read),
        "the document is public"
    );
    Ok(())
}

#[tokio::test]
async fn a_direct_delegation_and_a_public_delegation_take_the_higher() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let public = ctx.public();

    ctx.delegate(&alice, &public, &design_doc, Read).await?;
    ctx.delegate(&alice, &bob, &design_doc, Admin).await?;

    assert_eq!(
        ctx.best_access(&bob, &design_doc).await?,
        Some(Admin),
        "bob's own delegation is the better one"
    );
    assert_eq!(
        ctx.best_access(&carol, &design_doc).await?,
        Some(Read),
        "carol has only the public delegation"
    );
    Ok(())
}

// This is a sanity check for the testing facade
#[tokio::test]
async fn a_public_delegation_does_not_deliver_the_document() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"announcement").await?;
    ctx.sync_all().await?;

    assert!(
        !ctx.has_received(&bob, &design_doc).await?,
        "bob was never sent the document"
    );
    assert!(
        !ctx.can_decrypt(&bob, &ct).await?,
        "bob can't decrypt a document he doesn't have"
    );
    Ok(())
}
