mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Edit, Read, Relay};

#[tokio::test]
async fn delegating_to_public_creates_a_public_delegation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let public = ctx.public();

    for level in [Read, Edit, Admin] {
        let design_doc = ctx.doc(&alice, &format!("design_doc-{level:?}")).await?;

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

#[tokio::test]
async fn a_public_reader_reads_what_a_member_wrote() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"announcement").await?;

    ctx.sync_as_public(&alice, &bob).await?;

    assert_eq!(
        ctx.effective_access(&bob, &design_doc).await?,
        None,
        "bob is not a member and never becomes one"
    );
    assert_eq!(
        ctx.read(&bob, &ct).await?,
        b"announcement".to_vec(),
        "he reads it through the public delegation"
    );
    Ok(())
}

#[tokio::test]
async fn two_public_readers_meet_through_the_document() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;
    ctx.sync_as_public(&alice, &bob).await?;
    ctx.sync_as_public(&alice, &carol).await?;

    // Neither of them is a member. Both write and read as public.
    let from_bob = ctx.encrypt(&bob, &design_doc, b"from bob").await?;

    assert_eq!(
        ctx.read(&carol, &from_bob).await?,
        b"from bob".to_vec(),
        "carol reads what bob wrote, with neither of them a member"
    );
    Ok(())
}

#[tokio::test]
async fn another_member_does_not_displace_the_public_reader() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let server = ctx.individual("server").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &server, &design_doc, Relay).await?;
    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"relayed").await?;

    let pending = ctx.sync_as_public(&alice, &bob).await?;

    assert_eq!(pending, 0, "bob could apply every event he was sent");
    assert_eq!(
        ctx.read(&bob, &ct).await?,
        b"relayed".to_vec(),
        "the document is public whether or not it has other members"
    );
    Ok(())
}

#[tokio::test]
async fn a_public_document_is_reachable_as_public_and_not_as_yourself() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let server = ctx.individual("server").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &server, &design_doc, Relay).await?;
    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"announcement").await?;

    // The events reach bob through the server.
    ctx.sync(&alice, &server).await?;
    let pending = ctx.sync_as_public(&server, &bob).await?;

    assert_eq!(pending, 0, "bob could apply everything the server relayed");
    assert_eq!(
        ctx.effective_access_seen_by(&bob, &bob, &design_doc)
            .await?,
        None,
        "asking about himself does not find the document"
    );
    assert_eq!(
        ctx.effective_access_seen_by(&bob, &ctx.public(), &design_doc)
            .await?,
        Some(Read),
        "asking about public does"
    );
    assert_eq!(
        ctx.read(&bob, &ct).await?,
        b"announcement".to_vec(),
        "and he can read it"
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
    ctx.sync_all_unsent().await?;

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
