mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Edit, Read};

#[tokio::test]
async fn an_archive_round_trip_preserves_members_access_and_decryption() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa4c).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    ctx.delegate(&alice, &engineering, &design_doc, Edit)
        .await?;
    ctx.delegate(&alice, &bob, &engineering, Read).await?;
    ctx.delegate(&alice, &carol, &design_doc, Admin).await?;
    let ct = ctx
        .encrypt(&alice, &design_doc, b"before the archive")
        .await?;
    ctx.sync_all().await?;

    let members_before = ctx.transitive_members_of(&design_doc).await?;
    let archive = ctx.archive(&alice).await?;
    let restored = ctx.rebuild_from_archive(&archive, "alice-restored").await?;

    assert_eq!(
        ctx.transitive_members_of(&design_doc).await?,
        members_before,
        "the same people, at the same levels"
    );
    for who in [&bob, &carol] {
        assert_eq!(
            ctx.effective_access_seen_by(&restored, who, &design_doc)
                .await?,
            ctx.effective_access(who, &design_doc).await?,
            "the restored instance disagrees about {}",
            who.name()
        );
    }
    assert!(
        ctx.can_decrypt(&restored, &ct).await?,
        "and it can still read what it could read before"
    );
    Ok(())
}

#[tokio::test]
async fn a_restored_instance_can_still_issue_delegations() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa4c).await;
    let alice = ctx.individual("alice").await?;
    let dave = ctx.individual("dave").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.sync_all().await?;

    let archive = ctx.archive(&alice).await?;
    let restored = ctx.rebuild_from_archive(&archive, "alice-restored").await?;

    ctx.delegate(&restored, &dave, &design_doc, Edit).await?;
    ctx.sync_all().await?;

    assert_eq!(
        ctx.effective_access_seen_by(&alice, &dave, &design_doc)
            .await?,
        Some(Edit),
        "the original instance honors what the restored one signed"
    );
    Ok(())
}

#[tokio::test]
async fn an_old_archive_merged_with_later_events_converges() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa4c).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let old = ctx.archive(&alice).await?;

    // More happens after the archive is created.
    ctx.delegate(&alice, &carol, &design_doc, Admin).await?;
    ctx.revoke(&alice, &bob, &design_doc).await?;

    let restored = ctx
        .rebuild_from_archive(&old, "alice-from-old-archive")
        .await?;
    assert_eq!(
        ctx.effective_access_seen_by(&restored, &carol, &design_doc)
            .await?,
        None,
        "the archive predates carol's grant"
    );

    ctx.sync_all().await?;

    assert_eq!(
        ctx.effective_access_seen_by(&restored, &carol, &design_doc)
            .await?,
        ctx.effective_access(&carol, &design_doc).await?
    );
    assert_eq!(
        ctx.effective_access_seen_by(&restored, &bob, &design_doc)
            .await?,
        ctx.effective_access(&bob, &design_doc).await?,
        "including the revocation it never saw"
    );
    Ok(())
}

#[tokio::test]
async fn ingesting_an_archive_merges_into_a_live_instance() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa4c).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&bob, "notes").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.delegate(&bob, &alice, &notes, Read).await?;

    let from_bob = ctx.archive(&bob).await?;
    let pending = ctx.ingest_archive(&alice, from_bob).await?;

    assert_eq!(pending, 0, "nothing in bob's archive was unusable to alice");
    assert_eq!(
        ctx.effective_access_seen_by(&alice, &alice, &notes).await?,
        Some(Read),
        "alice learned about bob's document"
    );
    assert_eq!(
        ctx.effective_access_seen_by(&alice, &bob, &design_doc)
            .await?,
        Some(Read),
        "and kept what she already knew"
    );
    Ok(())
}
