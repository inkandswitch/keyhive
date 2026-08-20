mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Edit, Read};

#[tokio::test]
async fn an_archive_round_trip_preserves_members_access_and_decryption() -> Result<()> {
    let mut ctx = TestContext::new().await;
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
    ctx.sync_all_unsent().await?;

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
    assert_eq!(
        ctx.read(&restored, &ct).await?,
        b"before the archive".to_vec(),
        "and it can still read what it could read before"
    );
    Ok(())
}

#[tokio::test]
async fn a_restored_instance_can_still_issue_delegations() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let dave = ctx.individual("dave").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.sync_all_unsent().await?;

    let archive = ctx.archive(&alice).await?;
    let restored = ctx.rebuild_from_archive(&archive, "alice-restored").await?;

    ctx.delegate(&restored, &dave, &design_doc, Edit).await?;
    ctx.sync_all_unsent().await?;

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
    let mut ctx = TestContext::new().await;
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
        "the archive predates carol's delegation"
    );

    ctx.sync_all_unsent().await?;

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
    let mut ctx = TestContext::new().await;
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

#[tokio::test]
async fn an_instance_caught_up_by_syncing_can_read_what_it_missed() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let early = ctx.archive(&alice).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"hello world").await?;

    let restored = ctx.rebuild_from_archive(&early, "alice-restored").await?;
    assert!(
        !ctx.has_received(&restored, &design_doc).await?,
        "the archive predates the document"
    );

    assert!(
        !ctx.can_decrypt(&restored, &ct).await?,
        "and it can't yet read content written while it did not exist"
    );

    ctx.sync_all_unsent().await?;

    assert_eq!(
        ctx.read(&restored, &ct).await?,
        b"hello world".to_vec(),
        "but after sync, it reads content written while it did not exist"
    );
    Ok(())
}

#[tokio::test]
async fn an_archive_merged_into_a_rebuild_reaches_a_readable_state() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let early = ctx.archive(&alice).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let ct = ctx
        .encrypt(&alice, &design_doc, b"written after the fork")
        .await?;

    let restored = ctx.rebuild_from_archive(&early, "alice-restored").await?;
    let latest = ctx.archive(&alice).await?;
    let pending = ctx.ingest_archive(&restored, latest).await?;
    assert_eq!(pending, 0, "the later archive was ingested completely");

    // The archive carries the membership graph and not the key state, which is what
    // `ingesting_an_archive_carries_the_key_state_as_well_as_the_graph` covers.
    // The events carry the key state, so the two together reach a readable state.
    ctx.sync_all_unsent().await?;

    assert_eq!(
        ctx.read(&restored, &ct).await?,
        b"written after the fork".to_vec(),
        "rebuilt from the earlier archive, merged with the later one, caught up by events"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "ingesting an archive brings the membership graph but not the key state"]
async fn ingesting_an_archive_carries_the_key_state_as_well_as_the_graph() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let early = ctx.archive(&alice).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"hello world").await?;

    let restored = ctx.rebuild_from_archive(&early, "alice-restored").await?;
    let latest = ctx.archive(&alice).await?;
    let pending = ctx.ingest_archive(&restored, latest).await?;

    assert_eq!(pending, 0, "the archive was ingested completely");
    assert_eq!(
        ctx.effective_access_seen_by(&restored, &alice, &design_doc)
            .await?,
        Some(Admin),
        "and it believes it is an admin of the document"
    );
    assert!(
        ctx.can_decrypt(&restored, &ct).await?,
        "so it should be able to read the document it is an admin of"
    );
    Ok(())
}
