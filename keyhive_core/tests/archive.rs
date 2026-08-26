use keyhive_core::{
    access::Access::{Admin, Edit, Read},
    test_utils::{TestContext, TestError, TestResult as Result},
};

#[tokio::test]
async fn an_archive_round_trip_preserves_members_access_and_decryption() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    alice.add_member(carol.id(), design_doc, Admin, &[]).await?;
    let ct = ctx
        .encrypt(&alice, design_doc, b"before the archive")
        .await?;
    ctx.sync_all_unsent().await?;

    let members_before = ctx.named_access(alice.reachable_members(design_doc).await?);
    let archive = alice.into_archive().await;
    let restored = ctx.rebuild_from_archive(&archive, "alice-restored").await?;

    assert_eq!(
        ctx.named_access(alice.reachable_members(design_doc).await?),
        members_before,
        "the same people, at the same levels"
    );
    for who in [&bob, &carol] {
        assert_eq!(
            restored.access_for_doc(who, design_doc).await?,
            alice.access_for_doc(who, design_doc).await?,
            "the restored instance disagrees about {}",
            who.name()
        );
    }
    assert_eq!(
        restored.try_decrypt_content(design_doc, &ct).await?,
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

    let archive = alice.into_archive().await;
    let restored = ctx.rebuild_from_archive(&archive, "alice-restored").await?;

    restored
        .add_member(dave.id(), design_doc, Edit, &[])
        .await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        alice.access_for_doc(dave.id(), design_doc).await?,
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

    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    let old = alice.into_archive().await;

    // More happens after the archive is created.
    alice.add_member(carol.id(), design_doc, Admin, &[]).await?;
    alice.revoke_member(bob.id(), true, design_doc).await?;

    let restored = ctx
        .rebuild_from_archive(&old, "alice-from-old-archive")
        .await?;
    assert_eq!(
        restored.access_for_doc(carol.id(), design_doc).await?,
        None,
        "the archive predates carol's delegation"
    );

    ctx.sync_all_unsent().await?;

    assert_eq!(
        restored.access_for_doc(carol.id(), design_doc).await?,
        alice.access_for_doc(carol.id(), design_doc).await?
    );
    assert_eq!(
        restored.access_for_doc(bob.id(), design_doc).await?,
        alice.access_for_doc(bob.id(), design_doc).await?,
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

    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    bob.add_member(alice.id(), notes, Read, &[]).await?;

    let from_bob = bob.into_archive().await;
    let pending = alice.ingest_archive(from_bob).await?.len();

    assert_eq!(pending, 0, "nothing in bob's archive was unusable to alice");
    assert_eq!(
        alice.access_for_doc(alice.id(), notes).await?,
        Some(Read),
        "alice learned about bob's document"
    );
    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        Some(Read),
        "and kept what she already knew"
    );
    Ok(())
}

#[tokio::test]
async fn an_instance_caught_up_by_syncing_can_read_what_it_missed() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let early = alice.into_archive().await;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let ct = ctx.encrypt(&alice, design_doc, b"hello world").await?;

    let restored = ctx.rebuild_from_archive(&early, "alice-restored").await?;
    assert!(
        !restored.has_received(design_doc).await,
        "the archive predates the document"
    );

    // It cannot read the content, and the reason is that it has never heard of the document
    // rather than that it holds the wrong key. Those are different failures and only one of
    // them is fixed by syncing.
    assert!(
        matches!(
            restored
                .can_decrypt_content(design_doc, &ct)
                .await
                .map_err(TestError::from),
            Err(TestError::NotSynced(_))
        ),
        "and it can't yet be asked about content in a document it does not have"
    );

    ctx.sync_all_unsent().await?;

    assert_eq!(
        restored.try_decrypt_content(design_doc, &ct).await?,
        b"hello world".to_vec(),
        "but after sync, it reads content written while it did not exist"
    );
    Ok(())
}

#[tokio::test]
async fn an_archive_merged_into_a_rebuild_reaches_a_readable_state() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let early = alice.into_archive().await;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let ct = ctx
        .encrypt(&alice, design_doc, b"written after the fork")
        .await?;

    let restored = ctx.rebuild_from_archive(&early, "alice-restored").await?;
    let latest = alice.into_archive().await;
    let pending = restored.ingest_archive(latest).await?.len();
    assert_eq!(pending, 0, "the later archive was ingested completely");

    // The archive carries the membership graph and not the key state, which is what
    // `ingesting_an_archive_carries_the_key_state_as_well_as_the_graph` covers.
    // The events carry the key state, so the two together reach a readable state.
    ctx.sync_all_unsent().await?;

    assert_eq!(
        restored.try_decrypt_content(design_doc, &ct).await?,
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

    let early = alice.into_archive().await;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let ct = ctx.encrypt(&alice, design_doc, b"hello world").await?;

    let restored = ctx.rebuild_from_archive(&early, "alice-restored").await?;
    let latest = alice.into_archive().await;
    let pending = restored.ingest_archive(latest).await?.len();

    assert_eq!(pending, 0, "the archive was ingested completely");
    assert_eq!(
        restored.access_for_doc(alice.id(), design_doc).await?,
        Some(Admin),
        "and it believes it is an admin of the document"
    );
    assert!(
        restored.can_decrypt_content(design_doc, &ct).await?,
        "so it should be able to read the document it is an admin of"
    );
    Ok(())
}
