use keyhive_core::{
    access::Access::{Admin, Edit, Read, Relay},
    principal::public::Public,
    test_utils::{TestContext, TestError, TestResult as Result},
};
use std::collections::BTreeMap;

#[tokio::test]
async fn delegating_to_public_creates_a_public_delegation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let public = Public.id();

    for level in [Read, Edit, Admin] {
        let design_doc = ctx.doc(&alice, &format!("design_doc-{level:?}")).await?;

        assert_eq!(alice.access_for_doc(public, design_doc).await?, None);
        alice.add_member(public, design_doc, level, &[]).await?;

        assert_eq!(alice.access_for_doc(public, design_doc).await?, Some(level));
        assert_eq!(
            ctx.named_access(alice.reachable_members(design_doc).await?)
                .get("public"),
            Some(&level),
            "the public delegation should add public as a member"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_public_delegation_raises_best_access_for_doc_and_not_access_for_doc() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let public = Public.id();

    alice.add_member(public, design_doc, Read, &[]).await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        None,
        "nobody delegated anything to bob"
    );
    assert_eq!(
        alice.best_access_for_doc(bob.id(), design_doc).await?,
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
    let public = Public.id();

    alice.add_member(public, design_doc, Read, &[]).await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;

    assert_eq!(
        alice.best_access_for_doc(bob.id(), design_doc).await?,
        Some(Admin),
        "bob's own delegation is the better one"
    );
    assert_eq!(
        alice.best_access_for_doc(carol.id(), design_doc).await?,
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

    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    alice.force_pcs_update(design_doc).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"announcement").await?;

    ctx.sync_as_public(&alice, &bob).await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        None,
        "bob is not a member and never becomes one"
    );
    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
        b"announcement".to_vec(),
        "he reads it through the public delegation"
    );
    Ok(())
}

#[tokio::test]
async fn two_public_readers_meet_through_the_document() -> Result<()> {
    // Scenario:
    // Alice creates a doc and adds Public as a Read member.
    // A and B are not members of the doc.
    // A and B receive the doc events via the Public agent (simulating
    // the sync server checking Public access).
    // A encrypts content as Public, B decrypts as Public.
    //
    // ┌─────────────────────┐
    // │        Alice        │  (owner)
    // └─────────────────────┘
    //            │
    //            │ Read
    //            ▼
    // ┌─────────────────────┐
    // │       Public        │  (well-known identity)
    // └─────────────────────┘
    //
    // A and B are not members. They receive doc events because Public
    // has access, and encrypt/decrypt using Public's well-known keys.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    alice.force_pcs_update(design_doc).await?;
    ctx.sync_as_public(&alice, &bob).await?;
    ctx.sync_as_public(&alice, &carol).await?;

    // Neither of them is a member. Both write and read as public.
    let from_bob = ctx.encrypt(&bob, design_doc, b"from bob").await?;

    assert_eq!(
        carol.try_decrypt_content(design_doc, &from_bob).await?,
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

    alice
        .add_member(server.id(), design_doc, Relay, &[])
        .await?;
    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    alice.force_pcs_update(design_doc).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"relayed").await?;

    let pending = ctx.sync_as_public(&alice, &bob).await?;

    assert_eq!(pending, 0, "bob could apply every event he was sent");
    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
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

    // A document bob is a direct member of. The reachability assertion below
    // distinguishes "the public document is excluded" from "bob reaches nothing".
    let notes = ctx.doc(&alice, "notes").await?;
    alice.add_member(bob.id(), notes, Read, &[]).await?;

    alice
        .add_member(server.id(), design_doc, Relay, &[])
        .await?;
    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    alice.force_pcs_update(design_doc).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"announcement").await?;

    // The events reach bob through the server.
    ctx.sync(&alice, &server).await?;
    assert_eq!(
        ctx.pending_event_count(&server).await,
        0,
        "the server applied everything alice sent it"
    );
    assert!(
        !ctx.event_kinds_for(&server, &bob).await?.is_empty(),
        "the server has something to relay, so the assertions below are not on an empty delivery"
    );

    let pending = ctx.sync_as_public(&server, &bob).await?;

    assert_eq!(pending, 0, "bob could apply everything the server relayed");
    assert_eq!(
        bob.access_for_doc(bob.id(), design_doc).await?,
        None,
        "asking about himself does not find the document"
    );
    ctx.sync(&alice, &bob).await?;
    assert_eq!(
        ctx.named(bob.docs_reachable_by_agent(bob.id()).await?),
        BTreeMap::from([("notes".to_string(), Read)]),
        "the documents he reaches because of his personal access are notes and only \
        notes, so the public one is excluded rather than there being nothing to exclude it from"
    );
    assert_eq!(
        bob.access_for_doc(Public.id(), design_doc).await?,
        Some(Read),
        "asking about public does"
    );
    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
        b"announcement".to_vec(),
        "and he can read it"
    );
    Ok(())
}

// `has_received` and `can_decrypt_content` answer different questions, and this is
// where the difference shows.
#[tokio::test]
async fn a_public_delegation_does_not_deliver_the_document() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"announcement").await?;
    ctx.sync_all_unsent().await?;

    assert!(
        !bob.has_received(design_doc).await,
        "bob was never sent the document"
    );
    assert!(
        matches!(
            bob.can_decrypt_content(design_doc, &ct)
                .await
                .map_err(TestError::from),
            Err(TestError::NotSynced(_))
        ),
        "so asking whether he can decrypt it reports that, rather than a plain no"
    );
    Ok(())
}
