use keyhive_core::{
    access::Access::{Admin, Read},
    principal::public::Public,
    test_utils::{TestContext, TestResult as Result},
};

#[tokio::test]
async fn an_invitation_wraps_the_newest_secret_the_inviter_can_derive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.encrypt(&alice, design_doc, b"under the first").await?;

    // Bob's invitation wraps the first secret.
    let bob = ctx.individual("bob").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;

    // Adding bob blanked the root, so this write is under a later secret. Bob is
    // in the tree at this point.
    let second = ctx.encrypt(&alice, design_doc, b"under the second").await?;
    ctx.sync(&alice, &bob).await?;

    let carol = ctx.individual("carol").await?;
    bob.add_member(carol.id(), design_doc, Read, &[]).await?;
    ctx.sync(&alice, &carol).await?;
    ctx.sync(&bob, &carol).await?;
    ctx.give_content(&carol, &second).await?;

    assert_eq!(
        carol.try_decrypt_content(design_doc, &second).await?,
        b"under the second".to_vec(),
        "bob could derive the newer secret, so his invitation wraps that one"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_is_useless_to_a_non_member() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let ct = ctx.encrypt(&alice, design_doc, b"hello world").await?;

    // Bob gets an invitation from being added. Carol does not.
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;

    // Deliberately the wrong delivery to Carol.
    let for_bob = alice.static_events_for_agent(bob.id()).await;
    carol
        .ingest_unsorted_static_events(for_bob.into_values().collect())
        .await;

    assert!(
        !carol.can_decrypt_content(design_doc, &ct).await?,
        "carol has no secret for the prekey the invitation is encrypted to"
    );
    ctx.sync(&alice, &bob).await?;
    assert!(
        bob.can_decrypt_content(design_doc, &ct).await?,
        "bob reads the same write from the same invitation"
    );
    Ok(())
}

#[tokio::test]
async fn making_a_document_public_makes_its_history_public() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let earlier = ctx
        .encrypt(
            &alice,
            design_doc,
            b"written before the document was public",
        )
        .await?;
    alice.add_member(Public.id(), design_doc, Read, &[]).await?;

    // Carol was never added, but like everyone she has Public's key.
    let carol = ctx.individual("carol").await?;
    ctx.sync_as_public(&alice, &carol).await?;
    ctx.give_content(&carol, &earlier).await?;

    assert_eq!(
        carol.try_decrypt_content(design_doc, &earlier).await?,
        b"written before the document was public".to_vec(),
        "a public document reads from its start, not only from the next write onward"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_can_wrap_a_secret_the_inviter_got_from_its_own_invitation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    // Written first, so it predates every add below.
    let early = ctx
        .encrypt(&alice, design_doc, b"before anyone else was added")
        .await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;
    ctx.sync(&alice, &bob).await?;

    // Neither admin sees the other before acting. Bob's add blanked the root, so he
    // never derived the earlier secret from the tree and wraps the one his invitation gave him.
    let carol = ctx.individual("carol").await?;
    let dave = ctx.individual("dave").await?;
    alice.add_member(carol.id(), design_doc, Read, &[]).await?;
    bob.add_member(dave.id(), design_doc, Read, &[]).await?;

    ctx.sync_all_unsent().await?;
    ctx.give_content(&carol, &early).await?;
    ctx.give_content(&dave, &early).await?;

    for (reader, who) in [(&carol, "carol"), (&dave, "dave")] {
        assert_eq!(
            reader.try_decrypt_content(design_doc, &early).await?,
            b"before anyone else was added".to_vec(),
            "{who} reads content from before they joined"
        );
    }
    Ok(())
}
