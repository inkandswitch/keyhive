//! Reading back through update predecessor key chains.

use keyhive_core::{
    access::Access::{Admin, Read},
    principal::public::Public,
    test_utils::{TestContext, TestResult as Result},
};

#[tokio::test]
async fn the_chain_reaches_past_the_secret_an_invitation_wraps() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let first = ctx.encrypt(&alice, design_doc, b"under the first").await?;
    alice.force_pcs_update(design_doc).await?;
    let second = ctx.encrypt(&alice, design_doc, b"under the second").await?;
    alice.force_pcs_update(design_doc).await?;
    let third = ctx.encrypt(&alice, design_doc, b"under the third").await?;

    // Carol was in the tree for none of those rotations.
    let carol = ctx.individual("carol").await?;
    alice.add_member(carol.id(), design_doc, Read, &[]).await?;
    ctx.sync(&alice, &carol).await?;
    for ct in [&first, &second, &third] {
        ctx.give_content(&carol, ct).await?;
    }

    for (ct, expected) in [
        (&first, b"under the first".to_vec()),
        (&second, b"under the second".to_vec()),
        (&third, b"under the third".to_vec()),
    ] {
        assert_eq!(carol.try_decrypt_content(design_doc, ct).await?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn an_inviter_offers_the_newest_secret_it_can_reach() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.encrypt(&alice, design_doc, b"under the first").await?;

    // Bob's invitation wraps the first secret.
    let bob = ctx.individual("bob").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;

    // Adding bob blanked the root, so this write is under a later secret. Bob is
    // in the tree for it.
    let second = ctx.encrypt(&alice, design_doc, b"under the second").await?;
    ctx.sync(&alice, &bob).await?;

    // Bob invites carol without ever having read or written, so the only secret
    // he has recorded is the older one his own invitation named.
    let carol = ctx.individual("carol").await?;
    bob.add_member(carol.id(), design_doc, Read, &[]).await?;
    ctx.sync(&alice, &carol).await?;
    ctx.sync(&bob, &carol).await?;
    ctx.give_content(&carol, &second).await?;

    assert_eq!(
        carol.try_decrypt_content(design_doc, &second).await?,
        b"under the second".to_vec(),
        "bob could reach the newer secret, so his invitation offers that one"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_is_useless_to_a_non_member() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let ct = ctx.encrypt(&alice, design_doc, b"hello world").await?;

    // Bob is named and so gets an invitation. Carol is not.
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;

    // Deliberately the wrong delivery, which `TestContext::sync` will not do:
    // carol is handed everything bob would receive, invitation included.
    let for_bob = alice.static_events_for_agent(bob.id()).await;
    carol
        .ingest_unsorted_static_events(for_bob.into_values().collect())
        .await;

    assert!(
        !carol.can_decrypt_content(design_doc, &ct).await?,
        "carol holds no key for the prekey the invitation is encrypted to"
    );
    Ok(())
}

#[tokio::test]
async fn the_chain_survives_members_who_only_ever_held_an_invitation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let first = ctx.encrypt(&alice, design_doc, b"under the first").await?;

    let bob = ctx.individual("bob").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;
    let second = ctx.encrypt(&alice, design_doc, b"under the second").await?;
    ctx.sync(&alice, &bob).await?;

    // Bob invites carol without ever reading or writing.
    let carol = ctx.individual("carol").await?;
    bob.add_member(carol.id(), design_doc, Admin, &[]).await?;
    ctx.sync(&alice, &carol).await?;
    ctx.sync(&bob, &carol).await?;

    // Carol writes without reading. Her only secret came from her invitation, and
    // her add blanked the root, so this rotates and has to add that secret to the
    // chain.
    ctx.encrypt(&carol, design_doc, b"written by carol").await?;

    // Carol then invites dave, two invitation hops from anyone who wrote.
    let dave = ctx.individual("dave").await?;
    carol.add_member(dave.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;
    ctx.give_content(&dave, &first).await?;
    ctx.give_content(&dave, &second).await?;

    assert_eq!(
        dave.try_decrypt_content(design_doc, &first).await?,
        b"under the first".to_vec(),
        "the chain reaches the oldest secret through two members who only ever held an invitation"
    );
    assert_eq!(
        dave.try_decrypt_content(design_doc, &second).await?,
        b"under the second".to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn a_member_that_has_only_been_invited_still_wraps_the_earlier_secret() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let first = ctx.encrypt(&alice, design_doc, b"written by alice").await?;

    // Bob's invitation wraps the secret that write used.
    let bob = ctx.individual("bob").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;
    ctx.sync(&alice, &bob).await?;

    // Bob writes without ever reading, so the only secret he holds is the one in
    // his invitation. His write rotates, because his add blanked his path.
    ctx.encrypt(&bob, design_doc, b"written by bob").await?;

    let carol = ctx.individual("carol").await?;
    bob.add_member(carol.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;
    ctx.give_content(&carol, &first).await?;

    assert_eq!(
        carol.try_decrypt_content(design_doc, &first).await?,
        b"written by alice".to_vec(),
        "bob held alice's secret only in an invitation, and his update still wraps \
         it forward for carol"
    );
    Ok(())
}

#[tokio::test]
async fn an_invitation_survives_a_rotation_after_the_last_write() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let ct = ctx.encrypt(&alice, design_doc, b"hello world").await?;
    // The rotation lands after the write, so the secret bob is invited with is
    // newer than the one the content used.
    alice.force_pcs_update(design_doc).await?;

    let bob = ctx.individual("bob").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.sync(&alice, &bob).await?;
    ctx.give_content(&bob, &ct).await?;

    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
        b"hello world".to_vec(),
        "the invitation reaches back past the rotation to the key the content used"
    );
    Ok(())
}

#[tokio::test]
async fn making_a_document_public_opens_its_history() -> Result<()> {
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

    // Carol was never added, but like everyone she holds Public's key.
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
async fn an_invitation_wraps_every_update_head_the_inviter_can_reach() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;

    let shared = ctx.encrypt(&alice, design_doc, b"before the fork").await?;
    ctx.sync(&alice, &bob).await?;

    // Each rotates and writes without seeing the other, so the graph ends in two
    // concurrent updates.
    alice.force_pcs_update(design_doc).await?;
    let on_alice = ctx.encrypt(&alice, design_doc, b"on alice").await?;
    bob.force_pcs_update(design_doc).await?;
    let on_bob = ctx.encrypt(&bob, design_doc, b"on bob").await?;

    // Alice takes bob's branch, so both updates are heads she can reach.
    ctx.sync(&bob, &alice).await?;

    let carol = ctx.individual("carol").await?;
    alice.add_member(carol.id(), design_doc, Read, &[]).await?;
    ctx.sync(&alice, &carol).await?;
    for ct in [&shared, &on_alice, &on_bob] {
        ctx.give_content(&carol, ct).await?;
    }

    assert_eq!(
        carol.try_decrypt_content(design_doc, &on_alice).await?,
        b"on alice".to_vec(),
        "the invitation wraps alice's head"
    );
    assert_eq!(
        carol.try_decrypt_content(design_doc, &on_bob).await?,
        b"on bob".to_vec(),
        "and bob's, which alice can reach but did not produce"
    );
    assert_eq!(
        carol.try_decrypt_content(design_doc, &shared).await?,
        b"before the fork".to_vec(),
        "and the chain reaches behind both"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_invites_from_two_admins_both_open_earlier_content() -> Result<()> {
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

    // Neither admin sees the other before acting.
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

#[tokio::test]
async fn a_later_update_encrypts_a_secret_no_invitation_wrapped() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;
    ctx.encrypt(&alice, design_doc, b"before the fork").await?;
    ctx.sync(&alice, &bob).await?;

    // Each rotates without seeing the other. Only bob writes on his branch.
    alice.force_pcs_update(design_doc).await?;
    bob.force_pcs_update(design_doc).await?;
    let on_bob = ctx.encrypt(&bob, design_doc, b"on bob").await?;

    // Carol is invited while alice is still partitioned from bob. An invitation
    // wraps what the inviter can derive when it is created, and alice cannot reach
    // bob's secret yet, so carol's can never contain it.
    let carol = ctx.individual("carol").await?;
    alice.add_member(carol.id(), design_doc, Admin, &[]).await?;
    ctx.sync(&alice, &carol).await?;
    ctx.give_content(&carol, &on_bob).await?;
    assert!(
        !carol.can_decrypt_content(design_doc, &on_bob).await?,
        "precondition: carol's invitation does not reach bob's secret"
    );

    // Alice takes bob's branch, so she can derive his secret, and rotates. Encrypting
    // it into that update is the only way it can reach carol.
    ctx.sync(&bob, &alice).await?;
    alice.force_pcs_update(design_doc).await?;
    ctx.sync(&alice, &carol).await?;

    assert_eq!(
        carol.try_decrypt_content(design_doc, &on_bob).await?,
        b"on bob".to_vec(),
        "carol derives alice's newest secret from the tree and traverses the chain back to bob's"
    );
    Ok(())
}

#[tokio::test]
async fn an_update_propagates_an_ancestor_it_cannot_derive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Admin, &[]).await?;

    ctx.encrypt(&alice, design_doc, b"before the fork").await?;
    ctx.sync(&alice, &bob).await?;

    // Each rotates without seeing the other. Only bob writes on his branch.
    alice.force_pcs_update(design_doc).await?;
    bob.force_pcs_update(design_doc).await?;
    let on_bob = ctx.encrypt(&bob, design_doc, b"on bob").await?;

    // Carol is added while still partitioned, so her invitation wraps alice's
    // update and she has no way to reach bob's.
    let carol = ctx.individual("carol").await?;
    alice.add_member(carol.id(), design_doc, Admin, &[]).await?;

    // Alice takes bob's branch first, then carol receives from alice. Bob never
    // heard of carol, so he has nothing to send her.
    ctx.sync(&bob, &alice).await?;
    ctx.sync(&alice, &carol).await?;

    // Carol updates. Bob's update is a nearest ancestor she cannot derive, so she
    // has to record it as unreachable rather than drop it. Drop it here and
    // nothing afterwards ever points at bob's update again.
    carol.force_pcs_update(design_doc).await?;
    ctx.sync(&carol, &alice).await?;

    // Alice updates next. Her only nearest ancestor is carol's update, so unless
    // carol's carried the gap forward nothing points at bob's update again.
    alice.force_pcs_update(design_doc).await?;

    let dave = ctx.individual("dave").await?;
    alice.add_member(dave.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;
    ctx.give_content(&dave, &on_bob).await?;

    assert_eq!(
        dave.try_decrypt_content(design_doc, &on_bob).await?,
        b"on bob".to_vec(),
        "carol could not reach bob's update, so she propagated it for alice to handle"
    );
    Ok(())
}
