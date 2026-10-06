//! The update predecessor secret chain.

use keyhive_core::{
    access::Access::{Admin, Read},
    test_utils::{TestContext, TestResult as Result},
};

#[tokio::test]
async fn the_chain_goes_back_past_the_secret_an_invitation_wraps() -> Result<()> {
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
    // wraps what the inviter can derive when it is created and alice cannot reach
    // bob's secret yet, so carol's can't contain it.
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

    // Carol updates. Bob's update is a nearest ancestor she cannot derive, so her
    // update has no entry for it.
    carol.force_pcs_update(design_doc).await?;
    ctx.sync(&carol, &alice).await?;

    // Alice updates next. Her only nearest ancestor is carol's update, so she wraps
    // bob's only because it is still listed as unchained.
    alice.force_pcs_update(design_doc).await?;
    ctx.sync(&alice, &carol).await?;

    // Carol invites dave. Her invitation wraps alice's update, and dave follows
    // its chain back to bob's.
    let dave = ctx.individual("dave").await?;
    carol.add_member(dave.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;
    ctx.give_content(&dave, &on_bob).await?;

    assert_eq!(
        dave.try_decrypt_content(design_doc, &on_bob).await?,
        b"on bob".to_vec(),
        "carol could not wrap bob's update, so dave reaches it only through alice's"
    );
    Ok(())
}
