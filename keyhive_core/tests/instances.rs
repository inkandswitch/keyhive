mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Read};

#[tokio::test]
async fn two_instances_of_one_identity_are_one_member() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa11ce).await;
    let bob = ctx.individual("bob").await?;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;
    let design_doc = ctx.doc(&bob, "design_doc").await?;

    ctx.delegate(&bob, &alice, &design_doc, Read).await?;

    let members = ctx.transitive_members_of(&design_doc).await?;
    assert_eq!(members.get("alice"), Some(&Read));
    assert_eq!(
        members.get("alice-worker"),
        None,
        "the graph knows the identity, not the device"
    );
    assert_eq!(
        ctx.effective_access(&alice_worker, &design_doc).await?,
        Some(Read),
        "a delegation to one instance is a delegation to the identity"
    );
    Ok(())
}

#[tokio::test]
async fn either_instance_signs_as_the_identity() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa11ce).await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.sync_all().await?;

    ctx.delegate(&alice_worker, &carol, &design_doc, Admin)
        .await?;

    assert_eq!(
        ctx.effective_access_seen_by(&alice_worker, &carol, &design_doc)
            .await?,
        Some(Admin)
    );

    // Instances are separate replicas, so the first one learns of the delegation by sync like
    // anyone else.
    assert_eq!(
        ctx.effective_access_seen_by(&alice, &carol, &design_doc)
            .await?,
        None,
        "the first instance doesn't know about the delegation yet"
    );
    ctx.sync_all().await?;
    assert_eq!(
        ctx.effective_access_seen_by(&alice, &carol, &design_doc)
            .await?,
        Some(Admin),
        "the first instance honours what the second signed"
    );
    Ok(())
}

#[tokio::test]
async fn a_sibling_needs_the_prekey_secrets_to_open_an_invitation() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa11ce).await;
    let bob = ctx.individual("bob").await?;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;
    let design_doc = ctx.doc(&bob, "design_doc").await?;

    ctx.delegate(&bob, &alice, &design_doc, Read).await?;
    let ct = ctx
        .encrypt(&bob, &design_doc, b"invitation content")
        .await?;
    ctx.sync_all().await?;

    // Both instances know the document and both are members.
    assert!(ctx.has_received(&alice_worker, &design_doc).await?);
    assert_eq!(
        ctx.effective_access(&alice_worker, &design_doc).await?,
        Some(Read)
    );

    // Exactly one of them holds the secret key.
    let (invited, sibling) = if ctx.can_decrypt(&alice, &ct).await? {
        (&alice, &alice_worker)
    } else {
        (&alice_worker, &alice)
    };
    assert!(
        !ctx.can_decrypt(sibling, &ct).await?,
        "only one instance was invited, so only one can read (seed {:#x})",
        ctx.seed()
    );

    let stuck = ctx.pending_events(sibling).await?;
    assert!(
        stuck > 0,
        "the sibling's key-agreement events should be waiting, not discarded"
    );
    assert_eq!(
        ctx.pending_events(invited).await?,
        0,
        "the invited instance has nothing waiting"
    );

    let drained = ctx.share_prekey_secrets(invited, sibling).await?;

    assert_eq!(
        drained, stuck,
        "importing the secrets drained exactly those"
    );
    assert_eq!(ctx.pending_events(sibling).await?, 0);
    assert!(
        ctx.can_decrypt(sibling, &ct).await?,
        "and now the sibling can read it"
    );
    Ok(())
}

#[tokio::test]
async fn prekey_secrets_do_not_cross_between_identities() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xa11ce).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;

    assert!(
        ctx.share_prekey_secrets(&alice, &bob).await.is_err(),
        "alice and bob are different people"
    );
    Ok(())
}
