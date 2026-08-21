mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Read};

#[tokio::test]
async fn two_instances_of_one_identity_are_one_member() -> Result<()> {
    let mut ctx = TestContext::new().await;
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
    let mut ctx = TestContext::new().await;
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
    let mut ctx = TestContext::new().await;
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
    let alice_can = ctx.can_decrypt(&alice, &ct).await?;
    let worker_can = ctx.can_decrypt(&alice_worker, &ct).await?;
    assert!(
        alice_can ^ worker_can,
        "only one instance was invited, so only one can read"
    );
    let (invited, sibling) = if alice_can {
        (&alice, &alice_worker)
    } else {
        (&alice_worker, &alice)
    };

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
async fn two_instances_creating_documents_independently_converge() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;
    let reader = ctx.individual("reader").await?;

    // Each instance holds the other's prekey secrets, like two clients sharing storage.
    ctx.share_prekey_secrets(&alice, &alice_worker).await?;
    ctx.share_prekey_secrets(&alice_worker, &alice).await?;

    // Neither instance knows about the other's document when it makes it.
    let from_alice = ctx.doc(&alice, "notes").await?;
    ctx.delegate(&alice, &ctx.public(), &from_alice, Read)
        .await?;
    ctx.force_pcs_update(&alice, &from_alice).await?;

    let from_worker = ctx.doc(&alice_worker, "design_doc").await?;
    ctx.delegate(&alice_worker, &ctx.public(), &from_worker, Read)
        .await?;
    ctx.force_pcs_update(&alice_worker, &from_worker).await?;

    ctx.sync(&alice, &alice_worker).await?;
    ctx.sync(&alice_worker, &alice).await?;

    assert!(
        ctx.has_received(&alice, &from_worker).await?,
        "alice learned about the document the worker made"
    );
    assert!(
        ctx.has_received(&alice_worker, &from_alice).await?,
        "and the worker about alice's"
    );
    assert_eq!(ctx.pending_events(&alice).await?, 0);
    assert_eq!(
        ctx.pending_events(&alice_worker).await?,
        0,
        "neither instance was left holding an event it could not place"
    );

    let alice_wrote = ctx.encrypt(&alice, &from_alice, b"from alice").await?;
    let worker_wrote = ctx
        .encrypt(&alice_worker, &from_worker, b"from the worker")
        .await?;

    ctx.sync_as_public(&alice, &reader).await?;
    ctx.sync_as_public(&alice_worker, &reader).await?;

    assert_eq!(
        ctx.read(&reader, &alice_wrote).await?,
        b"from alice".to_vec()
    );
    assert_eq!(
        ctx.read(&reader, &worker_wrote).await?,
        b"from the worker".to_vec(),
        "one reader, two instances, both documents"
    );
    assert_eq!(
        ctx.pending_events(&reader).await?,
        0,
        "and nothing it was sent is stuck"
    );
    Ok(())
}

#[tokio::test]
async fn a_revocation_and_a_redelegation_reach_the_other_instance() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;
    let reader = ctx.individual("reader").await?;
    ctx.share_prekey_secrets(&alice, &alice_worker).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;

    // When revoking and re-delegating, the second delegation cannot be applied until the
    // revocation has been.
    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    ctx.revoke(&alice, &ctx.public(), &design_doc).await?;
    ctx.delegate(&alice, &ctx.public(), &design_doc, Read)
        .await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;

    ctx.sync(&alice, &alice_worker).await?;
    assert_eq!(
        ctx.pending_events(&alice_worker).await?,
        0,
        "the worker applied the revocation and the delegation that followed it"
    );
    assert_eq!(
        ctx.effective_access_seen_by(&alice_worker, &ctx.public(), &design_doc)
            .await?,
        Some(Read),
        "and ended on the re-delegation rather than the revocation"
    );

    let worker_wrote = ctx
        .encrypt(&alice_worker, &design_doc, b"after the re-delegation")
        .await?;
    ctx.sync_as_public(&alice, &reader).await?;
    ctx.sync_as_public(&alice_worker, &reader).await?;

    assert_eq!(
        ctx.read(&reader, &worker_wrote).await?,
        b"after the re-delegation".to_vec(),
        "the document is public again, so the reader reads what the worker wrote"
    );
    assert_eq!(
        ctx.pending_events(&reader).await?,
        0,
        "and nothing it was sent is stuck"
    );
    Ok(())
}

#[tokio::test]
async fn a_peer_cannot_read_an_instance_it_has_not_heard_from() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.second_instance(&alice, "alice-worker").await?;
    let bob = ctx.individual("bob").await?;
    ctx.share_prekey_secrets(&alice, &alice_worker).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync(&alice, &alice_worker).await?;

    let worker_wrote = ctx
        .encrypt(&alice_worker, &design_doc, b"written on the worker")
        .await?;

    // Everything alice has, which is everything except the worker's write.
    ctx.sync(&alice, &bob).await?;
    assert!(
        ctx.has_received(&bob, &design_doc).await?,
        "bob has the document itself"
    );
    assert!(
        !ctx.can_decrypt(&bob, &worker_wrote).await?,
        "but not the key agreement the worker's write went under"
    );

    ctx.sync(&alice_worker, &bob).await?;
    assert_eq!(
        ctx.read(&bob, &worker_wrote).await?,
        b"written on the worker".to_vec(),
        "the second round completes it"
    );
    assert_eq!(
        ctx.pending_events(&bob).await?,
        0,
        "with nothing left over from the first round"
    );
    Ok(())
}

#[tokio::test]
async fn prekey_secrets_do_not_cross_between_identities() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;

    assert!(
        ctx.share_prekey_secrets(&alice, &bob).await.is_err(),
        "alice and bob are different people"
    );
    Ok(())
}
