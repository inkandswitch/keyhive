use keyhive_core::{
    access::Access::{Admin, Read},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::public::Public,
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::{EventKind, Hive, TestContext, TestError, TestResult as Result},
};
use keyhive_crypto::signer::memory::MemorySigner;
use rand::rngs::OsRng;

#[tokio::test]
async fn two_instances_of_one_identity_are_one_member() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let bob = ctx.individual("bob").await?;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;
    let design_doc = ctx.doc(&bob, "design_doc").await?;

    bob.add_member(alice.id(), design_doc, Read, &[]).await?;

    let raw = bob.reachable_members(design_doc).await?;
    assert_eq!(
        raw.len(),
        2,
        "bob and alice, and no third entry for alice's second instance"
    );

    let members = ctx.named_access(raw);
    assert_eq!(members.get("alice"), Some(&Read));
    assert_eq!(
        bob.access_for_doc(alice_worker.id(), design_doc).await?,
        Some(Read),
        "a delegation to one instance is a delegation to the identity"
    );
    Ok(())
}

#[tokio::test]
async fn either_instance_signs_as_the_identity() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.sync_all_unsent().await?;

    alice_worker
        .add_member(carol.id(), design_doc, Admin, &[])
        .await?;

    assert_eq!(
        alice_worker.access_for_doc(carol.id(), design_doc).await?,
        Some(Admin)
    );

    // Instances are separate replicas, so the first one learns of the delegation by sync like
    // anyone else.
    assert_eq!(
        alice.access_for_doc(carol.id(), design_doc).await?,
        None,
        "the first instance doesn't know about the delegation yet"
    );
    ctx.sync_all_unsent().await?;
    assert_eq!(
        alice.access_for_doc(carol.id(), design_doc).await?,
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
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;
    let design_doc = ctx.doc(&bob, "design_doc").await?;

    bob.add_member(alice.id(), design_doc, Read, &[]).await?;
    let ct = ctx.encrypt(&bob, design_doc, b"invitation content").await?;
    ctx.sync_all_unsent().await?;

    // Both instances know the document and both are members.
    assert!(alice_worker.has_received(design_doc).await);
    assert_eq!(
        bob.access_for_doc(alice_worker.id(), design_doc).await?,
        Some(Read)
    );

    // Exactly one of them holds the secret key.
    let alice_can = alice.can_decrypt_content(design_doc, &ct).await?;
    let worker_can = alice_worker.can_decrypt_content(design_doc, &ct).await?;
    assert!(
        alice_can ^ worker_can,
        "only one instance was invited, so only one can read"
    );
    let (invited, sibling) = if alice_can {
        (&alice, &alice_worker)
    } else {
        (&alice_worker, &alice)
    };

    let stuck = sibling.stats().await.pending_total();
    assert!(
        stuck > 0,
        "the sibling's key-agreement events should be waiting, not discarded"
    );
    assert_eq!(
        ctx.pending_events_of_kind(sibling, EventKind::CgkaOperation)
            .await,
        stuck,
        "everything waiting on the sibling is key agreement, not something else"
    );
    assert_eq!(
        invited.stats().await.pending_total(),
        0,
        "the invited instance has nothing waiting"
    );

    let drained = ctx.share_prekey_secrets(invited, sibling).await?;

    assert_eq!(
        drained, stuck,
        "importing the secrets drained exactly those"
    );
    assert_eq!(sibling.stats().await.pending_total(), 0);
    assert!(
        sibling.can_decrypt_content(design_doc, &ct).await?,
        "and now the sibling can read it"
    );
    Ok(())
}

#[tokio::test]
async fn two_instances_creating_documents_independently_converge() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;
    let reader = ctx.individual("reader").await?;

    // Each instance holds the other's prekey secrets, like two clients sharing storage.
    ctx.share_prekey_secrets(&alice, &alice_worker).await?;
    ctx.share_prekey_secrets(&alice_worker, &alice).await?;

    // Neither instance knows about the other's document when it makes it.
    let from_alice = ctx.doc(&alice, "notes").await?;
    alice.add_member(Public.id(), from_alice, Read, &[]).await?;
    alice.force_pcs_update(from_alice).await?;

    let from_worker = ctx.doc(&alice_worker, "design_doc").await?;
    alice_worker
        .add_member(Public.id(), from_worker, Read, &[])
        .await?;
    alice_worker.force_pcs_update(from_worker).await?;

    ctx.sync(&alice, &alice_worker).await?;
    ctx.sync(&alice_worker, &alice).await?;

    assert!(
        alice.has_received(from_worker).await,
        "alice learned about the document the worker made"
    );
    assert!(
        alice_worker.has_received(from_alice).await,
        "and the worker about alice's"
    );
    assert_eq!(alice.stats().await.pending_total(), 0);
    assert_eq!(
        alice_worker.stats().await.pending_total(),
        0,
        "neither instance was left holding an event it could not place"
    );

    let alice_wrote = ctx.encrypt(&alice, from_alice, b"from alice").await?;
    let worker_wrote = ctx
        .encrypt(&alice_worker, from_worker, b"from the worker")
        .await?;

    ctx.sync_as_public(&alice, &reader).await?;
    ctx.sync_as_public(&alice_worker, &reader).await?;

    assert_eq!(
        reader.try_decrypt_content(from_alice, &alice_wrote).await?,
        b"from alice".to_vec()
    );
    assert_eq!(
        reader
            .try_decrypt_content(from_worker, &worker_wrote)
            .await?,
        b"from the worker".to_vec(),
        "one reader, two instances, both documents"
    );
    assert_eq!(
        reader.stats().await.pending_total(),
        0,
        "and nothing it was sent is stuck"
    );
    Ok(())
}

#[tokio::test]
async fn a_revocation_and_a_redelegation_reach_the_other_instance() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;
    let reader = ctx.individual("reader").await?;
    ctx.share_prekey_secrets(&alice, &alice_worker).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;

    // When revoking and re-delegating, the second delegation cannot be applied until the
    // revocation has been.
    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    alice.revoke_member(Public.id(), true, design_doc).await?;
    alice.add_member(Public.id(), design_doc, Read, &[]).await?;
    alice.force_pcs_update(design_doc).await?;

    ctx.sync(&alice, &alice_worker).await?;
    assert_eq!(
        alice_worker.stats().await.pending_total(),
        0,
        "the worker applied the revocation and the delegation that followed it"
    );
    assert_eq!(
        alice_worker.access_for_doc(Public.id(), design_doc).await?,
        Some(Read),
        "and ended on the re-delegation rather than the revocation"
    );

    let worker_wrote = ctx
        .encrypt(&alice_worker, design_doc, b"after the re-delegation")
        .await?;
    ctx.sync_as_public(&alice, &reader).await?;
    ctx.sync_as_public(&alice_worker, &reader).await?;

    assert_eq!(
        reader
            .try_decrypt_content(design_doc, &worker_wrote)
            .await?,
        b"after the re-delegation".to_vec(),
        "the document is public again, so the reader reads what the worker wrote"
    );
    assert_eq!(
        reader.stats().await.pending_total(),
        0,
        "and nothing it was sent is stuck"
    );
    Ok(())
}

#[tokio::test]
async fn a_peer_cannot_read_an_instance_it_has_not_heard_from() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let alice_worker = ctx.new_keyhive_instance_for(&alice, "alice-worker").await?;
    let bob = ctx.individual("bob").await?;
    ctx.share_prekey_secrets(&alice, &alice_worker).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.sync(&alice, &alice_worker).await?;

    let worker_wrote = ctx
        .encrypt(&alice_worker, design_doc, b"written on the worker")
        .await?;

    // Everything alice has, which is everything except the worker's write.
    ctx.sync(&alice, &bob).await?;
    assert!(
        bob.has_received(design_doc).await,
        "bob has the document itself"
    );
    assert!(
        !bob.can_decrypt_content(design_doc, &worker_wrote).await?,
        "but not the key agreement the worker's write went under"
    );

    ctx.sync(&alice_worker, &bob).await?;
    assert_eq!(
        bob.try_decrypt_content(design_doc, &worker_wrote).await?,
        b"written on the worker".to_vec(),
        "the second round completes it"
    );
    assert_eq!(
        bob.stats().await.pending_total(),
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

    match ctx.share_prekey_secrets(&alice, &bob).await {
        Err(TestError::DifferentIdentity { from, to }) => {
            assert_eq!(from, "alice");
            assert_eq!(to, "bob");
        }
        other => panic!("prekey secrets are not transferable between identities, got {other:?}"),
    }
    Ok(())
}

// This is a sanity check for the test harness.
#[tokio::test]
async fn a_keyhive_built_outside_the_context_can_join_the_cast() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    // Built with the library's own constructors rather than by the context, which is the
    // point: a test that needs an instance the context would not produce is not stuck.
    let mut csprng = OsRng;
    let signer = MemorySigner::generate(&mut csprng);
    let built: Hive =
        Keyhive::generate(signer, MemoryCiphertextStore::new(), NoListener, csprng).await?;
    let outsider = ctx.adopt(built, "outsider").await?;

    alice
        .add_member(outsider.id(), design_doc, Read, &[])
        .await?;
    let ct = ctx.encrypt(&alice, design_doc, b"for the outsider").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        alice.access_for_doc(outsider.id(), design_doc).await?,
        Some(Read),
        "alice treats it as a member"
    );
    assert_eq!(
        outsider.try_decrypt_content(design_doc, &ct).await?,
        b"for the outsider".to_vec(),
        "and it reads what it was given, so it is fully in the sync arrangement"
    );
    assert_eq!(
        ctx.named_access(alice.reachable_members(design_doc).await?)
            .get("outsider"),
        Some(&Read),
        "and it is named in assertions like anyone else"
    );
    Ok(())
}

/// A second instance claims a name like anything else. It is not in the identifier-to-name
/// map, which holds one entry per identity, so it has to be checked against separately.
#[tokio::test]
async fn a_second_instance_takes_its_name_too() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    ctx.new_keyhive_instance_for(&alice, "alice_phone").await?;

    for taken in ["alice", "alice_phone"] {
        match ctx.doc(&alice, taken).await {
            Err(TestError::NameTaken { name }) => assert_eq!(name, taken),
            other => panic!("{taken:?} is taken, got {other:?}"),
        }
    }
    Ok(())
}
