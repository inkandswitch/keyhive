//! The well-known `Public` principal as a member.

use keyhive_core::{
    access::Access::{Admin, Edit, Read, Relay},
    principal::public::Public,
    test_utils::{content_ref, TestContext, TestResult as Result},
};
use std::collections::BTreeMap;

#[tokio::test]
async fn delegating_to_public_creates_a_public_delegation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let public = Public.id();

    for level in [Read, Edit, Admin] {
        let design_doc = ctx.doc(&alice, &format!("design_doc-{level:?}")).await?;

        assert_eq!(alice.access_for_doc(public, design_doc).await, None);
        alice.add_member(public, design_doc, level, &[]).await?;

        assert_eq!(alice.access_for_doc(public, design_doc).await, Some(level));
        assert_eq!(
            ctx.named(alice.reachable_members(design_doc).await)
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
        alice.access_for_doc(bob.id(), design_doc).await,
        None,
        "nobody delegated anything to bob"
    );
    assert_eq!(
        alice.best_access_for_doc(bob.id(), design_doc).await,
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
        alice.best_access_for_doc(bob.id(), design_doc).await,
        Some(Admin),
        "bob's own delegation is the better one"
    );
    assert_eq!(
        alice.best_access_for_doc(carol.id(), design_doc).await,
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

    ctx.sync(&alice, &bob).await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await,
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
    ctx.sync(&alice, &bob).await?;
    ctx.sync(&alice, &carol).await?;

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

    let pending = ctx.sync(&alice, &bob).await?;

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
        server.stats().await.pending_total(),
        0,
        "the server applied everything alice sent it"
    );
    assert!(
        !ctx.event_kinds_for(&server, &bob).await?.is_empty(),
        "the server has something to relay, so the assertions below are not on an empty delivery"
    );

    let pending = ctx.sync(&server, &bob).await?;

    assert_eq!(pending, 0, "bob could apply everything the server relayed");
    assert_eq!(
        bob.access_for_doc(bob.id(), design_doc).await,
        None,
        "asking about himself does not find the document"
    );
    ctx.sync(&alice, &bob).await?;
    assert_eq!(
        ctx.named(bob.docs_reachable_by_agent(bob.id()).await),
        BTreeMap::from([("notes".to_string(), Read)]),
        "the documents he reaches because of his personal access are notes and only \
        notes, so the public one is excluded rather than there being nothing to exclude it from"
    );
    assert_eq!(
        bob.access_for_doc(Public.id(), design_doc).await,
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

#[tokio::test]
async fn a_public_editor_writes_by_rotating_the_public_leaf() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let peer = ctx.individual("peer").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(Public.id(), design_doc, Edit, &[]).await?;
    ctx.sync_as_public(&alice, &peer).await?;

    let written = peer
        .try_encrypt_content(
            design_doc,
            &content_ref(b"from the public peer"),
            &vec![],
            b"from the public peer",
        )
        .await?;

    let rotated_leaf_is_public = matches!(
        written.update_op().as_ref().map(|op| op.payload()),
        Some(beekem::operation::CgkaOperation::Update { new_path, .. })
            if new_path.leaf_id == beekem::id::MemberId::public()
    );
    assert!(
        rotated_leaf_is_public,
        "the peer is not in the tree so the rotation uses the public identity's key"
    );

    ctx.sync(&peer, &alice).await?;
    assert_eq!(
        alice
            .try_decrypt_content(design_doc, written.encrypted_content())
            .await?,
        b"from the public peer".to_vec(),
        "alice received the rotation so she reads what the peer wrote"
    );
    Ok(())
}

#[tokio::test]
async fn the_public_leaf_keeps_its_well_known_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let peer = ctx.individual("peer").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(Public.id(), design_doc, Edit, &[]).await?;
    ctx.sync_as_public(&alice, &peer).await?;

    let written = peer
        .try_encrypt_content(design_doc, &content_ref(b"hello"), &vec![], b"hello")
        .await?;
    let beekem::operation::CgkaOperation::Update {
        id,
        new_path,
        predecessors,
        doc_id,
    } = written
        .update_op()
        .as_ref()
        .expect("a peer with no leaf of its own rotates the public one")
        .payload()
        .clone()
    else {
        panic!("expected an update")
    };

    // The same path, with the public leaf given a key only the sender holds.
    let other_key =
        keyhive_crypto::share_key::ShareSecretKey::generate(&mut rand::rngs::OsRng).share_key();
    let mut swapped = new_path.clone();
    swapped.leaf_pk = beekem::keys::NodeKey::ShareKey(other_key);
    swapped.removed_keys = vec![Public.share_key()];

    let result = alice
        .receive_cgka_op(
            peer.try_sign(beekem::operation::CgkaOperation::Update {
                id,
                new_path: swapped,
                predecessors,
                doc_id,
            })
            .await?,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(keyhive_core::keyhive::ReceiveCgkaOpError::UnauthorizedCgkaOp(_))
        ),
        "every other public peer reads that path with the well-known key; {result:?}"
    );
    Ok(())
}
