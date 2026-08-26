use keyhive_core::{
    access::Access::{self, Edit, Read},
    test_utils::{EventKind, TestContext, TestResult as Result},
};

#[tokio::test]
async fn delivery_order_does_not_change_the_authority_graph() -> Result<()> {
    const ORDERS: u64 = 8;

    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;

    // One observer per delivery order, in one context, so they differ in the order they
    // were handed the same events and in nothing else.
    let mut observers = vec![];
    for i in 0..ORDERS {
        observers.push(ctx.individual(&format!("observer-{i}")).await?);
    }

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(carol.id(), engineering, Read, &[]).await?;
    alice.add_member(bob.id(), design_doc, Edit, &[]).await?;
    for observer in &observers {
        alice
            .add_member(observer.id(), design_doc, Read, &[])
            .await?;
    }
    alice.revoke_member(bob.id(), true, design_doc).await?;

    let mut answers: Vec<Vec<(String, Option<Access>)>> = vec![];
    for (order, observer) in observers.iter().enumerate() {
        let pending = ctx.sync_shuffled(&alice, observer, order as u64).await?;
        assert_eq!(pending, 0, "order {order} left events unapplied");

        let mut believes = vec![];
        for who in [&bob, &carol] {
            believes.push((
                who.name().to_string(),
                observer.access_for_doc(who, design_doc).await?,
            ));
        }
        answers.push(believes);
    }

    for (order, believes) in answers.iter().enumerate().skip(1) {
        assert_eq!(
            believes, &answers[0],
            "delivery order {order} produced a different graph"
        );
    }
    Ok(())
}

/// A revocation issued inside a group has to reach a peer who holds the parent document
/// directly, not only the members of the group it was issued in.
///
/// The same revocation issued on the document itself does reach Dave, so the gap is
/// specific to a revocation one level up the membership chain.
#[tokio::test]
#[ignore = "a revocation inside a group is not sent to a peer of the parent document"]
async fn a_revocation_inside_a_group_reaches_a_peer_of_the_parent() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let dave = ctx.individual("dave").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    alice.add_member(dave.id(), design_doc, Read, &[]).await?;
    alice.revoke_member(bob.id(), true, engineering).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        None,
        "alice, who issued the revocation, has it right"
    );
    assert_eq!(
        bob.access_for_doc(bob.id(), design_doc).await?,
        None,
        "and so does bob, who was sent it"
    );
    assert_eq!(
        dave.access_for_doc(bob.id(), design_doc).await?,
        None,
        "dave must agree: he holds every delegation that built this graph"
    );
    Ok(())
}

#[tokio::test]
async fn partial_delivery_leaves_events_pending_and_they_apply_later() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Edit, &[]).await?;

    // One event at a time.
    let pending_at_the_end = ctx.sync_in_batches(&alice, &bob, 1).await?;

    assert_eq!(
        pending_at_the_end, 0,
        "every event should have found its place by the last batch"
    );
    assert_eq!(ctx.pending_event_count(&bob).await, 0);
    assert_eq!(
        bob.access_for_doc(bob.id(), design_doc).await?,
        Some(Edit),
        "bob converged on the same answer alice has"
    );
    Ok(())
}

// This is a sanity check for the test harness.
#[tokio::test]
async fn the_resending_sync_methods_really_resend() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;

    let entitled = ctx.event_kinds_for(&alice, &bob).await?.len();
    assert!(entitled > 0, "bob is entitled to something to begin with");

    ctx.sync(&alice, &bob).await?;
    assert_eq!(
        ctx.events_last_delivered(),
        entitled,
        "sync sends everything bob is entitled to, not what he has yet to see"
    );

    ctx.sync_shuffled(&alice, &bob, 0).await?;
    assert_eq!(
        ctx.events_last_delivered(),
        entitled,
        "and so does sync_shuffled, which is what the redelivery tests call"
    );
    Ok(())
}

#[tokio::test]
async fn a_backlog_that_cannot_apply_does_not_block_new_events() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let server = ctx.individual("server").await?;
    let stranger = ctx.individual("stranger").await?;
    let alice = ctx.individual("alice").await?;

    // The server is a member of the stranger's document and is sent its key agreement
    // without the delegations that would let it place them. Nothing later supplies those.
    let stranger_doc = ctx.doc(&stranger, "stranger_doc").await?;
    stranger
        .add_member(server.id(), stranger_doc, Read, &[])
        .await?;
    let friend = ctx.individual("friend").await?;
    stranger
        .add_member(friend.id(), stranger_doc, Read, &[])
        .await?;
    // Rotations rather than more members, so the backlog grows without adding identities
    // that alice would also have to tell the server about.
    for _ in 0..4 {
        ctx.force_pcs_update(&stranger, stranger_doc).await?;
    }
    ctx.sync_without(&stranger, &server, EventKind::Delegated)
        .await?;

    let backlog = ctx.pending_event_count(&server).await;
    assert!(backlog > 0, "the server is holding events it cannot apply");

    // Unrelated and entirely valid: alice's own document, which the server may have in full.
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(server.id(), design_doc, Read, &[]).await?;
    ctx.force_pcs_update(&alice, design_doc).await?;
    let ct = ctx
        .encrypt(&alice, design_doc, b"written despite the backlog")
        .await?;

    let fresh = ctx.event_kinds_for(&alice, &server).await?.len();
    assert!(
        fresh > 0,
        "alice has events for the server, so the assertions below are not on an empty delivery"
    );

    ctx.sync(&alice, &server).await?;

    assert_eq!(
        ctx.pending_event_count(&server).await,
        backlog,
        "alice's events applied, and none of them joined the backlog"
    );
    assert_eq!(
        server.try_decrypt_content(design_doc, &ct).await?,
        b"written despite the backlog".to_vec(),
        "and the server can use what it was sent"
    );
    Ok(())
}

#[tokio::test]
async fn redelivering_known_events_changes_nothing() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"written once").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(ctx.pending_event_count(&bob).await, 0);
    assert!(bob.can_decrypt_content(design_doc, &ct).await?);

    // Bob has all of this already. The point of the test is that it is sent to him
    // anyway.
    let to_resend = ctx.event_kinds_for(&alice, &bob).await?;
    assert!(!to_resend.is_empty(), "there is nothing to redeliver");
    assert!(
        to_resend.contains(&EventKind::Delegated),
        "including the delegations that put bob in the group"
    );

    let pending = ctx.sync_shuffled(&alice, &bob, 0).await?;

    assert_eq!(
        pending, 0,
        "an event bob already held would not apply again"
    );
    assert_eq!(ctx.pending_event_count(&bob).await, 0);
    assert_eq!(
        bob.access_for_doc(bob.id(), design_doc).await?,
        Some(Read),
        "the second delivery changed what bob believes"
    );
    assert!(
        bob.can_decrypt_content(design_doc, &ct).await?,
        "the second delivery caused bob to lose the ability to decrypt"
    );
    Ok(())
}

#[tokio::test]
async fn withholding_key_agreement_leaves_a_member_who_cannot_read() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"needs a key").await?;

    ctx.sync_without(&alice, &bob, EventKind::CgkaOperation)
        .await?;

    assert_eq!(
        bob.access_for_doc(bob.id(), design_doc).await?,
        Some(Read),
        "the graph says bob is a reader"
    );
    assert!(
        !bob.can_decrypt_content(design_doc, &ct).await?,
        "but he was never given the key material"
    );

    // Now send the rest.
    ctx.sync(&alice, &bob).await?;
    assert!(
        bob.can_decrypt_content(design_doc, &ct).await?,
        "the key material allows him to decrypt"
    );
    Ok(())
}
