mod facade;

use facade::{Result, TestContext, TestEventKind};
use keyhive_core::access::Access::{self, Edit, Read};

// Sanity check for seeding tests
#[tokio::test]
async fn the_same_seed_produces_the_same_certificates() -> Result<()> {
    async fn build(seed: u64) -> Result<String> {
        let mut ctx = TestContext::with_seed(seed).await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        let cert = ctx.delegate(&alice, &bob, &design_doc, Read).await?;
        Ok(format!("{cert:?}"))
    }

    assert_eq!(build(1234).await?, build(1234).await?, "seed 1234 twice");
    assert_ne!(build(1234).await?, build(5678).await?, "different seeds");
    Ok(())
}

/// Sanity check for replaying tests with seed.
#[tokio::test]
async fn an_unseeded_context_still_reports_its_seed() -> Result<()> {
    let a = TestContext::new().await;
    let b = TestContext::new().await;
    assert_ne!(
        a.seed(),
        b.seed(),
        "new() must not be a fixed seed, or every test shares one identity"
    );

    let replay = TestContext::with_seed(a.seed()).await;
    assert_eq!(replay.seed(), a.seed());
    Ok(())
}

#[tokio::test]
async fn delivery_order_does_not_change_the_authority_graph() -> Result<()> {
    const SEED: u64 = 0xd00d;

    /// Builds the same context every time, delivers it to dave in the order `order` gives,
    /// and reports what dave then believes about everyone.
    async fn graph_seen_by_dave(order: u64) -> Result<Vec<(String, Option<Access>)>> {
        let mut ctx = TestContext::with_seed(SEED).await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let carol = ctx.individual("carol").await?;
        let dave = ctx.individual("dave").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        let engineering = ctx.group(&alice, "engineering").await?;

        ctx.delegate(&alice, &engineering, &design_doc, Edit)
            .await?;
        ctx.delegate(&alice, &carol, &engineering, Read).await?;
        ctx.delegate(&alice, &bob, &design_doc, Edit).await?;
        ctx.delegate(&alice, &dave, &design_doc, Read).await?;
        ctx.revoke(&alice, &bob, &design_doc).await?;

        let pending = ctx.sync_shuffled(&alice, &dave, order).await?;
        assert_eq!(pending, 0, "order {order} left events unapplied");

        let mut out = vec![];
        for who in [&bob, &carol, &dave] {
            out.push((
                who.name().to_string(),
                ctx.effective_access_seen_by(&dave, who, &design_doc)
                    .await?,
            ));
        }
        Ok(out)
    }

    let first = graph_seen_by_dave(0).await?;
    for order in 1..8u64 {
        assert_eq!(
            graph_seen_by_dave(order).await?,
            first,
            "delivery order {order} produced a different graph (seed {SEED:#x})"
        );
    }
    Ok(())
}

/// Dave holds Read on the document directly. He receives all five `Delegated` events that
/// describe the group, including the one admitting Bob. He is not sent the `Revoked` event
/// that cancels it. Nothing is left pending, no error is raised, and further syncing does
/// not change it. Dave believes Bob is still a member, while Alice and Bob agree he is not.
///
/// The same revocation issued directly on the document
/// is sent to Dave and does converge, so this is specific to a revocation one level up the
/// membership chain.
#[tokio::test]
#[ignore = "fails on main and on jtfm/cgka-authority: a group revocation is not sent to a peer of the parent document"]
async fn a_revocation_inside_a_group_reaches_a_peer_of_the_parent() -> Result<()> {
    let mut ctx = TestContext::with_seed(0x5EED).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let dave = ctx.individual("dave").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    ctx.delegate(&alice, &engineering, &design_doc, Edit)
        .await?;
    ctx.delegate(&alice, &bob, &engineering, Read).await?;
    ctx.delegate(&alice, &dave, &design_doc, Read).await?;
    ctx.revoke(&alice, &bob, &engineering).await?;
    ctx.sync_all().await?;

    assert_eq!(
        ctx.effective_access(&bob, &design_doc).await?,
        None,
        "alice, who issued the revocation, has it right"
    );
    assert_eq!(
        ctx.effective_access_seen_by(&bob, &bob, &design_doc)
            .await?,
        None,
        "and so does bob, who was sent it"
    );
    assert_eq!(
        ctx.effective_access_seen_by(&dave, &bob, &design_doc)
            .await?,
        None,
        "dave must agree: he holds every delegation that built this graph"
    );
    Ok(())
}

#[tokio::test]
async fn partial_delivery_leaves_events_pending_and_they_apply_later() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xbeef).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    ctx.delegate(&alice, &engineering, &design_doc, Edit)
        .await?;
    ctx.delegate(&alice, &bob, &engineering, Edit).await?;

    // One event at a time.
    let pending_at_the_end = ctx.sync_in_batches(&alice, &bob, 1).await?;

    assert_eq!(
        pending_at_the_end, 0,
        "every event should have found its place by the last batch"
    );
    assert_eq!(ctx.pending_events(&bob).await?, 0);
    assert_eq!(
        ctx.effective_access_seen_by(&bob, &bob, &design_doc)
            .await?,
        Some(Edit),
        "bob converged on the same answer alice has"
    );
    Ok(())
}

#[tokio::test]
async fn withholding_key_agreement_leaves_a_member_who_cannot_read() -> Result<()> {
    let mut ctx = TestContext::with_seed(0xcafe).await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"needs a key").await?;

    ctx.sync_without(&alice, &bob, TestEventKind::CgkaOperation)
        .await?;

    assert_eq!(
        ctx.effective_access_seen_by(&bob, &bob, &design_doc)
            .await?,
        Some(Read),
        "the graph says bob is a reader"
    );
    assert!(
        !ctx.can_decrypt(&bob, &ct).await?,
        "but he was never given the key material"
    );

    // Now send the rest.
    ctx.sync(&alice, &bob).await?;
    assert!(
        ctx.can_decrypt(&bob, &ct).await?,
        "the key material allows him to decrypt"
    );
    Ok(())
}
