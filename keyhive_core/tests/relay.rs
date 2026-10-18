//! A relay: a peer with `Relay` power that stores and forwards a document's
//! membership without reading the document.
//!
//! It holds the certificates and prekeys, so it answers who may do what as a
//! member would. It holds no key agreement: it is sent no CGKA operations and
//! has no tree. Members exchange those among themselves (or through a sync
//! layer that carries them opaquely).

use keyhive_core::test_utils::{EventKind, TestContext, TestResult as Result};
use keyline::power::Power::{Read, Relay};

#[tokio::test]
async fn a_relay_answers_for_membership_and_holds_no_key_agreement() -> Result<()> {
    const ORDERS: u64 = 4;

    for seed in 0..ORDERS {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let relay = ctx.individual("relay").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        alice.add_member(bob.id(), design_doc, Read).await?;
        alice.add_member(relay.id(), design_doc, Relay).await?;
        alice.force_pcs_update(design_doc).await?;

        assert!(
            alice
                .cgka_ops_reachable_by_agent(relay.id())
                .await?
                .is_empty(),
            "a relay is sent no key agreement (order {seed})"
        );

        // The relay gets every event alice has for it, in an arbitrary order.
        ctx.sync_shuffled(&alice, &relay, seed).await?;

        assert_eq!(
            relay.reachable_members(design_doc).await?,
            alice.reachable_members(design_doc).await?,
            "the relay answers reachability as alice does (order {seed})"
        );
        assert!(
            !relay.has_document(design_doc).await,
            "it holds no tree for the document (order {seed})"
        );
        assert!(relay.cgka_ops_for_doc(&design_doc).await.is_none());
        assert_eq!(
            relay.stats().await.pending_total(),
            0,
            "and nothing waits on it (order {seed})"
        );
    }
    Ok(())
}

/// Membership served by a relay is enough for a member to take the key
/// agreement from another member.
#[tokio::test]
async fn a_member_reads_with_membership_from_a_relay() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let relay = ctx.individual("relay").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
    alice.add_member(relay.id(), design_doc, Relay).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"for bob").await?;

    // Bob's certificates come from the relay; the key agreement from alice.
    ctx.sync(&alice, &relay).await?;
    ctx.sync(&relay, &bob).await?;
    ctx.sync_without(&alice, &bob, EventKind::Delegated).await?;
    ctx.give_content(&bob, &ct).await?;
    assert!(bob.can_decrypt_content(design_doc, &ct).await?);
    Ok(())
}

/// A relay's archive keeps the membership it relays: restored, it answers as
/// before, and still holds no key agreement.
#[tokio::test]
async fn a_relay_keeps_what_it_relays_across_an_archive() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let relay = ctx.individual("relay").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(relay.id(), design_doc, Relay).await?;
    alice.force_pcs_update(design_doc).await?;
    ctx.sync(&alice, &relay).await?;

    let archive = relay.into_archive().await?;
    let restored = ctx.rebuild_from_archive(&archive, "relay-restored").await?;

    assert_eq!(
        restored.reachable_members(design_doc).await?,
        relay.reachable_members(design_doc).await?
    );
    assert!(!restored.has_document(design_doc).await);
    assert_eq!(restored.stats().await.pending_total(), 0);
    Ok(())
}
