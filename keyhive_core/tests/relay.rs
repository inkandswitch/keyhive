//! A relay: a peer that stores and forwards a document's events without
//! reading it.

use beekem::operation::CgkaOperation;
use keyhive_core::{
    principal::document::id::DocumentId,
    test_utils::{Instance, TestContext, TestResult as Result},
};
use keyhive_crypto::digest::Digest;
use keyline::power::Power::{Read, Relay};
use std::collections::BTreeSet;

/// The digests of every CGKA operation `who` holds for a document.
async fn held_ops(who: &Instance, doc: DocumentId) -> BTreeSet<Digest<CgkaOperation>> {
    who.cgka_ops_for_doc(&doc)
        .await
        .unwrap_or_default()
        .iter()
        .map(|op| op.digest())
        .collect()
}

#[tokio::test]
async fn a_relay_answers_and_serves_like_a_member_without_a_tree() -> Result<()> {
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
        let ct = ctx.encrypt(&alice, design_doc, b"for bob").await?;

        // The relay gets every event alice has for it, in an arbitrary order.
        ctx.sync_shuffled(&alice, &relay, seed).await?;

        assert_eq!(
            relay.reachable_members(design_doc).await?,
            alice.reachable_members(design_doc).await?,
            "the relay answers reachability as alice does (order {seed})"
        );
        assert_eq!(
            held_ops(&relay, design_doc).await,
            held_ops(&alice, design_doc).await,
            "and holds every key agreement operation she does (order {seed})"
        );
        assert!(
            relay.has_document(design_doc).await,
            "the relay knows the document (order {seed})"
        );
        let doc_on_relay = relay
            .get_document(design_doc)
            .await
            .ok_or("the relay has a handle for it")?;
        assert!(
            doc_on_relay.cgka_members().await.is_none(),
            "but holds no tree for it: it was never invited (order {seed})"
        );

        // Bob syncs only from the relay, and reads what alice wrote.
        ctx.sync(&relay, &bob).await?;
        ctx.give_content(&bob, &ct).await?;
        assert!(
            bob.can_decrypt_content(design_doc, &ct).await?,
            "what the relay served is enough for a member (order {seed})"
        );
    }
    Ok(())
}

/// A relay's archive keeps every operation it relays, though it holds no tree
/// for the document: restored, it still knows the document and serves them.
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

    assert!(restored.has_document(design_doc).await);
    assert_eq!(
        held_ops(&restored, design_doc).await,
        held_ops(&relay, design_doc).await,
        "every operation the relay held"
    );
    Ok(())
}
