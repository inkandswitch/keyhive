//! A relay: a peer with `Relay` power that stores and forwards a document's
//! membership and key agreement without reading the document.
//!
//! It holds the certificates, prekeys and CGKA operations, so it answers who
//! may do what as a member would, and serves the key agreement to members who
//! sync only with it. It is never placed in the BeeKEM tree, so it holds no
//! key: the operations are signed, and their secrets are encrypted to the
//! tree's members.

use std::collections::HashSet;

use keyhive_core::{
    principal::document::id::DocumentId,
    test_utils::{EventKind, Instance, TestContext, TestResult as Result},
};
use keyline::power::Power::{Read, Relay};

/// The digests of the CGKA operations `who` holds for `doc`, if any.
async fn held_ops(who: &Instance, doc: DocumentId) -> Option<HashSet<String>> {
    Some(
        who.cgka_ops_for_doc(&doc)
            .await?
            .iter()
            .map(|op| op.digest().to_string())
            .collect(),
    )
}

#[tokio::test]
async fn a_relay_holds_and_serves_key_agreement_but_no_key() -> Result<()> {
    const ORDERS: u64 = 4;

    for through_a_group in [false, true] {
        for seed in 0..ORDERS {
            let case = format!("through a group: {through_a_group}, order {seed}");
            let mut ctx = TestContext::new().await;
            let alice = ctx.individual("alice").await?;
            let bob = ctx.individual("bob").await?;
            let relay = ctx.individual("relay").await?;
            let design_doc = ctx.doc(&alice, "design_doc").await?;
            alice.add_member(bob.id(), design_doc, Read).await?;
            if through_a_group {
                let relays = ctx.group(&alice, "relays").await?;
                alice.add_member(relays, design_doc, Relay).await?;
                alice.add_member(relay.id(), relays, Read).await?;
            } else {
                alice.add_member(relay.id(), design_doc, Relay).await?;
            }
            alice.force_pcs_update(design_doc).await?;
            let ct = ctx
                .encrypt(&alice, design_doc, b"not for the relay")
                .await?;

            let sent: HashSet<String> = alice
                .cgka_ops_reachable_by_agent(relay.id())
                .await?
                .iter()
                .map(|op| op.digest().to_string())
                .collect();
            assert_eq!(
                Some(&sent),
                held_ops(&alice, design_doc).await.as_ref(),
                "the relay is sent the document's key agreement ({case})"
            );

            assert_eq!(
                ctx.sync_shuffled(&alice, &relay, seed).await?,
                0,
                "and ingests all of it ({case})"
            );
            assert_eq!(relay.stats().await.pending_total(), 0, "({case})");
            assert_eq!(
                held_ops(&relay, design_doc).await,
                Some(sent),
                "it holds the operations it was sent ({case})"
            );
            assert_eq!(
                relay.reachable_members(design_doc).await?,
                alice.reachable_members(design_doc).await?,
                "it answers reachability as alice does ({case})"
            );

            assert!(
                !relay.has_document(design_doc).await,
                "it never joins the document's CGKA group ({case})"
            );
            assert!(
                !alice
                    .cgka_members_for(design_doc)
                    .await?
                    .expect("alice holds the document")
                    .contains(&relay.id()),
                "it is not in the BeeKEM tree ({case})"
            );
            ctx.give_content(&relay, &ct).await?;
            assert!(
                !matches!(relay.can_decrypt_content(design_doc, &ct).await, Ok(true)),
                "and cannot decrypt ({case})"
            );
        }
    }
    Ok(())
}

/// A reader who syncs only with a relay gets the key agreement from it, and
/// with it the document.
#[tokio::test]
async fn a_reader_takes_the_key_agreement_from_a_relay() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let relay = ctx.individual("relay").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
    alice.add_member(relay.id(), design_doc, Relay).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"for bob").await?;

    assert_eq!(ctx.sync(&alice, &relay).await?, 0);
    assert_eq!(ctx.sync(&relay, &bob).await?, 0);

    assert!(bob.has_document(design_doc).await);
    assert_eq!(
        held_ops(&bob, design_doc).await,
        held_ops(&alice, design_doc).await
    );
    let tree = bob
        .cgka_members_for(design_doc)
        .await?
        .expect("bob has joined the document's CGKA group");
    assert!(
        tree.contains(&alice.id()) && tree.contains(&bob.id()),
        "the readers are in the tree bob built from the relay's operations"
    );
    assert!(
        !tree.contains(&relay.id()),
        "and the relay that carried them is not"
    );
    ctx.give_content(&bob, &ct).await?;
    assert!(bob.can_decrypt_content(design_doc, &ct).await?);
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

/// The bulk form indexes relays: an owner sends a relay member the
/// document's operations, and the relay sends them on to the readers.
#[tokio::test]
async fn the_all_agents_index_includes_relays() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let relay = ctx.individual("relay").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
    alice.add_member(relay.id(), design_doc, Relay).await?;
    ctx.sync(&alice, &relay).await?;

    for (holder, recipient) in [(&alice, &relay), (&relay, &bob)] {
        let all = holder.cgka_ops_for_all_agents().await?;
        assert!(
            all.index
                .get(&recipient.id().into())
                .is_some_and(|docs| docs.contains(&design_doc.into())),
            "{} indexes {} for the document",
            holder.name(),
            recipient.name()
        );
    }
    Ok(())
}

/// A relay's archive keeps what it relays: restored, it answers as before,
/// still holds the key agreement, and still holds no key.
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
    let held = held_ops(&restored, design_doc).await;
    assert!(held.as_ref().is_some_and(|ops| !ops.is_empty()));
    assert_eq!(held, held_ops(&relay, design_doc).await);
    assert!(!restored.has_document(design_doc).await);
    assert_eq!(restored.stats().await.pending_total(), 0);
    Ok(())
}

/// A relay cut off from a document is sent none of its later key agreement.
#[tokio::test]
async fn a_revoked_relay_is_sent_no_new_key_agreement() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let relay = ctx.individual("relay").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(relay.id(), design_doc, Relay).await?;
    ctx.sync(&alice, &relay).await?;
    let before = held_ops(&relay, design_doc).await;
    assert!(before.is_some());

    alice.revoke_member(relay.id(), true, design_doc).await?;
    alice.force_pcs_update(design_doc).await?;
    assert!(alice
        .cgka_ops_reachable_by_agent(relay.id())
        .await?
        .is_empty());

    ctx.sync(&alice, &relay).await?;
    assert_eq!(held_ops(&relay, design_doc).await, before);
    assert_ne!(held_ops(&alice, design_doc).await, before);
    Ok(())
}
