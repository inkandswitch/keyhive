//! Reading a chain of content by walking back through the ancestors each write lists.
//!
//! Content written this way carries, inside its own ciphertext, the keys to the content it
//! lists. That is how someone who can open one write can open earlier ones they were never
//! given a key for. Keyhive defines the envelope and walks it; building one is the
//! application's job, which `encrypt_in_envelope` stands in for.

mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::Read;
use std::collections::BTreeSet;

fn contents(of: &[&[u8]]) -> BTreeSet<Vec<u8>> {
    of.iter().map(|c| c.to_vec()).collect()
}

#[tokio::test]
async fn a_reader_walks_back_through_the_ancestors_it_holds() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    // genesis, then two writes with it as their predecessor, then one with both of those.
    let genesis = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"genesis")
        .await?;
    let left = ctx
        .encrypt_in_envelope(&alice, &design_doc, std::slice::from_ref(&genesis), b"left")
        .await?;
    let right = ctx
        .encrypt_in_envelope(
            &alice,
            &design_doc,
            std::slice::from_ref(&genesis),
            b"right",
        )
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[left.clone(), right.clone()], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    for ct in [&genesis, &left, &right, &head] {
        ctx.deliver_content(&bob, ct).await?;
    }
    let walked = ctx.causal_decrypt(&bob, &head).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[b"genesis", b"left", b"right"]),
        "the walk reaches the root by both paths"
    );
    assert_eq!(
        walked.recovered_count(),
        3,
        "and reads the shared ancestor once rather than once per path"
    );
    assert_eq!(walked.missing(), 0, "bob holds every ancestor");
    Ok(())
}

/// A later member reads earlier content by walking back from a write made after they
/// joined. This is the shape ARK uses to admit someone to a document that already has
/// history: rotate, then write something that lists what came before.
#[tokio::test]
async fn a_later_member_recovers_earlier_content_by_walking_back() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let history = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"written before bob")
        .await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;

    let entry_point = ctx
        .encrypt_in_envelope(
            &alice,
            &design_doc,
            std::slice::from_ref(&history),
            b"written after bob",
        )
        .await?;
    ctx.sync_all_unsent().await?;

    assert!(
        !ctx.can_decrypt(&bob, &history).await?,
        "bob cannot derive the key for content written before he joined"
    );
    assert!(
        ctx.can_decrypt(&bob, &entry_point).await?,
        "he can open the write that came after"
    );

    ctx.deliver_content(&bob, &history).await?;
    ctx.deliver_content(&bob, &entry_point).await?;
    let walked = ctx.causal_decrypt(&bob, &entry_point).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[b"written before bob"]),
        "and the write he can open carries the key to the one he cannot"
    );
    Ok(())
}

#[tokio::test]
async fn an_ancestor_that_is_not_held_is_reported_rather_than_failing() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let genesis = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"genesis")
        .await?;
    let middle = ctx
        .encrypt_in_envelope(
            &alice,
            &design_doc,
            std::slice::from_ref(&genesis),
            b"middle",
        )
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, std::slice::from_ref(&middle), b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // Everything except the root of the chain.
    ctx.deliver_content(&bob, &head).await?;
    ctx.deliver_content(&bob, &middle).await?;
    let walked = ctx.causal_decrypt(&bob, &head).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[b"middle"]),
        "the walk gets as far as it can"
    );
    assert_eq!(
        walked.missing(),
        1,
        "and says something is outstanding rather than failing"
    );
    let key = walked
        .key_for_missing(&genesis)
        .ok_or("the walk did not say which content is outstanding")?;
    assert!(
        ctx.decrypt_with_key(&genesis, &key).is_ok(),
        "and the key it reported for it is the one that opens it, so fetching is enough"
    );

    Ok(())
}

/// `Document::try_causal_decrypt_content` collects the entrypoint's missing ancestors into
/// a local `CausalDecryptionState` and then returns the store walk's own state instead,
/// dropping what it collected. So a reader passed a write before the content it points at
/// is told there is nothing outstanding when what it needs is exactly that list and the
/// keys in it.
#[tokio::test]
#[ignore = "an ancestor the entrypoint lists is dropped from the report when it is missing. Fix this"]
async fn an_ancestor_the_entrypoint_lists_is_reported_when_missing() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let history = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"history")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, std::slice::from_ref(&history), b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // The entrypoint.
    ctx.deliver_content(&bob, &head).await?;
    let walked = ctx.causal_decrypt(&bob, &head).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[]),
        "there is nothing to walk"
    );
    assert_eq!(
        walked.missing(),
        1,
        "but bob needs to be told which content to go and fetch"
    );
    assert!(
        walked.key_for_missing(&history).is_some(),
        "with the key to open it once he has it"
    );
    Ok(())
}

/// `CiphertextStore` must stop serving content once it has been decrypted, whether by
/// removing it or by tracking what has been read.
///
/// The consumed content is not reported as outstanding either because the entrypoint lists
/// it directly. That's handled by `an_ancestor_the_entrypoint_lists_is_reported_when_missing`.
#[tokio::test]
async fn a_walk_consumes_the_content_it_reads() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let genesis = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"genesis")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, std::slice::from_ref(&genesis), b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    ctx.deliver_content(&bob, &genesis).await?;
    ctx.deliver_content(&bob, &head).await?;

    let first = ctx.causal_decrypt(&bob, &head).await?;
    assert_eq!(first.recovered(), contents(&[b"genesis"]));

    let second = ctx.causal_decrypt(&bob, &head).await?;
    assert_eq!(
        second.recovered(),
        contents(&[]),
        "the first walk took it out of the store"
    );

    ctx.deliver_content(&bob, &genesis).await?;
    let third = ctx.causal_decrypt(&bob, &head).await?;
    assert_eq!(
        third.recovered(),
        contents(&[b"genesis"]),
        "delivering it again is enough to read it again"
    );
    Ok(())
}
