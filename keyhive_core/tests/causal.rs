//! Reading a chain of content by walking back through the ancestors each write lists.
//!
//! Content written this way carries, inside its own ciphertext, the keys to the content it
//! lists. That is how someone who can open one write can open earlier ones they were never
//! given a key for. Keyhive defines the envelope and walks it. Building one is the
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
        .encrypt_in_envelope(&alice, &design_doc, &[&genesis], b"left")
        .await?;
    let right = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&genesis], b"right")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&left, &right], b"head")
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
        .encrypt_in_envelope(&alice, &design_doc, &[&history], b"written after bob")
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
        .encrypt_in_envelope(&alice, &design_doc, &[&genesis], b"middle")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&middle], b"head")
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

/// Walking from two heads reads their shared ancestor once, not once per head.
#[tokio::test]
async fn a_walk_from_two_heads_reads_their_shared_ancestor_once() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    // One root, two heads over it, and a third head on no path from either.
    let root = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"root")
        .await?;
    let left_head = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&root], b"left head")
        .await?;
    let right_head = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&root], b"right head")
        .await?;
    let unrelated = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"unrelated")
        .await?;
    ctx.sync_all_unsent().await?;

    for held in [&root, &left_head, &right_head, &unrelated] {
        ctx.deliver_content(&bob, held).await?;
    }
    let walked = ctx
        .causal_decrypt_from(&bob, &[&left_head, &right_head])
        .await?;

    assert_eq!(
        walked.recovered(),
        contents(&[b"left head", b"right head", b"root"]),
        "both heads and their shared ancestor, and not the unrelated head"
    );
    assert_eq!(
        walked.recovered_count(),
        3,
        "the shared ancestor is read once, not once per head"
    );
    assert_eq!(walked.missing(), 0, "bob holds everything the walk reaches");

    let key = walked
        .key_for_recovered(&root)
        .ok_or("the walk did not report the key it read the root under")?;
    assert!(
        ctx.decrypt_with_key(&root, &key).is_ok(),
        "and that key is the one that opens it"
    );
    assert!(
        walked.key_for_recovered(&unrelated).is_none(),
        "no key is reported for content the walk never reached"
    );

    Ok(())
}

#[tokio::test]
async fn content_that_is_not_an_ancestor_is_not_captured_in_the_walk() -> Result<()> {
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
        .encrypt_in_envelope(&alice, &design_doc, &[&genesis], b"head")
        .await?;
    // Held by bob, in the same document, and on no path from the head.
    let unrelated = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"unrelated")
        .await?;
    ctx.sync_all_unsent().await?;

    for held in [&head, &genesis, &unrelated] {
        ctx.deliver_content(&bob, held).await?;
    }
    let walked = ctx.causal_decrypt(&bob, &head).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[b"genesis"]),
        "the walk follows ancestry from the entrypoint rather than reading what is at hand"
    );
    assert_eq!(walked.missing(), 0, "nothing is outstanding");

    Ok(())
}

#[tokio::test]
async fn two_missing_ancestors_are_each_reported_with_their_own_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    // Two roots, each under its own branch, and a head that joins them.
    let first_root = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"first root")
        .await?;
    let second_root = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[], b"second root")
        .await?;
    let left = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&first_root], b"left")
        .await?;
    let right = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&second_root], b"right")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, &design_doc, &[&left, &right], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // Everything except the two roots.
    for held in [&head, &left, &right] {
        ctx.deliver_content(&bob, held).await?;
    }
    let walked = ctx.causal_decrypt(&bob, &head).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[b"left", b"right"]),
        "both branches are walked, not just the first"
    );
    assert_eq!(
        walked.missing(),
        2,
        "one root outstanding per branch, reported separately"
    );

    let first_key = walked
        .key_for_missing(&first_root)
        .ok_or("the walk did not report the first root")?;
    let second_key = walked
        .key_for_missing(&second_root)
        .ok_or("the walk did not report the second root")?;
    assert_ne!(
        first_key, second_key,
        "each outstanding root has its own key, not one key reported twice"
    );
    assert!(ctx.decrypt_with_key(&first_root, &first_key).is_ok());
    assert!(
        ctx.decrypt_with_key(&second_root, &second_key).is_ok(),
        "and each key opens the content it was reported for"
    );

    Ok(())
}

/// `Document::try_causal_decrypt_content` collects the entrypoint's missing ancestors into
/// a local `CausalDecryptionState` and then returns the store walk's own state instead,
/// dropping what it collected. So a reader passed a write before the content it points at
/// is told there is nothing outstanding when what it needs is exactly that list and the
/// keys in it.
#[tokio::test]
#[ignore = "an ancestor the entrypoint lists is dropped from the report when it is missing"]
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
        .encrypt_in_envelope(&alice, &design_doc, &[&history], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // Only the entrypoint. Bob is not given the ancestor it lists.
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
/// The second walk does not report the consumed content as outstanding, because the
/// entrypoint lists it directly.
/// `an_ancestor_the_entrypoint_lists_is_reported_when_missing` covers that case.
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
        .encrypt_in_envelope(&alice, &design_doc, &[&genesis], b"head")
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
