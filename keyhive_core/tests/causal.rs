//! Reading a chain of content by walking back through the ancestors each write lists.

use future_form::Sendable;
use keyhive_content::store::memory::MemoryCiphertextStore;
use keyhive_core::{
    keyhive::EncryptContentError,
    principal::document::id::DocumentId,
    test_utils::{
        decrypt_with_key, CausalDecryptionExt, Instance, TestContext, TestError,
        TestResult as Result,
    },
};
use keyhive_crypto::symmetric_key::SymmetricKey;
use keyline::power::Power::Read;
use std::{collections::BTreeSet, sync::Arc};

async fn setup_writer_and_reader() -> Result<(TestContext, Instance, Instance, DocumentId)> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
    ctx.sync_all_unsent().await?;
    Ok((ctx, alice, bob, design_doc))
}

fn contents(of: &[&[u8]]) -> BTreeSet<Vec<u8>> {
    of.iter().map(|c| c.to_vec()).collect()
}

#[tokio::test]
async fn a_reader_walks_back_through_the_ancestors_it_holds() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    // genesis, then two writes with it as their predecessor, then one with both of those.
    let genesis = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"genesis")
        .await?;
    let left = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&genesis], b"left")
        .await?;
    let right = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&genesis], b"right")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&left, &right], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    for ct in [&genesis, &left, &right, &head] {
        ctx.give_content(&bob, ct).await?;
    }
    let walked = bob.try_causal_decrypt_content(design_doc, &head).await?;

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

#[tokio::test]
async fn content_reads_back_as_its_payload_however_it_was_written() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;
    // A leading zero is also an empty count of ancestors, so a raw body would read back
    // without it.
    let genesis = ctx.encrypt(&alice, design_doc, b"\0genesis").await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&genesis], b"head")
        .await?;
    ctx.sync_all_unsent().await?;
    for ct in [&genesis, &head] {
        ctx.give_content(&bob, ct).await?;
    }

    assert_eq!(
        bob.try_decrypt_content(design_doc, &head).await?.plaintext,
        b"head"
    );
    let walked = bob.try_causal_decrypt_content(design_doc, &head).await?;
    assert_eq!(walked.recovered(), contents(&[b"\0genesis"]));
    Ok(())
}

#[tokio::test]
async fn a_write_cannot_refer_to_a_predecessor_this_replica_has_not_read() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;
    let genesis = ctx.encrypt(&alice, design_doc, b"genesis").await?;
    ctx.sync_all_unsent().await?;

    let written = bob
        .try_encrypt_content(design_doc, &[9; 32], &[genesis.content_ref], b"head")
        .await;
    assert!(matches!(
        written,
        Err(EncryptContentError::NoKeyForPredecessor(r)) if r == genesis.content_ref
    ));
    Ok(())
}

#[tokio::test]
async fn a_block_read_by_a_traversal_can_be_referred_to_as_a_predecessor() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;
    let genesis = ctx.encrypt(&alice, design_doc, b"genesis").await?;
    let head = ctx
        .encrypt_after(&alice, design_doc, &[&genesis], b"head")
        .await?;
    ctx.sync_all_unsent().await?;
    for ct in [&genesis, &head] {
        ctx.give_content(&bob, ct).await?;
    }

    bob.try_causal_decrypt_content(design_doc, &head).await?;
    ctx.encrypt_after(&bob, design_doc, &[&genesis], b"sibling")
        .await?;
    Ok(())
}

#[tokio::test]
async fn a_block_read_by_a_traversal_from_keys_can_be_referred_to_as_a_predecessor() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;
    let genesis = ctx.encrypt(&alice, design_doc, b"genesis").await?;
    let head = ctx
        .encrypt_after(&alice, design_doc, &[&genesis], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    let envelope = bob.try_decrypt_content(design_doc, &head).await?;
    let start: Vec<_> = envelope.ancestors.into_iter().collect();
    let store = MemoryCiphertextStore::new();
    store.insert(Arc::new(genesis.clone())).await;
    bob.try_causal_decrypt_from_keys::<Sendable, _, _>(design_doc, &start, &store)
        .await
        .map_err(|e| TestError::Other(e.to_string()))?;
    ctx.encrypt_after(&bob, design_doc, &[&genesis], b"sibling")
        .await?;
    Ok(())
}

#[tokio::test]
async fn another_block_with_the_same_ref_does_not_replace_a_known_key() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;
    let genesis = ctx.encrypt(&alice, design_doc, b"genesis").await?;
    // Listing genesis as its predecessor gives the impostor a key of its own.
    let (impostor, impostor_key) = alice
        .try_encrypt_content_keyed(
            design_doc,
            &genesis.content_ref,
            &[genesis.content_ref],
            b"impostor",
        )
        .await?;
    let impostor = impostor.encrypted_content().clone();
    ctx.sync_all_unsent().await?;
    let (_, genesis_key) = bob.try_decrypt_content_keyed(design_doc, &genesis).await?;
    assert_ne!(genesis_key, impostor_key);

    bob.try_decrypt_content(design_doc, &impostor).await?;
    let store = MemoryCiphertextStore::new();
    store.insert(Arc::new(impostor)).await;
    bob.try_causal_decrypt_from_keys::<Sendable, _, _>(
        design_doc,
        &[(genesis.content_ref, impostor_key)],
        &store,
    )
    .await
    .map_err(|e| TestError::Other(e.to_string()))?;

    let after = bob
        .try_encrypt_content(design_doc, &[9; 32], &[genesis.content_ref], b"after")
        .await?;
    let read = alice
        .try_decrypt_content(design_doc, after.encrypted_content())
        .await?;
    assert_eq!(read.ancestors.get(&genesis.content_ref), Some(&genesis_key));
    Ok(())
}

#[tokio::test]
async fn a_key_that_fails_to_decrypt_a_block_is_not_remembered() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;
    let head = ctx.encrypt(&alice, design_doc, b"head").await?;
    ctx.sync_all_unsent().await?;
    let store = MemoryCiphertextStore::new();
    store.insert(Arc::new(head.clone())).await;

    let walked = bob
        .try_causal_decrypt_from_keys::<Sendable, _, _>(
            design_doc,
            &[(head.content_ref, SymmetricKey::from([9; 32]))],
            &store,
        )
        .await;
    assert!(matches!(&walked, Err(err) if err.cannot.contains_key(&head.content_ref)));

    let written = bob
        .try_encrypt_content(design_doc, &[8; 32], &[head.content_ref], b"after head")
        .await;
    assert!(matches!(
        written,
        Err(EncryptContentError::NoKeyForPredecessor(r)) if r == head.content_ref
    ));
    Ok(())
}

/// A later member reads earlier content by traversing back from a write made after they
/// joined.
#[tokio::test]
async fn traversing_from_a_write_reports_its_ancestors() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let history = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"written before bob")
        .await?;

    alice.add_member(bob.id(), design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let entry_point = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&history], b"written after bob")
        .await?;
    ctx.sync_all_unsent().await?;

    assert!(
        bob.can_decrypt_content(design_doc, &entry_point).await?,
        "he can open the write that came after"
    );

    ctx.give_content(&bob, &history).await?;
    ctx.give_content(&bob, &entry_point).await?;
    let traversed = bob
        .try_causal_decrypt_content(design_doc, &entry_point)
        .await?;

    assert_eq!(
        traversed.recovered(),
        contents(&[b"written before bob"]),
        "and traversing back from it reports the earlier write"
    );
    Ok(())
}

/// Every other test here has one writer, who has the key to each ancestor from having
/// encrypted it. This one has a second writer reference content they only ever read, so the key
/// in their envelope is one they got by decrypting.
#[tokio::test]
async fn a_reader_can_reference_an_ancestor_they_decrypted_rather_than_wrote() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    let genesis = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"genesis")
        .await?;
    ctx.sync_all_unsent().await?;

    // Bob reads it. Decrypting is the only way he learns its key, since he did not write it.
    ctx.give_content(&bob, &genesis).await?;
    assert!(
        bob.can_decrypt_content(design_doc, &genesis).await?,
        "bob can open the genesis write"
    );

    alice.add_member(carol.id(), design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    // Bob writes a successor referencing the genesis, which means putting its key in the envelope.
    let head = ctx
        .encrypt_in_envelope(&bob, design_doc, &[&genesis], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    ctx.give_content(&carol, &genesis).await?;
    ctx.give_content(&carol, &head).await?;
    let traversed = carol.try_causal_decrypt_content(design_doc, &head).await?;
    assert_eq!(
        traversed.recovered(),
        contents(&[b"genesis"]),
        "the traversal reports the ancestor bob's write refers to"
    );
    assert_eq!(traversed.missing(), 0);
    Ok(())
}

#[tokio::test]
async fn an_ancestor_that_is_not_present_is_reported_rather_than_failing() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    let genesis = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"genesis")
        .await?;
    let middle = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&genesis], b"middle")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&middle], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // Everything except the root of the chain.
    ctx.give_content(&bob, &head).await?;
    ctx.give_content(&bob, &middle).await?;
    let traversed = bob.try_causal_decrypt_content(design_doc, &head).await?;

    assert_eq!(
        traversed.recovered(),
        contents(&[b"middle"]),
        "the traversal gets as far as it can"
    );
    assert_eq!(
        traversed.missing(),
        1,
        "and says something is outstanding rather than failing"
    );
    let key = traversed
        .key_for_missing(&genesis)
        .ok_or("the traversal did not say which content is outstanding")?;
    assert!(
        decrypt_with_key(&genesis, key, design_doc).is_ok(),
        "and the key it reported for it is the one that opens it, so fetching is enough"
    );

    Ok(())
}

#[tokio::test]
async fn a_walk_from_two_heads_reads_their_shared_ancestor_once() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    //   first_root              second_root
    //      │  └────────┐   ┌──────┘
    //      ▼           ▼   ▼
    //    left           right
    //      │  └────────┐   │  └──────┐
    //      ▼           ▼   ▼         ▼
    //  left_head     head_above   right_head
    //
    // The walk starts at left_head and right_head, so it never reaches head_above, which
    // sits above both middles. first_root is reachable through left and through right,
    // which is what makes it the shared ancestor.
    let first_root = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"first root")
        .await?;
    let second_root = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"second root")
        .await?;
    let left = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&first_root], b"left")
        .await?;
    let right = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&second_root, &first_root], b"right")
        .await?;
    let left_head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&left], b"left head")
        .await?;
    let right_head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&right], b"right head")
        .await?;
    let head_above = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&left, &right], b"the head above")
        .await?;
    ctx.sync_all_unsent().await?;

    for held in [
        &first_root,
        &second_root,
        &left,
        &right,
        &left_head,
        &right_head,
        &head_above,
    ] {
        ctx.give_content(&bob, held).await?;
    }
    // Walking from several heads at once needs the key for each entrypoint, which the
    // reader derives the same way it would for a single one.
    let mut heads = Vec::new();
    for head in [&left_head, &right_head] {
        let key = ctx
            .derived_key(&bob, design_doc, head)
            .await?
            .ok_or("the reader cannot derive the key for an entrypoint")?;
        heads.push((Arc::new(head.clone()), key));
    }
    let walked = bob.try_causal_decrypt_from(design_doc, &heads).await?;

    assert_eq!(
        walked.recovered(),
        contents(&[
            b"left head",
            b"right head",
            b"left",
            b"right",
            b"first root",
            b"second root",
        ]),
        "both entrypoints, both middles and both roots, and not the head above them"
    );
    assert_eq!(
        walked.recovered_count(),
        6,
        "first root is reached through left and through right, and read once"
    );
    assert_eq!(walked.missing(), 0, "bob holds everything the walk reaches");

    let key = walked
        .key_for_recovered(&first_root)
        .ok_or("the walk did not report the key it read the shared root under")?;
    assert!(
        decrypt_with_key(&first_root, key, design_doc).is_ok(),
        "and that key is the one that opens it"
    );
    assert!(
        walked.key_for_recovered(&head_above).is_none(),
        "no key is reported for content the walk never reached"
    );

    Ok(())
}

#[tokio::test]
async fn content_that_is_not_an_ancestor_is_not_captured_in_the_walk() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    let genesis = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"genesis")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&genesis], b"head")
        .await?;
    // Held by bob, in the same document, and on no path from the head.
    let unrelated = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"unrelated")
        .await?;
    ctx.sync_all_unsent().await?;

    for held in [&head, &genesis, &unrelated] {
        ctx.give_content(&bob, held).await?;
    }
    let walked = bob.try_causal_decrypt_content(design_doc, &head).await?;

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
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    // Two roots, each under its own branch, and a head that joins them.
    let first_root = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"first root")
        .await?;
    let second_root = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"second root")
        .await?;
    let left = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&first_root], b"left")
        .await?;
    let right = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&second_root], b"right")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&left, &right], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // Everything except the two roots.
    for held in [&head, &left, &right] {
        ctx.give_content(&bob, held).await?;
    }
    let walked = bob.try_causal_decrypt_content(design_doc, &head).await?;

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
    assert!(decrypt_with_key(&first_root, first_key, design_doc).is_ok());
    assert!(
        decrypt_with_key(&second_root, second_key, design_doc).is_ok(),
        "and each key opens the content it was reported for"
    );

    Ok(())
}

/// A reader passed a write before the content it points at is told which content to fetch,
/// with the keys to open it. The entrypoint's own ancestors are reported like those deeper
/// in the walk.
#[tokio::test]
async fn an_ancestor_the_entrypoint_lists_is_reported_when_missing() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    let history = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"history")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&history], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    // Only the entrypoint. Bob is not given the ancestor it lists.
    ctx.give_content(&bob, &head).await?;
    let walked = bob.try_causal_decrypt_content(design_doc, &head).await?;

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
/// A store that no longer serves content cannot tell "already read" from "never delivered",
/// so the second walk reports the consumed content as outstanding, with its key, as it does
/// for any ancestor the store does not serve.
#[tokio::test]
async fn a_walk_consumes_the_content_it_reads() -> Result<()> {
    let (mut ctx, alice, bob, design_doc) = setup_writer_and_reader().await?;

    let genesis = ctx
        .encrypt_in_envelope(&alice, design_doc, &[], b"genesis")
        .await?;
    let head = ctx
        .encrypt_in_envelope(&alice, design_doc, &[&genesis], b"head")
        .await?;
    ctx.sync_all_unsent().await?;

    ctx.give_content(&bob, &genesis).await?;
    ctx.give_content(&bob, &head).await?;

    let first = bob.try_causal_decrypt_content(design_doc, &head).await?;
    assert_eq!(first.recovered(), contents(&[b"genesis"]));

    let second = bob.try_causal_decrypt_content(design_doc, &head).await?;
    assert_eq!(
        second.recovered(),
        contents(&[]),
        "the first walk took it out of the store"
    );
    assert!(
        second.key_for_missing(&genesis).is_some(),
        "so it is reported as outstanding, with its key"
    );

    ctx.give_content(&bob, &genesis).await?;
    let third = bob.try_causal_decrypt_content(design_doc, &head).await?;
    assert_eq!(
        third.recovered(),
        contents(&[b"genesis"]),
        "delivering it again is enough to read it again"
    );
    Ok(())
}
