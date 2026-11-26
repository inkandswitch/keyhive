//! Preparing a write and applying it later, so a caller can persist first.

use future_form::Local;
use keyhive_content::store::memory::MemoryCiphertextStore;
use keyhive_core::{
    content::heads::ContentHeads,
    keyhive::{EncryptContentError, Keyhive},
    listener::log::Log,
    principal::document::EncryptError,
    test_utils::{content_ref, Instance, TestContext, TestResult as Result},
};
use keyhive_crypto::signer::memory::MemorySigner;
use keyline::power::Power::Edit;
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::rngs::ThreadRng;

/// Alice owns a document and has made Bob an editor. Bob's first write has to rotate
/// his leaf, which makes it a write that needs a CGKA update.
async fn alice_and_bob() -> Result<(
    TestContext,
    Instance,
    Instance,
    keyhive_core::principal::document::id::DocumentId,
)> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let doc = ctx.doc(&alice, "doc").await?;
    alice.add_member(bob.id(), doc, Edit).await?;
    ctx.sync(&alice, &bob).await?;
    Ok((ctx, alice, bob, doc))
}

#[tokio::test]
async fn a_dropped_preparation_leaves_the_keyhive_byte_identical() -> Result<()> {
    let (_ctx, _alice, bob, doc) = alice_and_bob().await?;
    let content = b"never written";
    let content_ref = content_ref(content);

    let before = bob.into_archive().await?;
    let prepared = bob
        .prepare_encrypt_content(doc, &content_ref, &[], content)
        .await?;
    assert!(
        prepared.rotation().is_some(),
        "precondition: Bob's first write rotates, so there is a CGKA update to not apply"
    );
    drop(prepared);

    let after = bob.into_archive().await?;
    assert!(before == after, "a dropped preparation changed the archive");
    assert_eq!(
        before.encode_zeroizing().as_slice(),
        after.encode_zeroizing().as_slice()
    );
    assert!(!bob.has_key_for(doc, &content_ref).await);
    Ok(())
}

/// What a write did, by the route it took: whether it rotated, whether the next write
/// rotated, whether Alice read it and with the key the writer was given.
async fn write_twice(prepare_and_apply: bool) -> Result<(bool, bool, bool)> {
    let (mut ctx, alice, bob, doc) = alice_and_bob().await?;
    let first = b"first";
    let (written, key) = if prepare_and_apply {
        let prepared = bob
            .prepare_encrypt_content(doc, &content_ref(first), &[], first)
            .await?;
        bob.apply_prepared_encryption(prepared).await?
    } else {
        bob.try_encrypt_content_keyed(doc, &content_ref(first), &[], first)
            .await?
    };
    let rotated = written.update_op().is_some();
    assert!(bob.has_key_for(doc, &content_ref(first)).await);

    ctx.sync(&bob, &alice).await?;
    let ciphertext = written.encrypted_content();
    let read = alice.try_decrypt_content(doc, ciphertext).await?.plaintext == first;
    let key_matches = ctx.derived_key(&alice, doc, ciphertext).await? == Some(key);
    assert!(
        key_matches,
        "the key the writer was given is the one the reader derives"
    );

    let second = b"second";
    let again = bob
        .try_encrypt_content(doc, &content_ref(second), &[], second)
        .await?;
    Ok((rotated, again.update_op().is_some(), read))
}

#[tokio::test]
async fn prepare_then_apply_does_what_the_one_shot_write_does() -> Result<()> {
    let one_shot = write_twice(false).await?;
    let prepared = write_twice(true).await?;
    assert_eq!(one_shot, prepared);
    assert_eq!(
        one_shot,
        (true, false, true),
        "rotate once, then write without"
    );
    Ok(())
}

#[tokio::test]
async fn a_second_preparation_is_refused_once_the_first_rotated() -> Result<()> {
    let (mut ctx, alice, bob, doc) = alice_and_bob().await?;
    let (one, two) = (b"one", b"two");
    let first = bob
        .prepare_encrypt_content(doc, &content_ref(one), &[], one)
        .await?;
    let second = bob
        .prepare_encrypt_content(doc, &content_ref(two), &[], two)
        .await?;
    assert!(first.rotation().is_some() && second.rotation().is_some());

    bob.apply_prepared_encryption(first).await?;
    let applied = bob.into_archive().await?;
    let refused = bob.apply_prepared_encryption(second).await;
    assert!(
        matches!(
            refused,
            Err(EncryptContentError::EncryptError(
                EncryptError::StalePreparedEncryption
            ))
        ),
        "got {refused:?}"
    );
    assert!(
        applied == bob.into_archive().await?,
        "a refused apply changed the archive"
    );
    assert!(!bob.has_key_for(doc, &content_ref(two)).await);

    // Preparing again, from the state the first write left, works and reads.
    let again = bob
        .prepare_encrypt_content(doc, &content_ref(two), &[], two)
        .await?;
    let (written, _) = bob.apply_prepared_encryption(again).await?;
    ctx.sync(&bob, &alice).await?;
    let plaintext = alice
        .try_decrypt_content(doc, written.encrypted_content())
        .await?
        .plaintext;
    assert_eq!(plaintext, two);
    Ok(())
}

#[tokio::test]
async fn a_preparation_is_refused_after_another_member_changed_the_group() -> Result<()> {
    let (mut ctx, alice, bob, doc) = alice_and_bob().await?;
    let content = b"late";
    let prepared = bob
        .prepare_encrypt_content(doc, &content_ref(content), &[], content)
        .await?;

    alice.force_pcs_update(doc).await?;
    ctx.sync(&alice, &bob).await?;

    let before = bob.into_archive().await?;
    let refused = bob.apply_prepared_encryption(prepared).await;
    assert!(
        matches!(
            refused,
            Err(EncryptContentError::EncryptError(
                EncryptError::StalePreparedEncryption
            ))
        ),
        "got {refused:?}"
    );
    assert!(
        before == bob.into_archive().await?,
        "a refused apply changed the archive"
    );
    Ok(())
}

/// The listener hears of a write's rotation when it is applied and not before.
#[tokio::test]
async fn the_listener_hears_of_the_rotation_at_apply_only() -> Result<()> {
    type Hive = Keyhive<
        Local,
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        Log<[u8; 32]>,
        ThreadRng,
        MemoryKeyline<ContentHeads<[u8; 32]>>,
    >;
    async fn hive() -> (Hive, Log<[u8; 32]>) {
        let log = Log::<[u8; 32]>::new();
        let hive = Hive::generate(
            MemorySigner::generate(&mut rand::thread_rng()),
            MemoryCiphertextStore::new(),
            log.clone(),
            MemoryKeyline::new(),
            rand::thread_rng(),
        )
        .await
        .unwrap();
        (hive, log)
    }
    let (alice, _) = hive().await;
    let (bob, bob_log) = hive().await;
    let bob_id = alice
        .receive_contact_card(&bob.get_existing_contact_card().await)
        .await?;
    let content = b"heard";
    let heads = *blake3::hash(content).as_bytes();
    let doc = alice.generate_doc(vec![], nonempty![heads]).await?;
    alice.add_member(bob_id, doc, Edit).await?;
    let events = alice.static_events_for_agent(bob_id).await?;
    assert!(bob
        .ingest_unsorted_static_events(events.into_values().collect())
        .await
        .is_empty());
    bob_log.clear().await;

    let prepared = bob
        .prepare_encrypt_content(doc, &heads, &[], content)
        .await?;
    assert!(prepared.rotation().is_some());
    let announced_by_preparing = bob_log.len().await;
    drop(prepared);
    assert_eq!(announced_by_preparing, bob_log.len().await);

    bob_log.clear().await;
    let prepared = bob
        .prepare_encrypt_content(doc, &heads, &[], content)
        .await?;
    assert_eq!(bob_log.len().await, 0, "preparing a write is silent");
    let (written, _) = bob.apply_prepared_encryption(prepared).await?;
    assert!(written.update_op().is_some());
    assert_eq!(
        bob_log.len().await,
        1,
        "applying announces the rotation, once"
    );
    Ok(())
}
