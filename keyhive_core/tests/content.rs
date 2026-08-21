mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Edit, Read};

#[tokio::test]
async fn a_member_added_before_a_write_can_derive_its_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let ct = ctx.encrypt(&alice, &design_doc, b"hello world").await?;
    ctx.sync_all().await?;

    assert!(ctx.can_decrypt(&bob, &ct).await?);
    Ok(())
}

#[tokio::test]
async fn a_member_added_after_a_write_cannot_derive_its_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let ct = ctx.encrypt(&alice, &design_doc, b"before bob").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all().await?;

    assert!(
        ctx.can_decrypt(&alice, &ct).await?,
        "the author can still read"
    );
    assert!(
        !ctx.can_decrypt(&bob, &ct).await?,
        "bob should not be able to derive the key"
    );
    Ok(())
}

#[tokio::test]
async fn predecessors_take_part_in_deriving_the_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    // The same bytes, so the content hash is the same both times and only the position in
    // the content DAG differs.
    let bytes = b"the same bytes twice";
    let root = ctx.encrypt(&alice, &design_doc, bytes).await?;
    let after_root = ctx
        .encrypt_after(&alice, &design_doc, std::slice::from_ref(&root), bytes)
        .await?;

    let root_key = ctx
        .derived_key(&alice, &root)
        .await?
        .ok_or("alice wrote the root and cannot derive its key")?;
    let after_root_key = ctx
        .derived_key(&alice, &after_root)
        .await?
        .ok_or("alice wrote the successor and cannot derive its key")?;

    assert_ne!(
        root_key, after_root_key,
        "identical bytes at different points in the DAG went under one key"
    );
    Ok(())
}

#[tokio::test]
async fn a_predecessor_does_not_make_its_earlier_key_derivable() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let before_bob = ctx.encrypt(&alice, &design_doc, b"before bob").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let after_bob = ctx
        .encrypt_after(
            &alice,
            &design_doc,
            std::slice::from_ref(&before_bob),
            b"after bob",
        )
        .await?;
    ctx.sync_all().await?;

    assert!(
        ctx.can_decrypt(&bob, &after_bob).await?,
        "bob was a member when this was written"
    );
    assert!(
        !ctx.can_decrypt(&bob, &before_bob).await?,
        "a successor naming earlier content does not hand over the earlier key"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_rotation_changes_the_key_the_same_content_goes_under() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    // The same bytes, so only the document's key material differs between the two writes.
    let bytes = b"the same bytes twice";
    let before = ctx.encrypt(&alice, &design_doc, bytes).await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;
    let after = ctx.encrypt(&alice, &design_doc, bytes).await?;

    assert_ne!(
        ctx.derived_key(&alice, &before).await?,
        ctx.derived_key(&alice, &after).await?,
        "the rotation left the same content under the same key"
    );
    assert!(
        ctx.can_decrypt(&alice, &before).await?,
        "and alice can still read what she wrote before it"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_rotation_does_not_lock_out_a_current_member() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all().await?;

    ctx.force_pcs_update(&alice, &design_doc).await?;
    let ct = ctx
        .encrypt(&alice, &design_doc, b"after the rotation")
        .await?;
    ctx.sync_all().await?;

    assert!(
        ctx.can_decrypt(&bob, &ct).await?,
        "bob was a member across the rotation"
    );
    Ok(())
}

#[tokio::test]
async fn content_written_after_a_rotation_does_not_open_what_came_before() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let history = ctx
        .encrypt(&alice, &design_doc, b"written before bob")
        .await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all().await?;
    ctx.force_pcs_update(&alice, &design_doc).await?;
    let successor = ctx
        .encrypt_after(
            &alice,
            &design_doc,
            std::slice::from_ref(&history),
            b"written after bob",
        )
        .await?;
    ctx.sync_all().await?;

    assert!(
        ctx.can_decrypt(&bob, &successor).await?,
        "bob reads content written under the key he was given"
    );
    assert!(
        !ctx.can_decrypt(&bob, &history).await?,
        "the presence of a predecessor does not provide access to its key"
    );
    Ok(())
}

// This is a sanity check for the testing facade
#[tokio::test]
async fn a_predecessor_from_another_document_is_refused() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;

    let in_design_doc = ctx.encrypt(&alice, &design_doc, b"a paragraph").await?;

    assert!(
        ctx.encrypt_after(&alice, &notes, &[in_design_doc], b"a note")
            .await
            .is_err(),
        "content in one document cannot precede content in another"
    );
    Ok(())
}

#[tokio::test]
async fn the_reader_derives_the_key_the_writer_used() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let (ct, written_under) = ctx.encrypt_keyed(&alice, &design_doc, b"hello").await?;
    ctx.sync_all().await?;

    assert_eq!(
        ctx.derived_key(&bob, &ct).await?,
        Some(written_under),
        "bob derived a different application secret"
    );
    Ok(())
}

#[tokio::test]
async fn a_non_member_derives_no_key() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let mallory = ctx.individual("mallory").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let (ct, _) = ctx.encrypt_keyed(&alice, &design_doc, b"secret").await?;
    ctx.sync_all().await?;

    assert_eq!(ctx.derived_key(&mallory, &ct).await?, None);
    Ok(())
}

#[tokio::test]
async fn the_wrong_key_does_not_decrypt() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let (first, first_key) = ctx.encrypt_keyed(&alice, &design_doc, b"one").await?;
    let (second, second_key) = ctx.encrypt_keyed(&alice, &design_doc, b"two").await?;
    assert_ne!(first_key, second_key, "two writes reused one key");

    assert_eq!(ctx.decrypt_with_key(&first, &first_key)?, b"one".to_vec());
    assert_eq!(ctx.decrypt_with_key(&second, &second_key)?, b"two".to_vec());
    assert!(ctx.decrypt_with_key(&first, &second_key).is_err());
    assert!(ctx.decrypt_with_key(&second, &first_key).is_err());
    Ok(())
}

#[tokio::test]
async fn a_ciphertext_is_refused_if_tampered_with() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let (ct, key) = ctx.encrypt_keyed(&alice, &design_doc, b"authentic").await?;
    ctx.sync_all().await?;

    let tampered = ct.with_a_flipped_bit();
    assert!(
        ctx.decrypt_with_key(&tampered, &key).is_err(),
        "the cipher is authenticated so one flipped bit causes an error"
    );
    assert!(
        !ctx.can_decrypt(&bob, &tampered).await?,
        "a flipped bit means no one can decrypt it"
    );
    Ok(())
}

#[tokio::test]
async fn a_reader_can_read_what_an_editor_wrote() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Edit).await?;
    let msg = b"Design Doc";
    let (ct, key) = ctx.encrypt_keyed(&alice, &design_doc, msg).await?;
    ctx.sync_all().await?;

    assert!(ctx.can_decrypt(&bob, &ct).await?);
    assert_eq!(ctx.decrypt_with_key(&ct, &key)?, msg.to_vec());
    Ok(())
}
