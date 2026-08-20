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
