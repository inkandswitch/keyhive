//! A document founded under an identity reserved ahead of time.

use keyhive_core::{
    principal::document::{id::DocumentId, GenerateDocError},
    test_utils::{content_ref, TestContext, TestResult as Result},
};
use keyhive_crypto::identifier::Identifier;
use keyline::power::Power::Admin;
use nonempty::nonempty;

#[tokio::test]
async fn a_reserved_identity_becomes_the_document_id() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let team = ctx.group(&alice, "team").await?;

    let reserved = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let expected = DocumentId::from(Identifier::from(&reserved));
    let doc = alice
        .generate_doc_with_reserved_signer(reserved, vec![team.into()], nonempty![[7u8; 32]])
        .await?;
    assert_eq!(doc, expected, "the reserved key's identity is the id");

    let members = alice.reachable_members(doc).await?;
    assert_eq!(members.get(&alice.id().into()), Some(&Admin));
    assert_eq!(
        members.get(&team.into()),
        Some(&Admin),
        "the coparent group is an admin"
    );

    let content = b"first write";
    let encrypted = alice
        .try_encrypt_content(doc, &content_ref(content), &[], content)
        .await?;
    assert!(alice
        .can_decrypt_content(doc, encrypted.encrypted_content())
        .await?);
    Ok(())
}

#[tokio::test]
async fn founding_a_reserved_identity_twice_leaves_the_first_document_alone() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;

    let reserved = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let doc = alice
        .generate_doc_with_reserved_signer(reserved.clone(), vec![], nonempty![[7u8; 32]])
        .await?;
    let members_before = alice.cgka_members_for(doc).await?;

    let again = alice
        .generate_doc_with_reserved_signer(reserved, vec![], nonempty![[8u8; 32]])
        .await;
    assert!(
        matches!(again, Err(GenerateDocError::AlreadyExists(id)) if id == doc),
        "a retry is refused: {again:?}"
    );
    assert_eq!(alice.cgka_members_for(doc).await?, members_before);
    Ok(())
}
