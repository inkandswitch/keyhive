mod facade;

use facade::{Result, TestContext};
use keyhive_core::access::Access::{Admin, Edit, Read};

#[tokio::test]
async fn a_certificate_reports_what_it_conveys() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let cert = ctx.delegate(&alice, &bob, &design_doc, Read).await?;

    assert_eq!(cert.issuer(), "alice");
    assert_eq!(cert.audience(), "bob");
    assert_eq!(cert.subject(), "design_doc");
    assert_eq!(cert.can(), Read);
    Ok(())
}

#[tokio::test]
async fn certificates_differing_in_any_field_are_distinct() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;

    let to_bob = ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let to_carol = ctx.delegate(&alice, &carol, &design_doc, Read).await?;
    let other_doc = ctx.delegate(&alice, &bob, &notes, Read).await?;
    let other_level = ctx.delegate(&alice, &carol, &notes, Admin).await?;

    let all = [&to_bob, &to_carol, &other_doc, &other_level];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "two delegations collided: {a:?} and {b:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_certificate_keeps_its_identity_as_the_graph_grows() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let to_bob = ctx.delegate(&alice, &bob, &design_doc, Edit).await?;
    let before = to_bob.clone();

    ctx.delegate(&alice, &carol, &design_doc, Read).await?;
    ctx.encrypt(&alice, &design_doc, b"some content").await?;
    ctx.revoke(&alice, &carol, &design_doc).await?;

    assert_eq!(to_bob, before);
    assert_eq!(ctx.effective_access(&bob, &design_doc).await?, Some(Edit));
    Ok(())
}
