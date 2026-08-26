use keyhive_core::access::Access::{Admin, Edit, Read};
use keyhive_core::test_utils::{AddMemberUpdateExt, TestContext, TestResult as Result};

// `AddMemberUpdate::summary()` is what the delegation says, as plain values.
#[tokio::test]
async fn a_delegation_reports_what_it_conveys() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let dlg = alice
        .add_member(bob.id(), design_doc, Read, &[])
        .await?
        .summary();

    assert_eq!(&*ctx.name_of(dlg.issuer), "alice");
    assert_eq!(&*ctx.name_of(dlg.audience), "bob");
    assert_eq!(&*ctx.name_of(dlg.subject), "design_doc");
    assert_eq!(dlg.can, Read);
    Ok(())
}

#[tokio::test]
async fn delegations_differing_in_any_field_are_distinct() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;

    let to_bob = alice
        .add_member(bob.id(), design_doc, Read, &[])
        .await?
        .summary();
    let to_carol = alice
        .add_member(carol.id(), design_doc, Read, &[])
        .await?
        .summary();
    let other_doc = alice
        .add_member(bob.id(), notes, Read, &[])
        .await?
        .summary();
    let other_level = alice
        .add_member(carol.id(), notes, Admin, &[])
        .await?
        .summary();

    let all = [&to_bob, &to_carol, &other_doc, &other_level];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "two delegations collided: {a:?} and {b:?}");
        }
    }

    let for_design_doc = ctx.delegations_for(&alice, design_doc).await?;
    let for_notes = ctx.delegations_for(&alice, notes).await?;
    for (dlg, sub) in [
        (&to_bob, &for_design_doc),
        (&to_carol, &for_design_doc),
        (&other_doc, &for_notes),
        (&other_level, &for_notes),
    ] {
        assert!(sub.contains(dlg), "{dlg:?} is not in {sub:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_delegation_keeps_its_identity_as_the_graph_grows() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    let to_bob = alice
        .add_member(bob.id(), design_doc, Edit, &[])
        .await?
        .summary();

    alice.add_member(carol.id(), design_doc, Read, &[]).await?;
    ctx.encrypt(&alice, design_doc, b"some content").await?;
    alice.revoke_member(carol.id(), true, design_doc).await?;

    let for_design_doc = ctx.delegations_for(&alice, design_doc).await?;
    assert!(
        for_design_doc.contains(&to_bob),
        "bob's delegation should be unchanged: {to_bob:?} is not in {for_design_doc:?}"
    );
    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        Some(Edit)
    );
    Ok(())
}
