//! Syncing a history that contains a revocation to a replica that has no revocations.

use keyhive_core::{
    access::Access::{Admin, Read},
    test_utils::{EventKind, Instance, TestContext, TestResult as Result},
};

/// Alice's document, reached through a group holding Bob and Erin, with Dave an
/// admin of the document who has synced nothing yet. Bob is the one the tests
/// revoke.
struct MemberGroup {
    alice: Instance,
    dave: Instance,
    bob: Instance,
    erin: Instance,
    design_doc: keyhive_core::principal::document::id::DocumentId,
    engineering: keyhive_core::principal::group::id::GroupId,
}

async fn doc_with_a_member_group(ctx: &mut TestContext) -> Result<MemberGroup> {
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let erin = ctx.individual("erin").await?;
    let dave = ctx.individual("dave").await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    for who in [&bob, &erin] {
        alice.add_member(who.id(), engineering, Read, &[]).await?;
    }
    alice.add_member(dave.id(), design_doc, Admin, &[]).await?;

    Ok(MemberGroup {
        alice,
        dave,
        bob,
        erin,
        design_doc,
        engineering,
    })
}

#[tokio::test]
async fn a_new_replica_takes_in_a_revocation_created_inside_a_member_group() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let MemberGroup {
        alice,
        dave,
        bob,
        erin,
        design_doc,
        engineering,
    } = doc_with_a_member_group(&mut ctx).await?;
    alice.revoke_member(bob.id(), true, engineering).await?;

    let pending = ctx.sync(&alice, &dave).await?;

    assert_eq!(pending, 0, "dave cannot apply {pending} events");
    assert!(
        ctx.revoked_members_of(&dave, engineering)
            .await?
            .contains_key(&bob.id().into()),
        "dave applied everything he was given and still does not have bob \
         revoked from the group, so the revocation was never received"
    );
    let on_dave = dave
        .cgka_members_for(design_doc)
        .await?
        .expect("dave has the tree");
    assert_eq!(
        on_dave,
        alice
            .cgka_members_for(design_doc)
            .await?
            .expect("alice has the tree")
    );
    assert!(on_dave.contains(&erin.id()), "erin is in the tree");
    assert!(!on_dave.contains(&bob.id()), "bob is not in the tree");
    Ok(())
}

#[tokio::test]
async fn a_document_admin_is_given_a_revocation_created_inside_a_member_group() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let MemberGroup {
        alice,
        dave,
        bob,
        engineering,
        ..
    } = doc_with_a_member_group(&mut ctx).await?;
    alice.revoke_member(bob.id(), true, engineering).await?;

    let offered = ctx.event_kinds_for(&alice, &dave).await?;

    assert!(
        offered.contains(&EventKind::Revoked),
        "dave is a document admin and was given {} events, none of them the \
         revocation inside the group",
        offered.len()
    );
    Ok(())
}

#[tokio::test]
async fn the_bulk_traversal_offers_a_revoked_members_keys_to_those_who_need_them() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let MemberGroup {
        alice,
        dave,
        bob,
        erin,
        engineering,
        ..
    } = doc_with_a_member_group(&mut ctx).await?;
    alice.revoke_member(bob.id(), true, engineering).await?;

    let all = alice.all_agent_events().await;

    // Dave reaches bob through the document, erin through the group they share.
    // Those are the two places the bulk traversal adds the revoked set, and a
    // recipient without bob's keys rejects the delegations concerning him.
    for who in [&dave, &erin] {
        let sources = all
            .prekey_index
            .get(&who.id().into())
            .expect("the traversal indexed this agent");
        assert!(
            sources.contains(&bob.id().into()),
            "{} is not given the revoked member's keys",
            who.name()
        );
    }
    Ok(())
}
