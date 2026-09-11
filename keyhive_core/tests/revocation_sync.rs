//! What is synced to each agent after a revocation.

use keyhive_core::{
    access::Access::{Admin, Read},
    test_utils::{Instance, TestContext, TestResult as Result},
};

/// Alice's document, reached through a group holding Bob and Erin, with Dave an
/// admin of the document who has synced nothing yet. Bob is the one the tests
/// revoke.
struct MemberGroup {
    alice: Instance,
    dave: Instance,
    bob: Instance,
    erin: Instance,
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
        engineering,
    })
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

    // The document reaches both of them, dave directly and erin through the
    // group, so this is the document loop's entry in the index. A recipient
    // without bob's keys rejects the delegations concerning him.
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

#[tokio::test]
async fn a_group_in_no_document_still_provides_keys_from_its_revoked_members() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let erin = ctx.individual("erin").await?;

    let engineering = ctx.group(&alice, "engineering").await?;
    for who in [&bob, &erin] {
        alice.add_member(who.id(), engineering, Read, &[]).await?;
    }
    alice.revoke_member(bob.id(), true, engineering).await?;

    let all = alice.all_agent_events().await;

    // No document holds engineering, so the group loop is the only one that can
    // put bob in erin's index.
    let sources = all
        .prekey_index
        .get(&erin.id().into())
        .expect("the traversal indexed erin");
    assert!(
        sources.contains(&bob.id().into()),
        "erin is not given the revoked member's keys"
    );
    Ok(())
}

#[tokio::test]
async fn the_bulk_traversal_reaches_a_revocation_nested_inside_a_revoked_group() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let dave = ctx.individual("dave").await?;
    let frank = ctx.individual("frank").await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let research = ctx.group(&alice, "research").await?;

    alice.add_member(dave.id(), design_doc, Admin, &[]).await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice.add_member(research, engineering, Read, &[]).await?;
    alice.add_member(frank.id(), research, Read, &[]).await?;

    alice.revoke_member(frank.id(), true, research).await?;
    alice.revoke_member(engineering, true, design_doc).await?;

    let all = alice.all_agent_events().await;

    // Frank is two groups down from the document and behind a revocation at each
    // step, so reaching him requires traversing into a revoked group.
    let sources = all
        .prekey_index
        .get(&dave.id().into())
        .expect("the traversal indexed dave");
    assert!(
        sources.contains(&frank.id().into()),
        "dave is not given the keys of a member revoked inside the revoked group"
    );
    Ok(())
}
