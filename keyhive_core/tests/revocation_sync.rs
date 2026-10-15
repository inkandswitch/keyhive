//! What is synced to each principal after a revocation: a revoked member's
//! keys go to no one, a live member's to those it may be seated with.

use keyhive_core::{
    principal::identifier::Identifier,
    test_utils::{Instance, TestContext, TestResult as Result},
};
use keyline::power::Power::{Admin, Read};

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
    alice.add_member(engineering, design_doc, Read).await?;
    for who in [&bob, &erin] {
        alice.add_member(who.id(), engineering, Read).await?;
    }
    alice.add_member(dave.id(), design_doc, Admin).await?;

    Ok(MemberGroup {
        alice,
        dave,
        bob,
        erin,
        engineering,
    })
}

#[tokio::test]
async fn the_bulk_traversal_offers_live_members_keys_and_not_revoked_ones() -> Result<()> {
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

    let all = alice.all_agent_events().await?;

    // The document reaches both of them, dave directly and erin through the
    // group. Erin may be seated with dave; bob is out and needs no seat.
    for who in [&dave, &erin] {
        let sources = all
            .prekey_index
            .get(&who.id().into())
            .expect("the traversal indexed this principal");
        assert!(
            sources.contains(&erin.id().into()),
            "{} is not given the live member's keys",
            who.name()
        );
        assert!(
            !sources.contains(&bob.id().into()),
            "{} is given the revoked member's keys",
            who.name()
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_group_in_no_document_offers_no_keys_of_its_revoked_members() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let erin = ctx.individual("erin").await?;

    let engineering = ctx.group(&alice, "engineering").await?;
    for who in [&bob, &erin] {
        alice.add_member(who.id(), engineering, Read).await?;
    }
    alice.revoke_member(bob.id(), true, engineering).await?;

    let all = alice.all_agent_events().await?;

    let sources = all
        .prekey_index
        .get(&erin.id().into())
        .expect("the traversal indexed erin");
    assert!(
        !sources.contains(&bob.id().into()),
        "erin is given the revoked member's keys"
    );
    Ok(())
}

#[tokio::test]
async fn a_member_revoked_inside_a_revoked_group_is_offered_to_no_one() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let dave = ctx.individual("dave").await?;
    let frank = ctx.individual("frank").await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let research = ctx.group(&alice, "research").await?;

    alice.add_member(dave.id(), design_doc, Admin).await?;
    alice.add_member(engineering, design_doc, Read).await?;
    alice.add_member(research, engineering, Read).await?;
    alice.add_member(frank.id(), research, Read).await?;

    alice.revoke_member(frank.id(), true, research).await?;
    alice.revoke_member(engineering, true, design_doc).await?;

    let all = alice.all_agent_events().await?;

    // Frank is two groups down from the document and behind a revocation at each
    // step.
    for (who, sources) in &all.prekey_index {
        assert!(
            *who == Identifier::from(frank.id()) || !sources.contains(&frank.id().into()),
            "{who} is given the keys of a member revoked inside the revoked group"
        );
    }
    assert!(
        all.explanations.contains_key(&frank.id().into()),
        "frank is sent what explains his removal"
    );
    Ok(())
}
