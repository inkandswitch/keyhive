//! What is synced to each principal after a revocation: a revoked member's
//! keys go to no one, a live member's to those who may add it to a CGKA
//! group.

use keyhive_core::test_utils::{Instance, TestContext, TestResult as Result};
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
async fn a_revoked_members_keys_reach_everyone_sent_its_revocation() -> Result<()> {
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

    // Both are sent engineering's revocation of bob, and the delegation it
    // revokes names him: erin as a member of the group, dave through the
    // document's delegation to it. Erin, still a member, may be added to a
    // CGKA group by either of them.
    for who in [&dave, &erin] {
        let sources = all
            .prekey_index
            .get(&who.id().into())
            .expect("this principal is indexed");
        assert!(
            sources.contains(&erin.id().into()),
            "{} is not given the live member's keys",
            who.name()
        );
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
        alice.add_member(who.id(), engineering, Read).await?;
    }
    alice.revoke_member(bob.id(), true, engineering).await?;

    let all = alice.all_agent_events().await?;

    // No document contains engineering, so only the group's own certificates
    // name bob.
    let sources = all
        .prekey_index
        .get(&erin.id().into())
        .expect("erin is indexed");
    assert!(
        sources.contains(&bob.id().into()),
        "erin is not given the revoked member's keys"
    );
    Ok(())
}

#[tokio::test]
async fn a_revocation_inside_a_revoked_group_sends_the_revoked_members_keys() -> Result<()> {
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

    // Dave holds the document's closure, which reaches research's delegation
    // to frank and its revocation through engineering.
    let sources = all
        .prekey_index
        .get(&dave.id().into())
        .expect("dave is indexed");
    assert!(
        sources.contains(&frank.id().into()),
        "dave is not given the keys of a member revoked inside the revoked group"
    );
    assert!(
        all.explanations.contains_key(&frank.id().into()),
        "frank is sent what explains his removal"
    );
    Ok(())
}

#[tokio::test]
async fn a_removed_member_and_its_remover_agree_on_what_it_is_sent() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(bob.id(), engineering, Admin).await?;
    ctx.sync_all_unsent().await?;

    alice.revoke_member(bob.id(), true, engineering).await?;
    ctx.sync_all_unsent().await?;

    let bobs_view = bob.event_digests_for_agent(bob.id()).await?;
    assert_eq!(alice.event_digests_for_agent(bob.id()).await?, bobs_view);
    assert_eq!(
        alice.all_agent_events().await?.digests_for(bob.id().into()),
        bobs_view
    );
    Ok(())
}
