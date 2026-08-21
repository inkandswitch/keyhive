mod facade;

use facade::{Result, TestContext, TestDocument, TestIndividual};
use keyhive_core::access::Access::{Admin, Edit, Read};
use std::collections::BTreeSet;

/// Write new content and report which of `cast` can read it.
///
/// Reading content written after a change is the behaviour behind "is this individual in
/// the document's key group?", which is what these tests are about.
async fn readers_after_writing(
    ctx: &mut TestContext,
    author: &TestIndividual,
    doc: &TestDocument,
    content: &[u8],
    cast: &[&TestIndividual],
) -> Result<BTreeSet<String>> {
    let ct = ctx.encrypt(author, doc, content).await?;
    ctx.sync_all_unsent().await?;
    let mut readers = BTreeSet::new();
    for who in cast {
        if ctx.can_decrypt(who, &ct).await? {
            readers.insert(who.name().to_string());
        }
    }
    Ok(readers)
}

fn named(who: &[&str]) -> BTreeSet<String> {
    who.iter().map(|n| n.to_string()).collect()
}

#[tokio::test]
async fn revoking_a_group_from_a_document_removes_only_its_members() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let dave = ctx.individual("dave").await?;
    let eve = ctx.individual("eve").await?;
    let frank = ctx.individual("frank").await?;
    let cast = [&alice, &bob, &carol, &dave, &eve, &frank];

    // inner = {dave, eve, frank}, outer = {carol, inner}
    let inner = ctx.group(&alice, "inner").await?;
    let outer = ctx.group(&alice, "outer").await?;
    for who in [&dave, &eve, &frank] {
        ctx.delegate(&alice, who, &inner, Read).await?;
    }
    ctx.delegate(&alice, &carol, &outer, Read).await?;
    ctx.delegate(&alice, &inner, &outer, Read).await?;

    // The document holds bob directly, outer, and frank directly.
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.delegate(&alice, &outer, &design_doc, Read).await?;
    ctx.delegate(&alice, &frank, &design_doc, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob", "carol", "dave", "eve", "frank"]),
        "everyone reaches the document to begin with"
    );

    ctx.revoke(&alice, &outer, &design_doc).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob", "frank"]),
        "carol, dave and eve had only the group route; frank also has a direct one"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_subgroup_removes_only_the_members_it_brought() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let dave = ctx.individual("dave").await?;
    let eve = ctx.individual("eve").await?;
    let frank = ctx.individual("frank").await?;
    let cast = [&alice, &bob, &carol, &dave, &eve, &frank];

    let inner = ctx.group(&alice, "inner").await?;
    let outer = ctx.group(&alice, "outer").await?;
    for who in [&dave, &eve, &frank] {
        ctx.delegate(&alice, who, &inner, Read).await?;
    }
    ctx.delegate(&alice, &carol, &outer, Read).await?;
    ctx.delegate(&alice, &inner, &outer, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.delegate(&alice, &outer, &design_doc, Read).await?;
    ctx.delegate(&alice, &frank, &design_doc, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob", "carol", "dave", "eve", "frank"]),
        "everyone reaches the document to begin with"
    );

    // The same graph as above, revoked one level further in.
    ctx.revoke(&alice, &inner, &outer).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob", "carol", "frank"]),
        "dave and eve came in through inner; carol was outer's own member"
    );
    Ok(())
}

#[tokio::test]
async fn a_change_in_a_group_that_holds_a_document_leaves_the_document_alone() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let dave = ctx.individual("dave").await?;
    let cast = [&alice, &bob, &dave];

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &bob, &design_doc, Read).await?;

    // The document is a member of engineering, so engineering reaches the document and not
    // the other way round.
    let staff = ctx.group(&alice, "staff").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    ctx.delegate(&alice, &dave, &staff, Read).await?;
    ctx.delegate(&alice, &design_doc, &engineering, Read)
        .await?;
    ctx.delegate(&alice, &staff, &engineering, Read).await?;

    let before = readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?;
    assert_eq!(
        before,
        named(&["alice", "bob"]),
        "dave reaches engineering, which the document is a member of, so not the document"
    );

    ctx.revoke(&alice, &staff, &engineering).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        before,
        "a revocation one level above the document does not touch its members"
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_member_to_a_group_reaches_the_documents_it_holds() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice"]),
        "bob is in nothing yet"
    );

    ctx.delegate(&alice, &bob, &engineering, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "joining the group joined the document's key group"
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_member_deep_in_a_chain_reaches_the_document() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    // innermost in middle in outermost in the document.
    let innermost = ctx.group(&alice, "innermost").await?;
    let middle = ctx.group(&alice, "middle").await?;
    let outermost = ctx.group(&alice, "outermost").await?;
    ctx.delegate(&alice, &innermost, &middle, Read).await?;
    ctx.delegate(&alice, &middle, &outermost, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &outermost, &design_doc, Read).await?;

    ctx.delegate(&alice, &bob, &innermost, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "three groups deep still reaches the document"
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_member_to_a_group_reaches_every_document_it_holds() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;
    ctx.delegate(&alice, &engineering, &notes, Read).await?;

    ctx.delegate(&alice, &bob, &engineering, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"one", &cast).await?,
        named(&["alice", "bob"])
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &notes, b"two", &cast).await?,
        named(&["alice", "bob"]),
        "one addition, every document the group holds"
    );
    Ok(())
}

#[tokio::test]
async fn a_member_with_a_second_route_survives_a_revocation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    // bob is in readers, which is in both left and right, both of which the document holds.
    let readers = ctx.group(&alice, "readers").await?;
    let left = ctx.group(&alice, "left").await?;
    let right = ctx.group(&alice, "right").await?;
    ctx.delegate(&alice, &bob, &readers, Read).await?;
    let readers_in_left = ctx.delegate(&alice, &readers, &left, Read).await?;
    ctx.delegate(&alice, &readers, &right, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &left, &design_doc, Read).await?;
    ctx.delegate(&alice, &right, &design_doc, Read).await?;

    ctx.revoke(&alice, &readers, &left).await?;
    assert!(
        !ctx.delegations_for(&alice, &left)
            .await?
            .contains(&readers_in_left),
        "the route that was cut is really gone, so the test turns on the other one"
    );

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "one of bob's two routes was cut, and the other still stands"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_one_route_leaves_the_other_document_alone() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let readers = ctx.group(&alice, "readers").await?;
    ctx.delegate(&alice, &bob, &readers, Read).await?;

    let left = ctx.group(&alice, "left").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &readers, &left, Read).await?;
    ctx.delegate(&alice, &left, &design_doc, Read).await?;

    let right = ctx.group(&alice, "right").await?;
    let notes = ctx.doc(&alice, "notes").await?;
    ctx.delegate(&alice, &readers, &right, Read).await?;
    ctx.delegate(&alice, &right, &notes, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches design_doc to begin with"
    );

    ctx.revoke(&alice, &readers, &left).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"one", &cast).await?,
        named(&["alice"]),
        "bob lost the route to design_doc"
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &notes, b"two", &cast).await?,
        named(&["alice", "bob"]),
        "and kept the one to notes, which went through a different group"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_group_from_one_document_leaves_the_other() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let engineering = ctx.group(&alice, "engineering").await?;
    ctx.delegate(&alice, &bob, &engineering, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;
    ctx.delegate(&alice, &engineering, &notes, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches design_doc to begin with"
    );

    ctx.revoke(&alice, &engineering, &design_doc).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"one", &cast).await?,
        named(&["alice"])
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &notes, b"two", &cast).await?,
        named(&["alice", "bob"]),
        "the same group still holds the other document"
    );
    Ok(())
}

#[tokio::test]
async fn a_direct_membership_survives_a_revocation_further_up() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let readers = ctx.group(&alice, "readers").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    ctx.delegate(&alice, &bob, &readers, Read).await?;
    let readers_in_engineering = ctx.delegate(&alice, &readers, &engineering, Read).await?;

    // The document holds engineering, and readers as well.
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;
    ctx.delegate(&alice, &readers, &design_doc, Read).await?;

    ctx.revoke(&alice, &readers, &engineering).await?;
    assert!(
        !ctx.delegations_for(&alice, &engineering)
            .await?
            .contains(&readers_in_engineering),
        "readers really did lose its membership in engineering"
    );

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "readers is still a member of the document in its own right"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_link_removes_everyone_below_it() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let innermost = ctx.group(&alice, "innermost").await?;
    let middle = ctx.group(&alice, "middle").await?;
    let outermost = ctx.group(&alice, "outermost").await?;
    ctx.delegate(&alice, &bob, &innermost, Read).await?;
    ctx.delegate(&alice, &innermost, &middle, Read).await?;
    ctx.delegate(&alice, &middle, &outermost, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &outermost, &design_doc, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    // Cut the middle of the chain, two levels above bob.
    ctx.revoke(&alice, &middle, &outermost).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "everything below the cut goes with it"
    );
    Ok(())
}

#[tokio::test]
async fn a_cycle_does_not_stop_an_addition_reaching_the_document() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    // Each group holds the other.
    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    ctx.delegate(&alice, &second, &first, Read).await?;
    ctx.delegate(&alice, &first, &second, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &first, &design_doc, Read).await?;

    ctx.delegate(&alice, &bob, &second, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches the document through second, which first holds"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_link_in_a_cycle_removes_access() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    ctx.delegate(&alice, &second, &first, Read).await?;
    ctx.delegate(&alice, &first, &second, Read).await?;
    ctx.delegate(&alice, &bob, &second, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &first, &design_doc, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    ctx.revoke(&alice, &second, &first).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "the other half of the cycle points away from the document, so it is not a route back"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_link_in_a_longer_cycle_removes_access() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    // first holds second holds third holds first.
    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    let third = ctx.group(&alice, "third").await?;
    ctx.delegate(&alice, &second, &first, Read).await?;
    ctx.delegate(&alice, &third, &second, Read).await?;
    ctx.delegate(&alice, &first, &third, Read).await?;
    ctx.delegate(&alice, &bob, &third, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &first, &design_doc, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    ctx.revoke(&alice, &second, &first).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "bob's only route to the document ran through the link that was cut"
    );
    Ok(())
}

#[tokio::test]
async fn breaking_a_cycle_from_both_sides_terminates() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    let third = ctx.group(&alice, "third").await?;
    ctx.delegate(&alice, &second, &first, Read).await?;
    ctx.delegate(&alice, &third, &second, Read).await?;
    ctx.delegate(&alice, &first, &third, Read).await?;
    ctx.delegate(&alice, &bob, &third, Read).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &first, &design_doc, Read).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    // Two revocations, each removing one edge of the cycle.
    ctx.revoke(&alice, &second, &first).await?;
    ctx.revoke(&alice, &first, &third).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "the cycle can be taken apart edge by edge without hanging or keeping bob"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_one_of_two_cyclic_groups_keeps_the_other_route() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    ctx.delegate(&alice, &second, &first, Read).await?;
    ctx.delegate(&alice, &first, &second, Read).await?;
    ctx.delegate(&alice, &bob, &first, Read).await?;

    // The document holds both halves of the cycle.
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let first_in_doc = ctx.delegate(&alice, &first, &design_doc, Read).await?;
    ctx.delegate(&alice, &second, &design_doc, Read).await?;

    ctx.revoke(&alice, &first, &design_doc).await?;
    assert!(
        !ctx.delegations_for(&alice, &design_doc)
            .await?
            .contains(&first_in_doc),
        "first is no longer a member of the document in its own right"
    );

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "second is still a member and holds first, so bob comes back round"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_member_keeps_the_members_they_admitted() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = ctx.individual("carol").await?;
    let dan = ctx.individual("dan").await?;
    let cast = [&alice, &carol, &dan];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;
    ctx.delegate(&alice, &carol, &engineering, Admin).await?;
    ctx.sync_all_unsent().await?;
    // Dan is in the group because carol put him there.
    ctx.delegate(&carol, &dan, &engineering, Read).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"before", &cast).await?,
        named(&["alice", "carol", "dan"])
    );

    ctx.revoke(&alice, &carol, &engineering).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice", "dan"]),
        "dan's delegation is re-issued rather than dropped with carol's"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "a cascading revocation keeps members admitted by the one it removes"]
async fn a_cascading_revocation_removes_the_members_they_admitted() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = ctx.individual("carol").await?;
    let dan = ctx.individual("dan").await?;
    let cast = [&alice, &carol, &dan];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;
    ctx.delegate(&alice, &carol, &engineering, Admin).await?;
    ctx.sync_all_unsent().await?;
    ctx.delegate(&carol, &dan, &engineering, Read).await?;
    ctx.sync_all_unsent().await?;

    ctx.revoke_cascading(&alice, &carol, &engineering).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, &design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "dan was only ever in the group because of carol's delegation"
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_member_is_listed_with_what_they_lost() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;

    let engineering = ctx.group(&alice, "engineering").await?;
    ctx.delegate(&alice, &bob, &engineering, Edit).await?;
    ctx.delegate(&alice, &carol, &engineering, Read).await?;

    assert!(
        ctx.revoked_members_of(&engineering).await?.is_empty(),
        "nobody has been revoked yet"
    );

    ctx.revoke(&alice, &bob, &engineering).await?;

    assert_eq!(
        ctx.revoked_members_of(&engineering).await?.get("bob"),
        Some(&Edit),
        "bob is listed at the level his delegation had conveyed"
    );
    assert_eq!(
        ctx.revoked_members_of(&engineering).await?.get("carol"),
        None,
        "and carol, who is still a member, is not listed"
    );
    assert_eq!(
        ctx.transitive_members_of(&engineering).await?.get("bob"),
        None,
        "the two lists do not overlap"
    );
    Ok(())
}

#[tokio::test]
async fn a_member_who_was_revoked_and_admitted_again_is_not_listed() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;

    let engineering = ctx.group(&alice, "engineering").await?;
    ctx.delegate(&alice, &bob, &engineering, Edit).await?;
    ctx.revoke(&alice, &bob, &engineering).await?;
    assert_eq!(
        ctx.revoked_members_of(&engineering).await?.get("bob"),
        Some(&Edit)
    );

    ctx.delegate(&alice, &bob, &engineering, Read).await?;

    assert_eq!(
        ctx.revoked_members_of(&engineering).await?.get("bob"),
        None,
        "he is a member again, so he is not a revoked member"
    );
    assert_eq!(
        ctx.transitive_members_of(&engineering).await?.get("bob"),
        Some(&Read),
        "at the level he was admitted at the second time"
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_member_is_listed_at_the_best_level_they_held() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;

    // Two delegations to the same person, at different levels.
    let engineering = ctx.group(&alice, "engineering").await?;
    ctx.delegate(&alice, &bob, &engineering, Read).await?;
    ctx.delegate(&alice, &bob, &engineering, Admin).await?;

    ctx.revoke(&alice, &bob, &engineering).await?;

    assert_eq!(
        ctx.revoked_members_of(&engineering).await?.get("bob"),
        Some(&Admin),
        "the level reported is the best one he lost, not whichever revocation came first"
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_member_of_a_document_is_listed_too() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Edit).await?;
    ctx.revoke(&alice, &bob, &design_doc).await?;

    assert_eq!(
        ctx.revoked_members_of(&design_doc).await?.get("bob"),
        Some(&Edit),
        "a document answers this the same way a group does"
    );
    Ok(())
}
