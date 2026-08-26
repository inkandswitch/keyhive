use keyhive_core::{
    access::Access::{Admin, Edit, Read},
    principal::document::id::DocumentId,
    test_utils::{AddMemberUpdateExt, Instance, TestContext, TestError, TestResult as Result},
};
use std::collections::BTreeSet;

/// Write new content and report which of `cast` can read it.
///
/// Reading content written after a change is the behaviour behind "is this individual in
/// the document's key group?", which is what these tests are about.
async fn readers_after_writing(
    ctx: &mut TestContext,
    author: &Instance,
    doc: DocumentId,
    content: &[u8],
    cast: &[&Instance],
) -> Result<BTreeSet<String>> {
    let ct = ctx.encrypt(author, doc, content).await?;
    ctx.sync_all_unsent().await?;
    let mut readers = BTreeSet::new();
    for who in cast {
        let reads = match who
            .can_decrypt_content(doc, &ct)
            .await
            .map_err(TestError::from)
        {
            Ok(yes) => yes,
            // Everything has just been synced, so an instance that still does not hold the
            // document was not entitled to it, which is the same answer for this question as
            // holding no key for it. This is the one place the two are deliberately merged.
            Err(TestError::NotSynced(_)) => false,
            Err(other) => return Err(other),
        };
        if reads {
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
    // Revoking a group from a document removes the correct individuals from the
    // document's key group, including nested group members, without removing
    // individuals who are still reachable via other paths (direct membership).
    //
    // Setup:
    //   design_doc has members:
    //     - alice (owner/active)
    //     - bob (direct individual member)
    //     - Group outer:
    //       - carol (individual)
    //       - Group inner:
    //         - dave (individual)
    //         - eve (individual)
    //     - frank, a direct member of design_doc and also a member of inner
    //
    // Revoke outer from design_doc -> carol, dave, and eve should be removed from
    // design_doc's key group. bob and alice should remain (direct members). frank
    // should remain because he is still a direct member of design_doc even though
    // he was also in inner.
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
        alice.add_member(who.id(), inner, Read, &[]).await?;
    }
    alice.add_member(carol.id(), outer, Read, &[]).await?;
    alice.add_member(inner, outer, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    alice.add_member(outer, design_doc, Read, &[]).await?;
    alice.add_member(frank.id(), design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob", "carol", "dave", "eve", "frank"]),
        "everyone reaches the document to begin with"
    );

    alice.revoke_member(outer, true, design_doc).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob", "frank"]),
        "carol, dave and eve had only the group route; frank also has a direct one"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_subgroup_removes_only_the_members_it_brought() -> Result<()> {
    // Revoking a sub-group from a parent group correctly removes the sub-group's
    // individuals from the key groups of documents that contain the parent group,
    // without removing individuals still reachable via other paths.
    //
    // Setup:
    //   Group outer:
    //     - alice (owner, auto-added by generate_group)
    //     - carol (individual)
    //     - Group inner:
    //       - alice (owner, auto-added)
    //       - dave (individual)
    //       - eve (individual)
    //       - frank (individual)
    //
    //   design_doc has members:
    //     - alice (owner/active)
    //     - bob (direct individual)
    //     - outer
    //     - frank (direct individual)
    //
    // Revoke inner from outer -> dave and eve should be removed from design_doc's
    // key group. alice, bob, carol, and frank should remain.
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
        alice.add_member(who.id(), inner, Read, &[]).await?;
    }
    alice.add_member(carol.id(), outer, Read, &[]).await?;
    alice.add_member(inner, outer, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    alice.add_member(outer, design_doc, Read, &[]).await?;
    alice.add_member(frank.id(), design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob", "carol", "dave", "eve", "frank"]),
        "everyone reaches the document to begin with"
    );

    alice.revoke_member(inner, true, outer).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob", "carol", "frank"]),
        "dave and eve came in through inner; carol was outer's own member"
    );
    Ok(())
}

#[tokio::test]
async fn a_change_in_a_group_that_holds_a_document_leaves_the_document_alone() -> Result<()> {
    // Revoking a sub-group from a group should not affect the key group of a doc
    // that is a member of that group. Adding design_doc to engineering grants
    // design_doc access to engineering, not engineering's members access to
    // design_doc.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let dave = ctx.individual("dave").await?;
    let cast = [&alice, &bob, &dave];

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(bob.id(), design_doc, Read, &[]).await?;

    let staff = ctx.group(&alice, "staff").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(dave.id(), staff, Read, &[]).await?;
    alice.add_member(design_doc, engineering, Read, &[]).await?;
    alice.add_member(staff, engineering, Read, &[]).await?;

    let before = readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?;
    assert_eq!(
        before,
        named(&["alice", "bob"]),
        "dave reaches engineering, which the document is a member of, so not the document"
    );

    alice.revoke_member(staff, true, engineering).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        before,
        "a revocation one level above the document does not touch its members"
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_member_to_a_group_reaches_the_documents_it_holds() -> Result<()> {
    // Adding an individual to a group should propagate key group adds to docs
    // that contain the group as a member. If engineering is a member of
    // design_doc, then adding bob to engineering should add bob to design_doc's
    // key group.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice"]),
        "bob is in nothing yet"
    );

    alice.add_member(bob.id(), engineering, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "joining the group joined the document's key group"
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_member_deep_in_a_chain_reaches_the_document() -> Result<()> {
    // innermost in middle in outermost in design_doc. Adding bob to innermost
    // should propagate to design_doc's key group.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    // carol was not delegated anything, so use her to check access did not widen.
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &bob, &carol];

    let innermost = ctx.group(&alice, "innermost").await?;
    let middle = ctx.group(&alice, "middle").await?;
    let outermost = ctx.group(&alice, "outermost").await?;
    alice.add_member(innermost, middle, Read, &[]).await?;
    alice.add_member(middle, outermost, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(outermost, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice"]),
        "bob is in none of the three groups yet"
    );

    alice.add_member(bob.id(), innermost, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "three groups deep still reaches the document"
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_member_to_a_group_reaches_every_document_it_holds() -> Result<()> {
    // engineering is a member of both design_doc and notes. Adding bob to
    // engineering should add bob to both of their key groups.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    // carol was not delegated anything, so use her to check access did not widen.
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &bob, &carol];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice.add_member(engineering, notes, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice"]),
        "bob is in the group holding neither document yet"
    );

    alice.add_member(bob.id(), engineering, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"one", &cast).await?,
        named(&["alice", "bob"])
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, notes, b"two", &cast).await?,
        named(&["alice", "bob"]),
        "one addition, every document the group holds"
    );
    Ok(())
}

#[tokio::test]
async fn a_member_with_a_second_route_survives_a_revocation() -> Result<()> {
    // readers is a member of both left and right, both in design_doc. bob is in
    // readers. Revoke readers from left -> bob should still be in design_doc's key
    // group (reachable via right).
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    // carol was not delegated anything, so use her to check access did not widen.
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &bob, &carol];

    let readers = ctx.group(&alice, "readers").await?;
    let left = ctx.group(&alice, "left").await?;
    let right = ctx.group(&alice, "right").await?;
    alice.add_member(bob.id(), readers, Read, &[]).await?;
    let readers_in_left = alice.add_member(readers, left, Read, &[]).await?.summary();
    alice.add_member(readers, right, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(left, design_doc, Read, &[]).await?;
    alice.add_member(right, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches the document by both routes to begin with, and carol by neither"
    );

    alice.revoke_member(readers, true, left).await?;
    assert!(
        !ctx.delegations_for(&alice, left)
            .await?
            .contains(&readers_in_left),
        "the route that was cut is really gone, so the test turns on the other one"
    );

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "one of bob's two routes was cut, and the other still stands"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_one_route_leaves_the_other_document_alone() -> Result<()> {
    // readers in left in design_doc, and readers in right in notes. bob in readers.
    // Revoke readers from left -> bob loses design_doc, keeps notes.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let readers = ctx.group(&alice, "readers").await?;
    alice.add_member(bob.id(), readers, Read, &[]).await?;

    let left = ctx.group(&alice, "left").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(readers, left, Read, &[]).await?;
    alice.add_member(left, design_doc, Read, &[]).await?;

    let right = ctx.group(&alice, "right").await?;
    let notes = ctx.doc(&alice, "notes").await?;
    alice.add_member(readers, right, Read, &[]).await?;
    alice.add_member(right, notes, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches design_doc to begin with"
    );

    alice.revoke_member(readers, true, left).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"one", &cast).await?,
        named(&["alice"]),
        "bob lost the route to design_doc"
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, notes, b"two", &cast).await?,
        named(&["alice", "bob"]),
        "and kept the one to notes, which went through a different group"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_group_from_one_document_leaves_the_other() -> Result<()> {
    // engineering in design_doc and notes. bob in engineering. Revoke engineering
    // from design_doc -> bob loses design_doc, keeps notes.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let notes = ctx.doc(&alice, "notes").await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice.add_member(engineering, notes, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches design_doc to begin with"
    );

    alice.revoke_member(engineering, true, design_doc).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"one", &cast).await?,
        named(&["alice"])
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, notes, b"two", &cast).await?,
        named(&["alice", "bob"]),
        "the same group still holds the other document"
    );
    Ok(())
}

#[tokio::test]
async fn a_direct_membership_survives_a_revocation_further_up() -> Result<()> {
    // readers in engineering in design_doc, and also readers directly in
    // design_doc. bob in readers. Revoke readers from engineering -> bob still in
    // design_doc's key group (readers is a direct member of design_doc).
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    // carol was not delegated anything, so use her to check access did not widen.
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &bob, &carol];

    let readers = ctx.group(&alice, "readers").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    alice.add_member(bob.id(), readers, Read, &[]).await?;
    let readers_in_engineering = alice
        .add_member(readers, engineering, Read, &[])
        .await?
        .summary();

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice.add_member(readers, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches the document by both routes to begin with, and carol by neither"
    );

    alice.revoke_member(readers, true, engineering).await?;
    assert!(
        !ctx.delegations_for(&alice, engineering)
            .await?
            .contains(&readers_in_engineering),
        "readers really did lose its membership in engineering"
    );

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "readers is still a member of the document in its own right"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_link_removes_everyone_below_it() -> Result<()> {
    // innermost in middle in outermost in design_doc. bob in innermost. Revoke
    // middle from outermost -> bob (and middle, innermost's members) should be
    // removed from design_doc's key group.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let innermost = ctx.group(&alice, "innermost").await?;
    let middle = ctx.group(&alice, "middle").await?;
    let outermost = ctx.group(&alice, "outermost").await?;
    alice.add_member(bob.id(), innermost, Read, &[]).await?;
    alice.add_member(innermost, middle, Read, &[]).await?;
    alice.add_member(middle, outermost, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(outermost, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    alice.revoke_member(middle, true, outermost).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "everything below the cut goes with it"
    );
    Ok(())
}

#[tokio::test]
async fn a_cycle_does_not_stop_an_addition_reaching_the_document() -> Result<()> {
    // first contains second, second contains first (direct cycle). first is in
    // design_doc. bob in second -> bob should be in design_doc's key group
    // (reachable via second -> first -> design_doc).
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    // carol was not delegated anything, so use her to check access did not widen.
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &bob, &carol];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    alice.add_member(second, first, Read, &[]).await?;
    alice.add_member(first, second, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(first, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice"]),
        "bob is in neither half of the cycle yet"
    );

    alice.add_member(bob.id(), second, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches the document through second, which first holds"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_link_in_a_cycle_removes_access() -> Result<()> {
    // first <-> second cycle, first in design_doc. bob in second. Revoke second
    // from first -> bob should be removed. The doc reaches down through first, and
    // first no longer contains second after revocation. second still containing
    // first doesn't help: that means first's members can access second, not that
    // second can access design_doc.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    alice.add_member(second, first, Read, &[]).await?;
    alice.add_member(first, second, Read, &[]).await?;
    alice.add_member(bob.id(), second, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(first, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    alice.revoke_member(second, true, first).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "the other half of the cycle points away from the document, so it is not a route back"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_link_in_a_longer_cycle_removes_access() -> Result<()> {
    // first -> second -> third -> first indirect cycle. first in design_doc. bob in
    // third. Revoke second from first -> bob loses access. The doc reaches down
    // through first, and first no longer contains second. The remaining cycle edges
    // (second -> third -> first) don't help: the doc only reaches down through
    // first.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    let third = ctx.group(&alice, "third").await?;
    alice.add_member(second, first, Read, &[]).await?;
    alice.add_member(third, second, Read, &[]).await?;
    alice.add_member(first, third, Read, &[]).await?;
    alice.add_member(bob.id(), third, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(first, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    alice.revoke_member(second, true, first).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "bob's only route to the document ran through the link that was cut"
    );
    Ok(())
}

#[tokio::test]
async fn breaking_a_cycle_from_both_sides_terminates() -> Result<()> {
    // first -> second -> third -> first indirect cycle. first in design_doc. bob in
    // third. Revoke second from first AND first from third, so the cycle breaks. Only
    // first is still in design_doc directly. second and third lose access.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let cast = [&alice, &bob];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    let third = ctx.group(&alice, "third").await?;
    alice.add_member(second, first, Read, &[]).await?;
    alice.add_member(third, second, Read, &[]).await?;
    alice.add_member(first, third, Read, &[]).await?;
    alice.add_member(bob.id(), third, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(first, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"])
    );

    alice.revoke_member(second, true, first).await?;
    alice.revoke_member(first, true, third).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "the cycle can be taken apart edge by edge without hanging or keeping bob"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_one_of_two_cyclic_groups_keeps_the_other_route() -> Result<()> {
    // first <-> second cycle, both are direct members of design_doc. bob in first.
    // Revoke first from design_doc -> second is still a direct member of
    // design_doc, and second contains first, so bob is still reachable via
    // design_doc -> second -> first. bob should stay in design_doc's key group.
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    // carol was not delegated anything, so use her to check access did not widen.
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &bob, &carol];

    let first = ctx.group(&alice, "first").await?;
    let second = ctx.group(&alice, "second").await?;
    alice.add_member(second, first, Read, &[]).await?;
    alice.add_member(first, second, Read, &[]).await?;
    alice.add_member(bob.id(), first, Read, &[]).await?;

    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let first_in_doc = alice
        .add_member(first, design_doc, Read, &[])
        .await?
        .summary();
    alice.add_member(second, design_doc, Read, &[]).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "bob"]),
        "bob reaches the document to begin with, and carol does not"
    );

    alice.revoke_member(first, true, design_doc).await?;
    assert!(
        !ctx.delegations_for(&alice, design_doc)
            .await?
            .contains(&first_in_doc),
        "first is no longer a member of the document in its own right"
    );

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
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
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice
        .add_member(carol.id(), engineering, Admin, &[])
        .await?;
    ctx.sync_all_unsent().await?;
    // Dan is in the group because carol put him there.
    carol.add_member(dan.id(), engineering, Read, &[]).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "carol", "dan"])
    );

    alice.revoke_member(carol.id(), true, engineering).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice", "dan"]),
        "dan's delegation is re-issued rather than dropped with carol's"
    );
    Ok(())
}

#[tokio::test]
async fn a_cascading_revocation_removes_the_member_it_names() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = ctx.individual("carol").await?;
    let cast = [&alice, &carol];

    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice
        .add_member(carol.id(), engineering, Admin, &[])
        .await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"before", &cast).await?,
        named(&["alice", "carol"])
    );

    alice.revoke_member(carol.id(), false, engineering).await?;

    assert_eq!(
        ctx.named_access(alice.reachable_members(engineering).await?)
            .get("carol"),
        None,
        "carol is out of the group"
    );
    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
        named(&["alice"]),
        "and out of the document the group holds"
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
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice
        .add_member(carol.id(), engineering, Admin, &[])
        .await?;
    ctx.sync_all_unsent().await?;
    carol.add_member(dan.id(), engineering, Read, &[]).await?;
    ctx.sync_all_unsent().await?;

    alice.revoke_member(carol.id(), false, engineering).await?;

    assert_eq!(
        readers_after_writing(&mut ctx, &alice, design_doc, b"after", &cast).await?,
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
    alice.add_member(bob.id(), engineering, Edit, &[]).await?;
    alice.add_member(carol.id(), engineering, Read, &[]).await?;

    assert!(
        ctx.named(ctx.revoked_members_of(&alice, engineering).await?)
            .is_empty(),
        "nobody has been revoked yet"
    );

    alice.revoke_member(bob.id(), true, engineering).await?;

    let revoked = ctx.named(ctx.revoked_members_of(&alice, engineering).await?);
    assert_eq!(
        revoked.get("bob"),
        Some(&Edit),
        "bob is listed at the level his delegation had conveyed"
    );
    assert_eq!(
        revoked.get("carol"),
        None,
        "and carol, who is still a member, is not listed"
    );
    assert_eq!(
        ctx.named_access(alice.reachable_members(engineering).await?)
            .get("bob"),
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
    alice.add_member(bob.id(), engineering, Edit, &[]).await?;
    alice.revoke_member(bob.id(), true, engineering).await?;
    assert_eq!(
        ctx.named(ctx.revoked_members_of(&alice, engineering).await?)
            .get("bob"),
        Some(&Edit)
    );

    alice.add_member(bob.id(), engineering, Read, &[]).await?;

    assert_eq!(
        ctx.named(ctx.revoked_members_of(&alice, engineering).await?)
            .get("bob"),
        None,
        "he is a member again, so he is not a revoked member"
    );
    assert_eq!(
        ctx.named_access(alice.reachable_members(engineering).await?)
            .get("bob"),
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
    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    alice.add_member(bob.id(), engineering, Admin, &[]).await?;

    alice.revoke_member(bob.id(), true, engineering).await?;

    assert_eq!(
        ctx.named(ctx.revoked_members_of(&alice, engineering).await?)
            .get("bob"),
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

    alice.add_member(bob.id(), design_doc, Edit, &[]).await?;
    alice.revoke_member(bob.id(), true, design_doc).await?;

    assert_eq!(
        ctx.named(ctx.revoked_members_of(&alice, design_doc).await?)
            .get("bob"),
        Some(&Edit),
        "a document answers this the same way a group does"
    );
    Ok(())
}
