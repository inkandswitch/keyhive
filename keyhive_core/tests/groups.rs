//! Membership through groups: routes, attenuation along a chain, and who may
//! extend or cut one, asked of Keyline through `Keyhive`.

use keyhive_core::{
    principal::group::{id::GroupId, RevokeMemberError},
    test_utils::{Instance, TestContext, TestError, TestResult as Result},
};
use keyhive_crypto::id::Id;
use keyline::{
    certificate::Certificate,
    delegation::Delegation,
    power::Power::{self, Admin, Edit, Read},
};
use std::collections::BTreeMap;

async fn members(who: &Instance, group: GroupId) -> Result<BTreeMap<Id, Power>> {
    Ok(who.reachable_members(group).await?)
}

/// `outer --Admin--> middle --Read--> a --Admin--> b --Admin--> carol`, all
/// written by alice, who generated every group. Carol may only read `outer`,
/// but has admin over every link below the read delegation into `a`.
struct WeakestLinkChain {
    ctx: TestContext,
    alice: Instance,
    carol: Instance,
    outer: GroupId,
}

async fn weakest_link_chain() -> Result<WeakestLinkChain> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = ctx.individual("carol").await?;
    let outer = ctx.group(&alice, "outer").await?;
    let middle = ctx.group(&alice, "middle").await?;
    let a = ctx.group(&alice, "a").await?;
    let b = ctx.group(&alice, "b").await?;
    alice.add_member(middle, outer, Admin).await?;
    alice.add_member(a, middle, Read).await?;
    alice.add_member(b, a, Admin).await?;
    alice.add_member(carol.id(), b, Admin).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        members(&carol, outer).await?.get(&carol.id().into()),
        Some(&Read),
        "carol reads the outer group and no more"
    );
    Ok(WeakestLinkChain {
        ctx,
        alice,
        carol,
        outer,
    })
}

#[tokio::test]
async fn a_group_lists_its_creator_and_no_one_else() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let g0 = ctx.group(&alice, "g0").await?;
    assert_eq!(
        members(&alice, g0).await?,
        BTreeMap::from([(alice.id().into(), Admin)])
    );
    Ok(())
}

/// Reaching someone twice, once as an admin and once through a group that
/// only reads, does not demote them.
#[tokio::test]
async fn the_best_route_counts() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let inner = ctx.group(&alice, "inner").await?;
    let outer = ctx.group(&alice, "outer").await?;
    alice.add_member(inner, outer, Read).await?;
    assert_eq!(
        members(&alice, outer).await?.get(&alice.id().into()),
        Some(&Admin),
        "an admin who is also in a reader group is still an admin"
    );
    Ok(())
}

#[tokio::test]
async fn the_best_route_counts_through_a_nested_group() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = ctx.individual("carol").await?;
    let inner = ctx.group(&alice, "inner").await?;
    let admin_route = ctx.group(&alice, "admin_route").await?;
    let read_route = ctx.group(&alice, "read_route").await?;
    let outer = ctx.group(&alice, "outer").await?;
    for middle in [admin_route, read_route] {
        alice.add_member(inner, middle, Admin).await?;
    }
    alice.add_member(admin_route, outer, Admin).await?;
    alice.add_member(read_route, outer, Read).await?;
    alice.add_member(carol.id(), inner, Admin).await?;
    assert_eq!(
        members(&alice, outer).await?.get(&carol.id().into()),
        Some(&Admin),
        "the admin route to the inner group is the one that counts"
    );
    Ok(())
}

/// A member's power is capped by their own delegation and by the group's
/// power here, whichever is weaker.
#[tokio::test]
async fn a_member_is_capped_by_the_weaker_of_their_link_and_the_groups() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let inner = ctx.group(&alice, "inner").await?;
    let outer = ctx.group(&alice, "outer").await?;
    alice.add_member(inner, outer, Edit).await?;
    alice.add_member(bob.id(), inner, Admin).await?;
    alice.add_member(carol.id(), inner, Read).await?;

    let outer_members = members(&alice, outer).await?;
    assert_eq!(
        outer_members.get(&alice.id().into()),
        Some(&Admin),
        "alice is admin of the outer group directly"
    );
    assert_eq!(
        outer_members.get(&bob.id().into()),
        Some(&Edit),
        "bob is admin of the inner group, which can only edit this one"
    );
    assert_eq!(
        outer_members.get(&carol.id().into()),
        Some(&Read),
        "carol has only read for the inner group, so she only has read for this one"
    );
    Ok(())
}

#[tokio::test]
async fn a_chain_is_as_strong_as_its_weakest_link_at_the_head() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let carol = ctx.individual("carol").await?;
    let outer = ctx.group(&alice, "outer").await?;
    let middle = ctx.group(&alice, "middle").await?;
    let inner = ctx.group(&alice, "inner").await?;
    alice.add_member(middle, outer, Read).await?;
    alice.add_member(inner, middle, Admin).await?;
    alice.add_member(carol.id(), inner, Admin).await?;
    assert_eq!(
        members(&alice, outer).await?.get(&carol.id().into()),
        Some(&Read),
        "the chain is only as strong as the read delegation at its head"
    );
    Ok(())
}

#[tokio::test]
async fn granting_beyond_the_weakest_link_is_refused() -> Result<()> {
    let WeakestLinkChain {
        mut ctx,
        carol,
        outer,
        ..
    } = weakest_link_chain().await?;
    let dan = ctx.individual("dan").await?;
    ctx.sync_all_unsent().await?;

    match carol
        .add_member(dan.id(), outer, Admin)
        .await
        .map_err(TestError::from)
    {
        Err(TestError::Escalation { wanted, held }) => {
            assert_eq!((wanted, held), (Admin, Read));
        }
        other => panic!("a reader made someone else an admin: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn revoking_beyond_the_weakest_link_is_refused() -> Result<()> {
    let WeakestLinkChain {
        mut ctx,
        alice,
        carol,
        outer,
    } = weakest_link_chain().await?;
    let erin = ctx.individual("erin").await?;
    alice.add_member(erin.id(), outer, Admin).await?;
    ctx.sync_all_unsent().await?;

    match carol
        .revoke_member(erin.id(), true, outer)
        .await
        .map_err(TestError::from)
    {
        Err(TestError::NoAuthority) => {}
        other => panic!("a reader revoked an admin: {other:?}"),
    }
    assert_eq!(
        members(&alice, outer).await?.get(&erin.id().into()),
        Some(&Admin),
        "erin is still an admin of the group"
    );
    Ok(())
}

/// A delegation signed directly, past the API's refusal, cannot convey more
/// than its issuer holds: Keyline attenuates it to the issuer's power.
#[tokio::test]
async fn a_delegation_beyond_the_weakest_link_is_attenuated() -> Result<()> {
    let WeakestLinkChain {
        mut ctx,
        alice,
        carol,
        outer,
    } = weakest_link_chain().await?;
    let dan = ctx.individual("dan").await?;
    let forged = carol
        .sign_certificate(&Delegation::new(Id::from(dan.id()), Id::from(outer), Admin))
        .await?;
    alice
        .receive_certificate(Certificate::Delegation(forged.signed().clone()))
        .await
        .map_err(|e| TestError::Other(e.to_string()))?;
    assert_eq!(
        members(&alice, outer).await?.get(&dan.id().into()),
        Some(&Read),
        "dan gets what carol holds, not what she claimed"
    );
    Ok(())
}

/// `g0` is administered by alice; `g1` by alice and `g0`; `g2` by bob and
/// `g0`; `g3` by `g1` and `g2`.
#[tokio::test]
async fn membership_is_transitive_through_shared_parents() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    ctx.sync_all_unsent().await?;
    let g0 = ctx.group(&alice, "g0").await?;
    let g1 = alice.generate_group(vec![g0.into()]).await?;
    let g2 = alice
        .generate_group(vec![bob.id().into(), g0.into()])
        .await?;
    let g3 = alice.generate_group(vec![g1.into(), g2.into()]).await?;

    let ids = |m: BTreeMap<Id, Power>| m.into_keys().collect::<Vec<_>>();
    let mut expected = vec![alice.id().into(), g0.into()];
    expected.sort();
    assert_eq!(ids(members(&alice, g1).await?), expected, "g1");

    let mut expected = vec![alice.id().into(), bob.id().into(), g0.into()];
    expected.sort();
    assert_eq!(ids(members(&alice, g2).await?), expected, "g2");

    let mut expected = vec![
        alice.id().into(),
        bob.id().into(),
        g0.into(),
        g1.into(),
        g2.into(),
    ];
    expected.sort();
    assert_eq!(ids(members(&alice, g3).await?), expected, "g3");
    Ok(())
}

/// A cycle of ten groups: each administers the next, and the last
/// administers the first. Everyone on it is a member of every group.
#[tokio::test]
async fn membership_terminates_on_a_cycle() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    ctx.sync_all_unsent().await?;
    let g0 = ctx.group(&alice, "g0").await?;
    let g1 = alice.generate_group(vec![bob.id().into()]).await?;
    let mut chain = vec![g1];
    for _ in 2..10 {
        let previous = *chain.last().expect("the chain starts with g1");
        chain.push(alice.generate_group(vec![previous.into()]).await?);
    }
    let g9 = *chain.last().expect("ten groups");
    alice.add_member(g9, g0, Admin).await?;

    let g0_members = members(&alice, g0).await?;
    assert!(g0_members.contains_key(&alice.id().into()));
    assert!(g0_members.contains_key(&bob.id().into()));
    for g in &chain {
        assert!(g0_members.contains_key(&Id::from(*g)), "{g:?}");
    }
    assert_eq!(g0_members.len(), 11, "alice, bob, and g1 to g9");
    Ok(())
}

#[tokio::test]
async fn an_added_member_reaches_every_group_above() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let owner = ctx.individual("owner").await?;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    ctx.sync_all_unsent().await?;
    let g0 = ctx.group(&owner, "g0").await?;
    let g1 = owner
        .generate_group(vec![alice.id().into(), bob.id().into(), g0.into()])
        .await?;
    let g2 = owner.generate_group(vec![g1.into()]).await?;
    owner.add_member(carol.id(), g0, Edit).await?;

    assert_eq!(
        members(&owner, g0).await?,
        BTreeMap::from([(owner.id().into(), Admin), (carol.id().into(), Edit)])
    );
    let g2_members = members(&owner, g2).await?;
    for (who, power) in [
        (Id::from(owner.id()), Admin),
        (alice.id().into(), Admin),
        (bob.id().into(), Admin),
        (carol.id().into(), Edit),
        (g0.into(), Admin),
        (g1.into(), Admin),
    ] {
        assert_eq!(g2_members.get(&who), Some(&power), "{who:?}");
    }
    assert_eq!(g2_members.len(), 6);
    Ok(())
}

/// Bob, admitted by alice, admits carol, who admits dan. Revoking bob with
/// adoption keeps carol and dan; revoking carol without it cuts off everyone
/// she admitted; revoking oneself leaves.
#[tokio::test]
async fn revocation_adopts_or_cascades() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let dan = ctx.individual("dan").await?;
    let g1 = ctx.group(&alice, "g1").await?;

    alice.add_member(bob.id(), g1, Edit).await?;
    ctx.sync_all_unsent().await?;
    bob.add_member(carol.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;
    carol.add_member(dan.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;
    assert_eq!(members(&alice, g1).await?.len(), 4);

    alice.revoke_member(bob.id(), true, g1).await?;
    let after_bob = members(&alice, g1).await?;
    assert!(!after_bob.contains_key(&bob.id().into()), "bob is out");
    assert!(after_bob.contains_key(&carol.id().into()), "carol is kept");
    assert!(after_bob.contains_key(&dan.id().into()), "and so is dan");
    ctx.sync_all_unsent().await?;

    carol.add_member(bob.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;
    assert!(members(&alice, g1).await?.contains_key(&bob.id().into()));

    alice.revoke_member(carol.id(), false, g1).await?;
    let after_carol = members(&alice, g1).await?;
    assert!(
        !after_carol.contains_key(&carol.id().into()),
        "carol is out"
    );
    assert!(
        !after_carol.contains_key(&dan.id().into()),
        "and dan, whom she admitted"
    );
    assert!(
        !after_carol.contains_key(&bob.id().into()),
        "and bob, whom she admitted back"
    );

    alice.revoke_member(alice.id(), false, g1).await?;
    assert!(!members(&alice, g1).await?.contains_key(&alice.id().into()));
    Ok(())
}

/// Re-adding a member re-issues past every earlier revocation in turn, not
/// only the first: the third grant is a live certificate, not a copy of the
/// second, which was revoked.
#[tokio::test]
async fn a_member_can_be_readmitted_any_number_of_times() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let g1 = ctx.group(&alice, "g1").await?;

    for round in 0..3 {
        alice.add_member(bob.id(), g1, Read).await?;
        assert_eq!(
            members(&alice, g1).await?.get(&bob.id().into()),
            Some(&Read),
            "bob is in after grant {round}"
        );
        alice.revoke_member(bob.id(), false, g1).await?;
        assert!(!members(&alice, g1).await?.contains_key(&bob.id().into()));
    }
    Ok(())
}

/// A member below Admin revokes only the delegations it issued: another
/// admin's grant to the same member survives, and so does the member.
#[tokio::test]
async fn a_member_below_admin_revokes_only_its_own_grant() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let g1 = ctx.group(&alice, "g1").await?;

    alice.add_member(bob.id(), g1, Edit).await?;
    alice.add_member(carol.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;
    bob.add_member(carol.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;

    let update = bob.revoke_member(carol.id(), false, g1).await?;
    assert_eq!(update.revocations().len(), 1, "only bob's own grant");
    assert_eq!(
        members(&bob, g1).await?.get(&carol.id().into()),
        Some(&Read),
        "alice's grant keeps carol in"
    );
    Ok(())
}

/// Revoking someone who reaches the group only through another group is
/// refused: there is no delegation of theirs to revoke here.
#[tokio::test]
async fn revoking_an_indirect_member_is_refused() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let outer = ctx.group(&alice, "outer").await?;
    let inner = ctx.group(&alice, "inner").await?;
    alice.add_member(inner, outer, Read).await?;
    alice.add_member(bob.id(), inner, Read).await?;

    let result = alice.revoke_member(bob.id(), true, outer).await;
    assert!(
        matches!(result, Err(RevokeMemberError::NotADirectMember(id)) if id == Id::from(bob.id())),
        "{result:?}"
    );
    assert_eq!(
        members(&alice, outer).await?.get(&bob.id().into()),
        Some(&Read),
        "and bob keeps his access through inner"
    );
    Ok(())
}

/// Adoption grants no more than the revoker holds: bob, at Edit, adopts the
/// Admin member carol admitted at Edit.
#[tokio::test]
async fn adoption_is_capped_at_the_revokers_power() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let dan = ctx.individual("dan").await?;
    let g1 = ctx.group(&alice, "g1").await?;

    alice.add_member(bob.id(), g1, Edit).await?;
    alice.add_member(carol.id(), g1, Admin).await?;
    ctx.sync_all_unsent().await?;
    bob.add_member(carol.id(), g1, Read).await?;
    carol.add_member(dan.id(), g1, Admin).await?;
    ctx.sync_all_unsent().await?;

    let update = bob.revoke_member(carol.id(), true, g1).await?;
    let adopted: Vec<Power> = update
        .redelegations()
        .iter()
        .map(|d| d.payload().power)
        .collect();
    assert_eq!(adopted, vec![Edit], "dan is adopted at bob's power");
    Ok(())
}

/// Documents are Keyline subjects too, but not groups.
#[tokio::test]
async fn a_document_is_not_a_group() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let g1 = ctx.group(&alice, "g1").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    assert!(alice.has_group(g1).await?);
    assert!(!alice.has_group(GroupId::new(Id::from(design_doc))).await?);
    Ok(())
}

/// Adoption re-issues only the grants the removed member made to others: a
/// member the revoker admitted itself keeps its own grant, and the removed
/// member's grant to the revoker is not re-issued to the revoker.
#[tokio::test]
async fn adoption_reissues_only_the_removed_members_grants() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let dan = ctx.individual("dan").await?;
    let eve = ctx.individual("eve").await?;
    let g1 = ctx.group(&alice, "g1").await?;

    alice.add_member(bob.id(), g1, Admin).await?;
    alice.add_member(eve.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;
    bob.add_member(dan.id(), g1, Read).await?;
    bob.add_member(alice.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;

    let update = alice.revoke_member(bob.id(), true, g1).await?;
    let adopted: Vec<Id> = update
        .redelegations()
        .iter()
        .map(|d| d.payload().audience)
        .collect();
    assert_eq!(
        adopted,
        vec![Id::from(dan.id())],
        "only bob's grant to dan is adopted"
    );
    Ok(())
}

/// An adoption identical to a delegation revoked earlier is re-issued past
/// that revocation, so the adopted member keeps access.
#[tokio::test]
async fn adoption_reissues_past_an_earlier_revocation() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let g1 = ctx.group(&alice, "g1").await?;

    alice.add_member(carol.id(), g1, Read).await?;
    alice.revoke_member(carol.id(), false, g1).await?;
    alice.add_member(bob.id(), g1, Admin).await?;
    ctx.sync_all_unsent().await?;
    bob.add_member(carol.id(), g1, Read).await?;
    ctx.sync_all_unsent().await?;

    // Adopting carol re-creates alice's revoked grant to her, byte for byte.
    let update = alice.revoke_member(bob.id(), true, g1).await?;
    assert!(
        update
            .redelegations()
            .iter()
            .all(|d| d.payload().citation.is_some()),
        "the adoption cites the earlier revocation"
    );
    assert_eq!(
        members(&alice, g1).await?.get(&carol.id().into()),
        Some(&Read)
    );
    Ok(())
}
