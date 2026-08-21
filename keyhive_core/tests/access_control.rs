mod facade;

use facade::{Result, TestContext, TestError};
use keyhive_core::access::Access::{self, Admin, Edit, Read, Relay};

#[tokio::test]
async fn a_group_member_reaches_the_groups_documents() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    ctx.delegate(&alice, &engineering, &design_doc, Edit)
        .await?;
    ctx.delegate(&alice, &bob, &engineering, Read).await?;

    assert_eq!(ctx.effective_access(&bob, &design_doc).await?, Some(Read));
    Ok(())
}

#[tokio::test]
async fn members_are_listed_with_their_effective_level() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Edit).await?;
    ctx.delegate(&alice, &carol, &design_doc, Read).await?;

    let members = ctx.transitive_members_of(&design_doc).await?;
    assert_eq!(members.get("bob"), Some(&Edit));
    assert_eq!(members.get("carol"), Some(&Read));
    Ok(())
}

#[tokio::test]
#[ignore = "fails on main; fixed by jtfm/cgka-authority; un-ignore when that lands"]
async fn attenuation_is_the_minimum_along_the_route() -> Result<()> {
    for a in [Relay, Read, Edit, Admin] {
        for b in [Relay, Read, Edit, Admin] {
            for c in [Relay, Read, Edit, Admin] {
                let mut ctx = TestContext::new().await;
                let alice = ctx.individual("alice").await?;
                let bob = ctx.individual("bob").await?;
                let design_doc = ctx.doc(&alice, "design_doc").await?;
                let outer = ctx.group(&alice, "outer").await?;
                let inner = ctx.group(&alice, "inner").await?;

                ctx.delegate(&alice, &outer, &design_doc, a).await?;
                ctx.delegate(&alice, &inner, &outer, b).await?;
                ctx.delegate(&alice, &bob, &inner, c).await?;

                assert_eq!(
                    ctx.effective_access(&bob, &design_doc).await?,
                    Some(a.min(b).min(c)),
                    "design_doc -{a:?}-> outer -{b:?}-> inner -{c:?}-> bob"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "fails on main; fixed by jtfm/cgka-authority; un-ignore when that lands"]
async fn relay_never_permits_decryption() -> Result<()> {
    for (doc_to_group, group_to_bob) in [
        (Relay, Read),
        (Relay, Edit),
        (Relay, Admin),
        (Read, Relay),
        (Read, Read),
    ] {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        let relays = ctx.group(&alice, "relays").await?;

        ctx.delegate(&alice, &relays, &design_doc, doc_to_group)
            .await?;
        ctx.delegate(&alice, &bob, &relays, group_to_bob).await?;

        let may_read = doc_to_group.min(group_to_bob) >= Read;
        let ct = ctx.encrypt(&alice, &design_doc, b"top secret").await?;
        ctx.sync_all_unsent().await?;

        assert_eq!(
            ctx.can_decrypt(&bob, &ct).await?,
            may_read,
            "decryption at {doc_to_group:?}/{group_to_bob:?}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "fails on main; fixed by jtfm/cgka-authority; un-ignore when that lands"]
async fn multi_route_resolution_is_deterministic() -> Result<()> {
    let mut answers: std::collections::BTreeMap<Option<Access>, usize> = Default::default();
    for round in 0..8 {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        let engineering = ctx.group(&alice, "engineering").await?;

        // Route 1: design_doc -Edit-> engineering -Admin-> bob, giving Edit.
        ctx.delegate(&alice, &engineering, &design_doc, Edit)
            .await?;
        ctx.delegate(&alice, &bob, &engineering, Admin).await?;
        // Route 2: design_doc -Read-> bob, giving Read.
        ctx.delegate(&alice, &bob, &design_doc, Read).await?;

        let access = ctx.effective_access(&bob, &design_doc).await?;
        answers.entry(access).or_insert(round);
    }
    assert_eq!(
        answers.len(),
        1,
        "more than one answer across eight graphs, with the round that gave each: {answers:?}"
    );
    assert_eq!(
        answers.into_keys().next().unwrap(),
        Some(Edit),
        "the better of the two routes"
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_member_cannot_read_new_content() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    let before = ctx.encrypt(&alice, &design_doc, b"first").await?;
    ctx.sync_all_unsent().await?;
    assert!(
        ctx.can_decrypt(&bob, &before).await?,
        "bob could read before"
    );

    ctx.revoke(&alice, &bob, &design_doc).await?;
    let after = ctx.encrypt(&alice, &design_doc, b"second").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(ctx.effective_access(&bob, &design_doc).await?, None);
    assert!(
        !ctx.can_decrypt(&bob, &after).await?,
        "cannot read new content"
    );
    Ok(())
}

#[tokio::test]
async fn two_replicas_agree_on_effective_access() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    ctx.delegate(&alice, &engineering, &design_doc, Edit)
        .await?;
    ctx.delegate(&alice, &bob, &engineering, Read).await?;
    ctx.delegate(&alice, &carol, &engineering, Admin).await?;
    ctx.sync_all_unsent().await?;

    for observer in [&alice, &bob, &carol] {
        assert_eq!(
            ctx.effective_access_seen_by(observer, &bob, &design_doc)
                .await?,
            Some(Read),
            "{} disagrees about bob",
            observer.name()
        );
    }
    Ok(())
}

/// A document can be a member of another document and access propagates.
#[tokio::test]
async fn admin_on_a_parent_doc_reaches_the_child_doc() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let account = ctx.doc(&alice, "account").await?;
    let project = ctx.doc(&alice, "project").await?;

    ctx.delegate(&alice, &account, &project, Admin).await?;
    ctx.delegate(&alice, &bob, &account, Admin).await?;

    assert_eq!(ctx.effective_access(&bob, &account).await?, Some(Admin));
    assert_eq!(ctx.effective_access(&bob, &project).await?, Some(Admin));
    Ok(())
}

#[tokio::test]
async fn a_transitive_admin_through_a_document_can_delegate() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let account = ctx.doc(&alice, "account").await?;
    let project = ctx.doc(&alice, "project").await?;

    ctx.delegate(&alice, &account, &project, Admin).await?;
    ctx.delegate(&alice, &bob, &account, Admin).await?;
    ctx.sync_all_unsent().await?;
    assert_eq!(
        ctx.effective_access(&bob, &project).await?,
        Some(Admin),
        "bob reaches project through account"
    );
    assert_eq!(
        ctx.effective_access(&bob, &account).await?,
        Some(Admin),
        "and account, which is where he holds it"
    );

    ctx.delegate(&bob, &carol, &project, Edit).await?;
    assert_eq!(
        ctx.effective_access_seen_by(&bob, &carol, &project).await?,
        Some(Edit),
        "bob delegated based on a route (through a doc) he does not hold directly"
    );

    ctx.sync_all_unsent().await?;
    assert_eq!(
        ctx.effective_access(&carol, &project).await?,
        Some(Edit),
        "and alice, who owns the document, honors it"
    );
    assert_eq!(
        ctx.effective_access(&carol, &account).await?,
        None,
        "carol was let into project, and that does not reach back up to account"
    );
    Ok(())
}

#[tokio::test]
async fn a_transitive_admin_through_a_group_can_delegate() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let project = ctx.doc(&alice, "project").await?;

    ctx.delegate(&alice, &engineering, &project, Admin).await?;
    ctx.delegate(&alice, &bob, &engineering, Admin).await?;
    ctx.sync_all_unsent().await?;
    assert_eq!(ctx.effective_access(&bob, &project).await?, Some(Admin));
    let members_of_the_group = ctx.transitive_members_of(&engineering).await?;
    assert_eq!(members_of_the_group.get("bob"), Some(&Admin));
    assert_eq!(
        members_of_the_group.get("carol"),
        None,
        "carol is not in the group to begin with"
    );

    ctx.delegate(&bob, &carol, &project, Edit).await?;
    assert_eq!(
        ctx.effective_access_seen_by(&bob, &carol, &project).await?,
        Some(Edit),
        "bob delegated on the strength of a route he does not hold directly"
    );

    ctx.sync_all_unsent().await?;
    assert_eq!(
        ctx.effective_access(&carol, &project).await?,
        Some(Edit),
        "bob delegated based on a route (through a group) he does not hold directly"
    );
    assert_eq!(
        ctx.transitive_members_of(&engineering).await?.get("carol"),
        None,
        "and being let into project does not put her in the group that holds it"
    );
    Ok(())
}

/// A group holds a document and the document holds the group. Reachability has to
/// terminate from either end and neither membership may be lost.
#[tokio::test]
async fn a_membership_cycle_still_resolves() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &engineering, Read).await?;
    ctx.delegate(&alice, &engineering, &design_doc, Read)
        .await?;
    ctx.delegate(&alice, &design_doc, &engineering, Read)
        .await?;

    assert_eq!(ctx.effective_access(&bob, &design_doc).await?, Some(Read));

    let of_the_document = ctx.transitive_members_of(&design_doc).await?;
    assert_eq!(
        of_the_document.get("bob"),
        Some(&Read),
        "bob reaches the document through the group, even when there's a cycle"
    );
    assert_eq!(
        of_the_document.get("engineering"),
        Some(&Read),
        "and the group is still a member of the document"
    );

    let of_the_group = ctx.transitive_members_of(&engineering).await?;
    assert_eq!(
        of_the_group.get("bob"),
        Some(&Read),
        "the walk terminates from the other end too"
    );
    assert_eq!(
        of_the_group.get("design_doc"),
        Some(&Read),
        "and the reverse edge is what makes it a cycle"
    );
    Ok(())
}

/// Alice creates a group, so she is its admin. Giving a document she owns a `Read`
/// membership in that group hands her a second, weaker route to it. Her own access must not
/// drop because of a route she gained.
#[tokio::test]
#[ignore = "a member's level comes from the last route explored, not the best one. Fix this."]
async fn an_attenuated_second_route_does_not_lower_reported_access() -> Result<()> {
    for _ in 0..5 {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let engineering = ctx.group(&alice, "engineering").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;

        assert_eq!(
            ctx.transitive_members_of(&engineering).await?.get("alice"),
            Some(&Admin),
            "alice created the group"
        );

        ctx.delegate(&alice, &design_doc, &engineering, Read)
            .await?;

        assert_eq!(
            ctx.transitive_members_of(&engineering).await?.get("alice"),
            Some(&Admin),
            "the weaker route took precedence over her own"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_reader_cannot_delegate_above_read() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;

    for access in [Edit, Admin] {
        match ctx.delegate(&bob, &carol, &design_doc, access).await {
            Err(TestError::Escalation { wanted, held }) => {
                assert_eq!(wanted, access);
                assert_eq!(held, Read);
            }
            other => panic!("expected an escalation refusal, got {other:?}"),
        }
    }
    assert_eq!(ctx.effective_access(&carol, &design_doc).await?, None);
    Ok(())
}

#[tokio::test]
async fn a_revoked_member_cannot_delegate_or_revoke() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let mallory = ctx.individual("mallory").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &mallory, &design_doc, Read).await?;
    ctx.sync_all_unsent().await?;
    ctx.revoke(&alice, &mallory, &design_doc).await?;
    ctx.sync_all_unsent().await?;

    assert!(
        matches!(
            ctx.delegate(&mallory, &carol, &design_doc, Read).await,
            Err(TestError::NoAuthority)
        ),
        "a revoked member may not issue a delegation"
    );
    assert!(
        matches!(
            ctx.revoke(&mallory, &alice, &design_doc).await,
            Err(TestError::NoAuthority)
        ),
        "or a revocation"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_group_removes_only_those_who_needed_it() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    ctx.delegate(&alice, &engineering, &design_doc, Edit)
        .await?;
    ctx.delegate(&alice, &bob, &engineering, Edit).await?;
    ctx.delegate(&alice, &carol, &engineering, Edit).await?;
    ctx.delegate(&alice, &carol, &design_doc, Read).await?;

    assert_eq!(ctx.effective_access(&bob, &design_doc).await?, Some(Edit));
    // Carol has two routes here, Edit through the group and Read directly. Her exact level
    // therefore depends on the rule for combining multiple routes, which has its own test.
    // This test is about revocation, so it only checks that she has some access, not which
    // level.
    assert!(ctx.effective_access(&carol, &design_doc).await?.is_some());

    ctx.revoke(&alice, &engineering, &design_doc).await?;

    let after = ctx.encrypt(&alice, &design_doc, b"post-revocation").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(ctx.effective_access(&bob, &design_doc).await?, None);
    assert!(
        !ctx.can_decrypt(&bob, &after).await?,
        "bob had only the group route"
    );

    assert_eq!(ctx.effective_access(&carol, &design_doc).await?, Some(Read));
    assert!(
        ctx.can_decrypt(&carol, &after).await?,
        "carol kept her direct route"
    );
    Ok(())
}
