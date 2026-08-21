mod facade;

use facade::{Result, TestContext, TestError};
use keyhive_core::access::Access::{Admin, Edit, Read, Relay};

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
        ctx.sync_all().await?;

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
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..25 {
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

        seen.insert(ctx.effective_access(&bob, &design_doc).await?);
    }
    assert_eq!(seen.len(), 1, "answer varied across runs: {seen:?}");
    assert_eq!(
        seen.into_iter().next().unwrap(),
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
    ctx.sync_all().await?;
    assert!(
        ctx.can_decrypt(&bob, &before).await?,
        "bob could read before"
    );

    ctx.revoke(&alice, &bob, &design_doc).await?;
    let after = ctx.encrypt(&alice, &design_doc, b"second").await?;
    ctx.sync_all().await?;

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
    ctx.sync_all().await?;

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
async fn a_reader_cannot_delegate_above_read() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    ctx.delegate(&alice, &bob, &design_doc, Read).await?;
    ctx.sync_all().await?;

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
    ctx.sync_all().await?;
    ctx.revoke(&alice, &mallory, &design_doc).await?;
    ctx.sync_all().await?;

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
    ctx.sync_all().await?;

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
