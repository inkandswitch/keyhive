use keyhive_core::{
    access::Access::{self, Admin, Edit, Read, Relay},
    keyhive::NotFound,
    test_utils::{TestContext, TestError, TestResult as Result},
};

#[tokio::test]
async fn a_group_member_reaches_the_groups_documents() -> Result<()> {
    // Scenario:
    // Alice and Bob are separate Keyhive agents
    //
    // 1. Alice registers Bob
    // 2. Alice creates a new group that she owns
    // 3. Alice adds Bob to the group
    // 4. Alice creates a new document that the group controls
    //
    // Both Alice and Bob should be able to access the document
    //
    // ┌─────────────────────┐   ┌─────────────────────┐
    // │                     │   │                     │
    // │        Alice        │   │         Bob         │
    // │                     │   │                     │
    // └─────────────────────┘   └─────────────────────┘
    //            ▲                         ▲
    //            │                         │
    //            │                         │
    //            │ ┌─────────────────────┐ │
    //            │ │                     │ │
    //            └─│        Group        │─┘
    //              │                     │
    //              └─────────────────────┘
    //                         ▲
    //                         │
    //                         │
    //              ┌─────────────────────┐
    //              │                     │
    //              │         Doc         │
    //              │                     │
    //              └─────────────────────┘
    //
    // Scenario:
    // Alice creates a doc and a group.
    // Alice gives the group Edit access to the doc.
    // Alice adds A and B with Edit access to the group.
    // A encrypts content to the doc, B decrypts it.
    //
    // ┌─────────────────────┐
    // │        Alice        │  (owner)
    // └─────────────────────┘
    //            │
    //            ▼
    // ┌─────────────────────┐
    // │        Group        │  ← A and B are Edit members
    // └─────────────────────┘
    //            │ Edit
    //            ▼
    // ┌─────────────────────┐
    // │         Doc         │  ← A encrypts, B decrypts
    // └─────────────────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        Some(Read)
    );

    // The graph saying Read is not the same as the key agreement having reached him.
    let ct = ctx
        .encrypt(&alice, design_doc, b"through the group")
        .await?;
    ctx.sync_all_unsent().await?;
    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
        b"through the group".to_vec(),
        "bob reads it through the group, not only reaches it"
    );
    Ok(())
}

#[tokio::test]
async fn members_are_listed_with_their_effective_level() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(bob.id(), design_doc, Edit, &[]).await?;
    alice.add_member(carol.id(), design_doc, Read, &[]).await?;

    let members = ctx.named_access(alice.reachable_members(design_doc).await?);
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

                alice.add_member(outer, design_doc, a, &[]).await?;
                alice.add_member(inner, outer, b, &[]).await?;
                alice.add_member(bob.id(), inner, c, &[]).await?;

                assert_eq!(
                    alice.access_for_doc(bob.id(), design_doc).await?,
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

        alice
            .add_member(relays, design_doc, doc_to_group, &[])
            .await?;
        alice
            .add_member(bob.id(), relays, group_to_bob, &[])
            .await?;

        let may_read = doc_to_group.min(group_to_bob) >= Read;
        let ct = ctx.encrypt(&alice, design_doc, b"top secret").await?;
        ctx.sync_all_unsent().await?;

        assert_eq!(
            bob.can_decrypt_content(design_doc, &ct).await?,
            may_read,
            "decryption at {doc_to_group:?}/{group_to_bob:?}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "fails on main; fixed by jtfm/cgka-authority; un-ignore when that lands"]
async fn multi_route_resolution_is_deterministic() -> Result<()> {
    // Eight separate runs. In the presence of a bug the answer differs between them.
    let mut answers: std::collections::BTreeMap<Option<Access>, usize> = Default::default();
    for round in 0..8 {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;
        let engineering = ctx.group(&alice, "engineering").await?;

        // Route 1: design_doc -Edit-> engineering -Admin-> bob, giving Edit.
        alice.add_member(engineering, design_doc, Edit, &[]).await?;
        alice.add_member(bob.id(), engineering, Admin, &[]).await?;
        // Route 2: design_doc -Read-> bob, giving Read.
        alice.add_member(bob.id(), design_doc, Read, &[]).await?;

        let access = alice.access_for_doc(bob.id(), design_doc).await?;
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

    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    let before = ctx.encrypt(&alice, design_doc, b"first").await?;
    ctx.sync_all_unsent().await?;
    assert!(
        bob.can_decrypt_content(design_doc, &before).await?,
        "bob could read before"
    );

    alice.revoke_member(bob.id(), true, design_doc).await?;
    let after = ctx.encrypt(&alice, design_doc, b"second").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(alice.access_for_doc(bob.id(), design_doc).await?, None);
    assert!(
        !bob.can_decrypt_content(design_doc, &after).await?,
        "cannot read new content"
    );
    Ok(())
}

#[tokio::test]
async fn two_replicas_agree_on_access_for_a_doc() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let engineering = ctx.group(&alice, "engineering").await?;

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    alice
        .add_member(carol.id(), engineering, Admin, &[])
        .await?;
    ctx.sync_all_unsent().await?;

    for observer in [&alice, &bob, &carol] {
        assert_eq!(
            observer.access_for_doc(bob.id(), design_doc).await?,
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
    // Scenario:
    // Alice owns both Doc A and Doc B.
    // Alice grants Bob Admin access on Doc A.
    // Alice adds Doc A as an Admin member of Doc B.
    //
    // Question: Does Bob have Admin access to Doc B transitively?
    //
    // ┌─────────────────────┐
    // │                     │
    // │         Bob         │
    // │                     │
    // └─────────────────────┘
    //            │
    //            │ Admin
    //            ▼
    // ┌─────────────────────┐
    // │                     │
    // │       Doc A         │
    // │                     │
    // └─────────────────────┘
    //            │
    //            │ Admin
    //            ▼
    // ┌─────────────────────┐
    // │                     │
    // │       Doc B         │
    // │                     │
    // └─────────────────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let account = ctx.doc(&alice, "account").await?;
    let project = ctx.doc(&alice, "project").await?;

    alice.add_member(account, project, Admin, &[]).await?;
    alice.add_member(bob.id(), account, Admin, &[]).await?;

    assert_eq!(alice.access_for_doc(bob.id(), account).await?, Some(Admin));
    assert_eq!(alice.access_for_doc(bob.id(), project).await?, Some(Admin));
    Ok(())
}

#[tokio::test]
async fn what_an_agent_reaches_covers_groups_as_well_as_documents() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    alice
        .add_member(carol.id(), engineering, Admin, &[])
        .await?;
    ctx.sync_all_unsent().await?;

    let bob_reaches = ctx.named(alice.membered_reachable_by_agent(bob.id()).await?);
    assert_eq!(
        bob_reaches.get("engineering"),
        Some(&Read),
        "the group he is a member of"
    );
    assert_eq!(
        bob_reaches.get("design_doc"),
        Some(&Read),
        "and the document it holds"
    );
    assert_eq!(
        ctx.named(bob.docs_reachable_by_agent(bob.id()).await?)
            .get("design_doc"),
        Some(&Read),
        "and bob agrees"
    );

    assert_eq!(
        ctx.named(alice.membered_reachable_by_agent(carol.id()).await?)
            .get("engineering"),
        Some(&Admin),
        "at the level each member was given, not one level for everyone"
    );
    Ok(())
}

#[tokio::test]
async fn a_transitive_admin_through_a_document_can_delegate() -> Result<()> {
    // Scenario:
    // Alice owns Account Doc A and Doc B.
    // Alice adds Account Doc A as Admin member of Doc B.
    // Alice adds Bob as Admin member of Account Doc A.
    //
    // Bob has transitive Admin access to Doc B (through Account Doc A).
    //
    // Test: Bob should be able to call add_member on Doc B to add Carol.
    //
    // ┌─────────┐   ┌─────────┐   ┌─────────┐
    // │  Alice  │   │   Bob   │   │  Carol  │
    // └────┬────┘   └────┬────┘   └─────────┘
    //      │             │              ▲
    //      │ Admin       │ Admin        │ Edit (Bob adds)
    //      ▼             ▼              │
    // ┌─────────────────────┐           │
    // │   Account Doc A     │           │
    // └─────────┬───────────┘           │
    //           │ Admin                 │
    //           ▼                       │
    // ┌─────────────────────┐           │
    // │       Doc B         │ ──────────┘
    // └─────────────────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let account = ctx.doc(&alice, "account").await?;
    let project = ctx.doc(&alice, "project").await?;

    alice.add_member(account, project, Admin, &[]).await?;
    alice.add_member(bob.id(), account, Admin, &[]).await?;
    ctx.sync_all_unsent().await?;
    assert_eq!(
        alice.access_for_doc(bob.id(), project).await?,
        Some(Admin),
        "bob reaches project through account"
    );
    assert_eq!(
        alice.access_for_doc(bob.id(), account).await?,
        Some(Admin),
        "and account, which is where he holds it"
    );

    bob.add_member(carol.id(), project, Edit, &[]).await?;
    assert_eq!(
        bob.access_for_doc(carol.id(), project).await?,
        Some(Edit),
        "bob delegated based on a route (through a doc) he does not hold directly"
    );

    ctx.sync_all_unsent().await?;
    assert_eq!(
        alice.access_for_doc(carol.id(), project).await?,
        Some(Edit),
        "and alice, who owns the document, honors it"
    );
    assert_eq!(
        alice.access_for_doc(carol.id(), account).await?,
        None,
        "carol was let into project, and that does not reach back up to account"
    );
    Ok(())
}

#[tokio::test]
async fn a_transitive_admin_through_a_group_can_delegate() -> Result<()> {
    // Same scenario but using a Group as the intermediary.
    //
    // ┌─────────┐   ┌─────────┐   ┌─────────┐
    // │  Alice  │   │   Bob   │   │  Carol  │
    // └────┬────┘   └────┬────┘   └─────────┘
    //      │             │              ▲
    //      │ Admin       │ Admin        │ Edit (Bob adds)
    //      ▼             ▼              │
    // ┌─────────────────────┐           │
    // │      Group G        │           │
    // └─────────┬───────────┘           │
    //           │ Admin                 │
    //           ▼                       │
    // ┌─────────────────────┐           │
    // │       Doc B         │ ──────────┘
    // └─────────────────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let project = ctx.doc(&alice, "project").await?;

    alice.add_member(engineering, project, Admin, &[]).await?;
    alice.add_member(bob.id(), engineering, Admin, &[]).await?;
    ctx.sync_all_unsent().await?;
    assert_eq!(alice.access_for_doc(bob.id(), project).await?, Some(Admin));
    let members_of_the_group = ctx.named_access(alice.reachable_members(engineering).await?);
    assert_eq!(members_of_the_group.get("bob"), Some(&Admin));
    assert_eq!(
        members_of_the_group.get("carol"),
        None,
        "carol is not in the group to begin with"
    );

    bob.add_member(carol.id(), project, Edit, &[]).await?;
    assert_eq!(
        bob.access_for_doc(carol.id(), project).await?,
        Some(Edit),
        "bob delegated on the strength of a route he does not hold directly"
    );

    ctx.sync_all_unsent().await?;
    assert_eq!(
        alice.access_for_doc(carol.id(), project).await?,
        Some(Edit),
        "bob delegated based on a route (through a group) he does not hold directly"
    );
    assert_eq!(
        ctx.named_access(alice.reachable_members(engineering).await?)
            .get("carol"),
        None,
        "and being let into project does not put her in the group that holds it"
    );
    Ok(())
}

/// A group holds a document and the document holds the group. Reachability has to
/// terminate from either end and neither membership may be lost.
#[tokio::test]
async fn a_membership_cycle_still_resolves() -> Result<()> {
    // Scenario:
    // Alice and Bob are separate Keyhive agents
    //
    // 1. Alice registers Bob
    // 2. Alice creates a new group that she owns
    // 3. Alice adds Bob to the group
    // 4. Alice creates a new document that the group controls
    // 5. Alice creates a cycle by adding the document to the group
    //
    // Both Alice and Bob should be able to access the document
    //
    //
    //
    // ┌─────────────────────┐   ┌─────────────────────┐
    // │                     │   │                     │
    // │        Alice        │   │         Bob         │
    // │                     │   │                     │
    // └─────────────────────┘   └─────────────────────┘
    //            ▲                         ▲
    //            │                         │
    //            │                         │
    //            │ ┌─────────────────────┐ │
    //            │ │                     │ │
    //            └─│        Group        │─┘
    //              │                     │
    //              └─────────────────────┘
    //                      ▲     │
    //                      │     │
    //                      │     ▼
    //              ┌─────────────────────┐
    //              │                     │
    //              │         Doc         │
    //              │                     │
    //              └─────────────────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(bob.id(), engineering, Read, &[]).await?;
    alice.add_member(engineering, design_doc, Read, &[]).await?;
    alice.add_member(design_doc, engineering, Read, &[]).await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        Some(Read)
    );

    let of_the_document = ctx.named_access(alice.reachable_members(design_doc).await?);
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

    let of_the_group = ctx.named_access(alice.reachable_members(engineering).await?);
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
#[ignore = "a member's level comes from the last route explored, not the best one"]
async fn an_attenuated_second_route_does_not_lower_reported_access() -> Result<()> {
    // Five separate runs. In the presence of a bug the answer differs between them.
    for _ in 0..5 {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let engineering = ctx.group(&alice, "engineering").await?;
        let design_doc = ctx.doc(&alice, "design_doc").await?;

        assert_eq!(
            ctx.named_access(alice.reachable_members(engineering).await?)
                .get("alice"),
            Some(&Admin),
            "alice created the group"
        );

        alice.add_member(design_doc, engineering, Read, &[]).await?;

        assert_eq!(
            ctx.named_access(alice.reachable_members(engineering).await?)
                .get("alice"),
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

    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    ctx.sync_all_unsent().await?;

    for access in [Edit, Admin] {
        match bob
            .add_member(carol.id(), design_doc, access, &[])
            .await
            .map_err(TestError::from)
        {
            Err(TestError::Escalation { wanted, held }) => {
                assert_eq!(wanted, access);
                assert_eq!(held, Read);
            }
            other => panic!("expected an escalation refusal, got {other:?}"),
        }
    }
    assert_eq!(alice.access_for_doc(carol.id(), design_doc).await?, None);
    Ok(())
}

#[tokio::test]
async fn a_transitive_reader_cannot_delegate_above_read() -> Result<()> {
    // Scenario:
    // Alice owns Doc A and Doc B.
    // Alice adds Doc A as Admin member of Doc B.
    // Alice adds Bob as a Read member of Doc A.
    //
    // Bob has transitive Read access to Doc B.
    // Bob tries to add Carol as Admin of Doc B. It should fail with an access escalation.
    //
    // ┌─────────┐   ┌─────────┐   ┌─────────┐
    // │  Alice  │   │   Bob   │   │  Carol  │
    // └────┬────┘   └────┬────┘   └─────────┘
    //      │             │              ▲
    //      │ Read        │ Read         │ Admin (Bob tries, should fail)
    //      ▼             ▼              │
    // ┌─────────────────────┐           │
    // │       Doc A         │           │
    // └─────────┬───────────┘           │
    //           │ Admin                 │
    //           ▼                       │
    // ┌─────────────────────┐           │
    // │       Doc B         │ ──────────┘
    // └─────────────────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let account = ctx.doc(&alice, "account").await?;
    let project = ctx.doc(&alice, "project").await?;

    alice.add_member(account, project, Admin, &[]).await?;
    alice.add_member(bob.id(), account, Read, &[]).await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), project).await?,
        Some(Read),
        "bob holds Read on account, which attenuates his route to project"
    );

    for access in [Edit, Admin] {
        match bob
            .add_member(carol.id(), project, access, &[])
            .await
            .map_err(TestError::from)
        {
            Err(TestError::Escalation { wanted, held }) => {
                assert_eq!(wanted, access);
                assert_eq!(
                    held, Read,
                    "attenuated along the route, not taken from account"
                );
            }
            other => panic!("expected an escalation refusal, got {other:?}"),
        }
    }
    assert_eq!(alice.access_for_doc(carol.id(), project).await?, None);

    // The refusal is about the level, not about the route being transitive: the same
    // delegation at bob's own level goes through.
    bob.add_member(carol.id(), project, Read, &[]).await?;
    assert_eq!(
        bob.access_for_doc(carol.id(), project).await?,
        Some(Read),
        "bob delegated at the level he holds"
    );

    ctx.sync_all_unsent().await?;
    assert_eq!(
        alice.access_for_doc(carol.id(), project).await?,
        Some(Read),
        "and alice, who owns the document, honors it"
    );
    assert_eq!(
        alice.access_for_doc(carol.id(), account).await?,
        None,
        "being let into project does not reach back up to the document that holds it"
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_member_cannot_delegate_or_revoke() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let mallory = ctx.individual("mallory").await?;
    let carol = ctx.individual("carol").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice
        .add_member(mallory.id(), design_doc, Read, &[])
        .await?;
    ctx.sync_all_unsent().await?;
    alice.revoke_member(mallory.id(), true, design_doc).await?;
    ctx.sync_all_unsent().await?;

    match mallory
        .add_member(carol.id(), design_doc, Read, &[])
        .await
        .map_err(TestError::from)
    {
        Err(TestError::NoAuthority) => {}
        other => panic!("a revoked member may not issue a delegation, got {other:?}"),
    }
    match mallory
        .revoke_member(alice.id(), true, design_doc)
        .await
        .map_err(TestError::from)
    {
        Err(TestError::NoAuthority) => {}
        other => panic!("nor a revocation, got {other:?}"),
    }
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

    alice.add_member(engineering, design_doc, Edit, &[]).await?;
    alice.add_member(bob.id(), engineering, Edit, &[]).await?;
    alice.add_member(carol.id(), engineering, Edit, &[]).await?;
    alice.add_member(carol.id(), design_doc, Read, &[]).await?;

    assert_eq!(
        alice.access_for_doc(bob.id(), design_doc).await?,
        Some(Edit)
    );
    // Carol has two routes here, Edit through the group and Read directly. Her exact level
    // therefore depends on the rule for combining multiple routes, which has its own test.
    // This test is about revocation, so it only checks that she has some access, not which
    // level.
    assert!(alice
        .access_for_doc(carol.id(), design_doc)
        .await?
        .is_some());

    // Bob and carol have to receive the document before it is taken away again, or the
    // "cannot read" assertions below hold because they were never sent it rather than
    // because they were removed.
    ctx.sync_all_unsent().await?;
    assert!(
        bob.has_received(design_doc).await,
        "bob holds the document while he is still a member"
    );

    alice.revoke_member(engineering, true, design_doc).await?;

    let after = ctx.encrypt(&alice, design_doc, b"post-revocation").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(alice.access_for_doc(bob.id(), design_doc).await?, None);
    assert!(
        !bob.can_decrypt_content(design_doc, &after).await?,
        "bob had only the group route"
    );

    assert_eq!(
        alice.access_for_doc(carol.id(), design_doc).await?,
        Some(Read)
    );
    assert!(
        carol.can_decrypt_content(design_doc, &after).await?,
        "carol kept her direct route"
    );
    Ok(())
}

/// A resource argument is typed, so naming the wrong kind of thing does not compile:
/// `try_decrypt_content(engineering, ..)` wants a `DocumentId` and a `GroupId` will not pass,
/// and `reachable_members(bob.id())` wants a `MemberedId`. What is left for runtime is the
/// one thing the types cannot rule out, which is an identifier this instance never received.
#[tokio::test]
async fn an_identifier_that_was_never_received_says_so() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let engineering = ctx.group(&alice, "engineering").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    assert!(
        matches!(bob.reachable_members(engineering).await, Err(NotFound(_))),
        "bob has never been told the group exists"
    );

    // The two access queries agree about that, rather than one of them reporting "no
    // access" for a document the instance was never sent.
    assert!(
        matches!(
            bob.access_for_doc(bob.id(), design_doc).await,
            Err(NotFound(_))
        ),
        "not being sent a document is not the same as having no access to it"
    );
    assert!(
        matches!(
            bob.best_access_for_doc(bob.id(), design_doc).await,
            Err(NotFound(_))
        ),
        "and best_access_for_doc says the same"
    );
    Ok(())
}
