use beekem::operation::CitationId;
use future_form::Sendable;
use keyhive_core::{
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{
        document::id::DocumentId,
        individual::{id::IndividualId, op::KeyOp, IndividualState},
    },
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::{make_simple_keyhive, Hive, TestContext},
};
use keyhive_crypto::{
    identifier::Identifier, signer::memory::MemorySigner, verifiable::Verifiable, verified::Signed,
};
use keyline::{contract::Keyline, delegation::Delegation, power::Power};
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::rngs::OsRng;
use std::collections::HashMap;
use testresult::TestResult;

#[tokio::test]
async fn test_transitive_admin_can_revoke() -> TestResult {
    // Scenario:
    // Alice owns Account Doc A and Doc B.
    // Alice adds Account Doc A as Admin member of Doc B.
    // Alice adds Bob as Admin member of Account Doc A.
    // Bob adds Carol to Doc B.
    // ┌─────────┐   ┌─────────┐   ┌─────────┐
    // │  Alice  │   │   Bob   │   │  Carol  │
    // └────┬────┘   └────┬────┘   └────┬────┘
    //      │             │             │
    //      │ Admin       │ Admin       │ Edit (Bob adds)
    //      ▼             ▼             │
    // ┌─────────────────────┐          │
    // │   Account Doc A     │          │
    // └─────────┬───────────┘          │
    //           │ Admin                │
    //           ▼                      │
    // ┌─────────────────────┐          │
    // │       Doc B         │◀─────────┘
    // └─────────────────────┘
    // Test: After Bob adds Carol, Bob should also be able to revoke Carol.
    // Bob writes on his own replica, and Alice learns of it by sync.
    test_utils::init_logging();
    let (alice, bob, carol_id, alice_on_bob, bob_on_alice) = cast().await?;

    let doc_a_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    alice.add_member(doc_a_id, doc_b_id, Power::Admin).await?;
    alice
        .add_member(bob_on_alice, doc_a_id, Power::Admin)
        .await?;
    bob.ingest_event_table(alice.events_for_agent(bob_on_alice).await?)
        .await?;

    bob.add_member(carol_id, doc_b_id, Power::Edit).await?;
    alice
        .ingest_event_table(bob.events_for_agent(alice_on_bob).await?)
        .await?;
    assert_eq!(
        alice.docs_reachable_by_agent(carol_id).await?.len(),
        1,
        "Carol should reach Doc B before revoke"
    );

    bob.revoke_member(carol_id, true, doc_b_id).await?;
    alice
        .ingest_event_table(bob.events_for_agent(alice_on_bob).await?)
        .await?;
    assert_eq!(
        alice.docs_reachable_by_agent(carol_id).await?.len(),
        0,
        "Carol should not reach Doc B after revoke"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_can_revoke_via_group() -> TestResult {
    // Same as above but with Group as intermediary.
    test_utils::init_logging();
    let (alice, bob, carol_id, alice_on_bob, bob_on_alice) = cast().await?;

    let group_id = alice.generate_group(vec![]).await?;
    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    alice.add_member(group_id, doc_b_id, Power::Admin).await?;
    alice
        .add_member(bob_on_alice, group_id, Power::Admin)
        .await?;
    bob.ingest_event_table(alice.events_for_agent(bob_on_alice).await?)
        .await?;

    bob.add_member(carol_id, doc_b_id, Power::Edit).await?;
    alice
        .ingest_event_table(bob.events_for_agent(alice_on_bob).await?)
        .await?;
    assert_eq!(
        alice.docs_reachable_by_agent(carol_id).await?.len(),
        1,
        "Carol should reach Doc B before revoke"
    );

    bob.revoke_member(carol_id, true, doc_b_id).await?;
    alice
        .ingest_event_table(bob.events_for_agent(alice_on_bob).await?)
        .await?;
    assert_eq!(
        alice.docs_reachable_by_agent(carol_id).await?.len(),
        0,
        "Carol should not reach Doc B after revoke"
    );

    Ok(())
}

/// Alice and Bob, each known to the other, and Carol, known to both. Returns
/// the two keyhives, Carol's id, Alice's id on Bob, and Bob's id on Alice.
async fn cast(
) -> Result<(Hive, Hive, IndividualId, IndividualId, IndividualId), Box<dyn std::error::Error>> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;

    let bob_on_alice = alice
        .receive_contact_card(&bob.generate_contact_card().await?)
        .await?;
    let alice_on_bob = bob
        .receive_contact_card(&alice.generate_contact_card().await?)
        .await?;
    let carol_card = carol.generate_contact_card().await?;
    let carol_id = alice.receive_contact_card(&carol_card).await?;
    bob.receive_contact_card(&carol_card).await?;

    Ok((alice, bob, carol_id, alice_on_bob, bob_on_alice))
}

#[tokio::test]
async fn test_deep_chain_revocation() -> TestResult {
    // Chain: Alice (owner) → Bob → Carol → Dave → Eve, each link written by
    // its issuer's own replica. Carol revokes Eve: her standing is three hops
    // from the group, and her revocation still reaches Eve's delegation,
    // which hangs off a node Carol holds Admin over.
    //
    // ┌─────────┐
    // │  Alice  │  (Group owner)
    // └────┬────┘
    //      │ Admin
    //      ▼
    // ┌─────────┐
    // │   Bob   │
    // └────┬────┘
    //      │ Admin
    //      ▼
    // ┌─────────┐
    // │  Carol  │  ← revoker
    // └────┬────┘
    //      │ Admin
    //      ▼
    // ┌─────────┐
    // │  Dave   │
    // └────┬────┘
    //      │ Edit
    //      ▼
    // ┌─────────┐
    // │   Eve   │  ← revoked
    // └─────────┘
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let carol = ctx.individual("carol").await?;
    let dave = ctx.individual("dave").await?;
    let eve = ctx.individual("eve").await?;
    let group = ctx.group(&alice, "group").await?;

    for (issuer, audience, power) in [
        (&alice, &bob, Power::Admin),
        (&bob, &carol, Power::Admin),
        (&carol, &dave, Power::Admin),
        (&dave, &eve, Power::Edit),
    ] {
        issuer.add_member(audience.id(), group, power).await?;
        ctx.sync_all_unsent().await?;
    }
    assert_eq!(
        alice.reachable_members(group).await?.get(&eve.id().into()),
        Some(&Power::Edit),
        "Eve is a member at the end of the chain"
    );

    carol.revoke_member(eve.id(), true, group).await?;
    ctx.sync_all_unsent().await?;

    assert!(
        !alice
            .reachable_members(group)
            .await?
            .contains_key(&eve.id().into()),
        "Eve should no longer be a member after revocation"
    );
    Ok(())
}

#[tokio::test]
async fn test_concurrent_cgka_adds_merge_correctly() -> TestResult {
    // Scenario: Alice and Bob both have the doc with CGKA initialized.
    // Alice adds Carol, Bob adds Dave — concurrently.
    // Then they sync: Alice ingests Bob's events, Bob ingests Alice's events.
    // Both should end up with the same members.
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;

    // Cross-register
    let bob_prekey_op = bob.expand_prekeys().await?;
    let bob_on_alice = IndividualState::new(KeyOp::Add(bob_prekey_op));
    let bob_on_alice_id = bob_on_alice.id();
    assert!(alice.register_individual(bob_on_alice).await);

    let alice_prekey_op = alice.expand_prekeys().await?;
    let alice_on_bob = IndividualState::new(KeyOp::Add(alice_prekey_op));
    let alice_on_bob_id = alice_on_bob.id();
    assert!(bob.register_individual(alice_on_bob).await);

    // Alice creates doc, adds Bob as Admin
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    alice
        .add_member(bob_on_alice_id, doc_id, Power::Admin)
        .await?;

    // Share ALL events (including CGKA) to Bob so his CGKA is initialized
    let events_for_bob = alice.events_for_agent(bob_on_alice_id).await?;
    bob.ingest_event_table(events_for_bob).await?;

    // Now both have the doc with CGKA initialized.
    // Alice adds Carol concurrently with Bob adding Dave.
    let carol = make_simple_keyhive().await?;
    let carol_prekey_op = carol.expand_prekeys().await?;
    let carol_on_alice = IndividualState::new(KeyOp::Add(carol_prekey_op.clone()));
    let carol_on_alice_id = carol_on_alice.id();
    assert!(alice.register_individual(carol_on_alice).await);

    // Also register Carol on Bob
    let carol_on_bob = IndividualState::new(KeyOp::Add(carol_prekey_op));
    assert!(bob.register_individual(carol_on_bob).await);

    // Alice adds Carol as Edit member
    alice
        .add_member(carol_on_alice_id, doc_id, Power::Edit)
        .await?;

    let dave = make_simple_keyhive().await?;
    let dave_on_bob = IndividualState::new(KeyOp::Add(dave.expand_prekeys().await?));
    let dave_id = dave_on_bob.id();
    assert!(bob.register_individual(dave_on_bob).await);

    // Bob adds Dave as Read member (concurrently, before syncing)
    bob.add_member(dave_id, doc_id, Power::Read).await?;

    // Now sync: Alice sends to Bob, Bob sends to Alice
    let events_alice_to_bob = alice.events_for_agent(bob_on_alice_id).await?;
    let events_bob_to_alice = bob.events_for_agent(alice_on_bob_id).await?;

    bob.ingest_event_table(events_alice_to_bob).await?;
    alice.ingest_event_table(events_bob_to_alice).await?;

    // Both should see Carol and Dave on the doc
    let alice_reachable = alice.docs_reachable_by_agent(carol_on_alice_id).await?;
    assert_eq!(
        alice_reachable.len(),
        1,
        "Alice should see Carol on the doc"
    );

    let alice_dave_reachable = alice.docs_reachable_by_agent(dave_id).await?;
    assert_eq!(
        alice_dave_reachable.len(),
        1,
        "Alice should see Dave on the doc after ingesting Bob's events"
    );

    let bob_dave_reachable = bob.docs_reachable_by_agent(dave_id).await?;
    assert_eq!(
        bob_dave_reachable.len(),
        1,
        "Bob should still see Dave on the doc"
    );

    Ok(())
}

#[tokio::test]
async fn a_peer_that_started_its_own_tree_converges_when_the_creators_ops_arrive() -> TestResult {
    // Bob has the document but none of its CGKA ops. He starts a tree of his
    // own by adding himself. Only afterwards does he receive Alice's ops.
    // Their self-adds are concurrent roots, both at leaf 0.
    test_utils::init_logging();

    // Replaying the ops sorts the concurrent roots by id. When Bob's id sorts
    // first, the sorted tree differs from the order in which either peer first
    // applied the roots. When Alice's does, the two orders match.
    for bob_sorts_first in [true, false] {
        own_tree_converges_with_creators_ops(bob_sorts_first)
            .await
            .map_err(|e| format!("bob_sorts_first = {bob_sorts_first}: {e:?}"))?;
    }
    Ok(())
}

async fn own_tree_converges_with_creators_ops(bob_sorts_first: bool) -> TestResult {
    let mut signers = [
        MemorySigner::generate(&mut OsRng),
        MemorySigner::generate(&mut OsRng),
    ];
    signers.sort_by_key(|signer| signer.verifying_key().to_bytes());
    let [first, second] = signers;
    let (bob_signer, alice_signer) = if bob_sorts_first {
        (first, second)
    } else {
        (second, first)
    };

    let alice = Keyhive::<Sendable, _, _, _, _, _, _, _>::generate(
        alice_signer,
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        NoListener,
        MemoryKeyline::new(),
        OsRng,
    )
    .await?;
    let bob = Keyhive::<Sendable, _, _, _, _, _, _, _>::generate(
        bob_signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        NoListener,
        MemoryKeyline::new(),
        OsRng,
    )
    .await?;

    // Cross-register
    let bob_prekey_op = bob.expand_prekeys().await?;
    let bob_on_alice = IndividualState::new(KeyOp::Add(bob_prekey_op.clone()));
    let bob_on_alice_id = bob_on_alice.id();
    assert!(alice.register_individual(bob_on_alice).await);

    let alice_prekey_op = alice.expand_prekeys().await?;
    let alice_on_bob = IndividualState::new(KeyOp::Add(alice_prekey_op));
    let alice_on_bob_id = alice_on_bob.id();
    assert!(bob.register_individual(alice_on_bob).await);

    // Alice creates the doc with Bob as a co-founder, so Bob holds a founding
    // delegation he may enact himself.
    let doc_id = alice
        .generate_doc(vec![bob_on_alice_id.into()], nonempty![[0u8; 32]])
        .await?;

    // Share only delegation events (no CGKA) to Bob
    let events_for_bob = alice.events_for_agent(bob_on_alice_id).await?;
    let events_without_cgka: HashMap<_, _> = events_for_bob
        .into_iter()
        .filter(|(_, event)| !matches!(event, keyhive_core::event::Event::CgkaOperation(_)))
        .collect();
    bob.ingest_event_table(events_without_cgka).await?;

    // Without key agreement, the document is not yet a document to Bob.
    assert!(bob.get_document(doc_id).await.is_none());

    // Bob starts his own tree. His add has no predecessors, so it is a
    // causal root of the operation graph.
    {
        let bob_active_id = bob.active().id();
        let bob_pk = bob_prekey_op.payload().share_key;
        // Bob's founding delegation: the document's Keyline root edge to him.
        let doc_kl = Identifier::from(doc_id);
        let bob_founding: [u8; 32] = Keyline::<Sendable>::delegations_to(
            bob.keyline(),
            doc_kl,
            Identifier::from(bob_active_id),
        )
        .await?
        .value
        .into_iter()
        .find(|(_, (issuer, _))| *issuer == doc_kl)
        .ok_or("bob holds a founding delegation")?
        .0
        .into();

        let mut bob_tree =
            keyhive_core::cgka::Cgka::new(doc_id, bob_active_id, beekem::keys::ShareKeyMap::new());
        let bob_add = bob_tree
            .add::<Sendable, _>(
                bob_active_id,
                bob_pk,
                Some(KeyOp::Add(bob_prekey_op.clone()).to_key_proof()),
                [CitationId(bob_founding)].into(),
                &bob_signer,
            )
            .await?
            .ok_or("bob is not yet in his own tree, so adding him yields an op")?;

        // His add is authorized by his founding delegation, so it makes the
        // document known to him.
        bob.receive_cgka_op(bob_add).await?;
        assert!(bob.get_document(doc_id).await.is_some());
    }

    // Now Alice sends her CGKA ops to Bob, starting with her add of herself
    let all_events_for_bob = alice.events_for_agent(bob_on_alice_id).await?;
    let cgka_only: HashMap<_, _> = all_events_for_bob
        .into_iter()
        .filter(|(_, event)| matches!(event, keyhive_core::event::Event::CgkaOperation(_)))
        .collect();

    bob.ingest_event_table(cgka_only)
        .await
        .map_err(|e| format!("alice's ops should merge with the tree bob started: {e:?}"))?;

    let dave = make_simple_keyhive().await?;
    let dave_on_bob = IndividualState::new(KeyOp::Add(dave.expand_prekeys().await?));
    let dave_id = dave_on_bob.id();
    assert!(bob.register_individual(dave_on_bob).await);
    bob.add_member(dave_id, doc_id, Power::Read)
        .await
        .map_err(|e| format!("bob's tree should still take an add: {e:?}"))?;

    assert_eq!(
        bob.docs_reachable_by_agent(dave_id).await?.len(),
        1,
        "the document bob just admitted Dave to should be reachable by Dave"
    );

    // Exchange everything in both directions. The two trees should now agree.
    bob.ingest_event_table(alice.events_for_agent(bob_on_alice_id).await?)
        .await?;
    alice
        .ingest_event_table(bob.events_for_agent(alice_on_bob_id).await?)
        .await?;

    let doc_on_alice = alice.get_document(doc_id).await.unwrap();
    let doc_on_bob = bob
        .get_document(doc_id)
        .await
        .ok_or("bob knows the document")?;
    let alice_members = doc_on_alice
        .cgka_members()
        .await
        .ok_or("alice holds a tree")?;
    let alice_ops = doc_on_alice
        .cgka_ops_count()
        .await
        .ok_or("alice holds a tree")?;
    let bob_members = doc_on_bob.cgka_members().await.ok_or("bob holds a tree")?;
    let bob_ops = doc_on_bob
        .cgka_ops_count()
        .await
        .ok_or("bob holds a tree")?;
    assert_eq!(
        alice_members, bob_members,
        "both trees hold the same members"
    );
    assert!(alice_members.contains(&bob.id()), "bob is a member");
    assert_eq!(alice_ops, bob_ops, "both trees hold the same ops");

    // Each can read what the other writes, even when they write concurrently.
    // Neither tree has a root key yet, so each write performs an update. To read
    // the other's write, each peer rebuilds the tree up to that update.
    let from_alice = alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"from alice")
        .await?;
    let from_bob = bob
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"from bob")
        .await?;
    bob.ingest_event_table(alice.events_for_agent(bob_on_alice_id).await?)
        .await?;
    alice
        .ingest_event_table(bob.events_for_agent(alice_on_bob_id).await?)
        .await?;
    assert_eq!(
        bob.try_decrypt_content(doc_id, from_alice.encrypted_content())
            .await?,
        b"from alice".to_vec()
    );
    assert_eq!(
        alice
            .try_decrypt_content(doc_id, from_bob.encrypted_content())
            .await?,
        b"from bob".to_vec()
    );

    // The concurrent updates leave two heads. Alice's next write resolves them
    // with another update, after which both derive the same PCS key.
    let after = alice
        .try_encrypt_content(doc_id, &[3u8; 32], &vec![[1u8; 32]], b"after")
        .await?;
    bob.ingest_event_table(alice.events_for_agent(bob_on_alice_id).await?)
        .await?;
    assert_eq!(
        bob.try_decrypt_content(doc_id, after.encrypted_content())
            .await?,
        b"after".to_vec()
    );
    let alice_pcs = alice
        .try_pcs_key_hash(doc_id)
        .await
        .ok_or("alice derives a key")?;
    let bob_pcs = bob
        .try_pcs_key_hash(doc_id)
        .await
        .ok_or("bob derives a key")?;
    assert_eq!(alice_pcs, bob_pcs, "both trees derive the same PCS key");

    Ok(())
}

/// A document that is a member of another document is known as a document
/// once its key agreement is authorized, whatever order its events arrive in.
///
/// Doc A's genesis key agreement cites its root edge. Delivered to an invited
/// member without the root edge, it waits, and the member does not hold Doc A
/// yet; once the root edge arrives, it applies.
#[tokio::test]
async fn test_document_waits_for_its_defining_delegation() -> TestResult {
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
    alice
        .receive_contact_card(&carol.get_existing_contact_card().await)
        .await?;

    // Alice owns Doc A and Doc B, adds Doc A as a Read member of Doc B, and
    // invites Carol to Doc A.
    let doc_a_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

    alice.add_member(doc_a_id, doc_b_id, Power::Read).await?;
    alice.add_member(carol.id(), doc_a_id, Power::Read).await?;

    // Collect what Carol is sent, then split out Doc A's defining (root)
    // delegation, i.e. the one issued by Doc A itself, so it is delivered last.
    let alice_id = { alice.active().id() };
    let all_events = alice.static_events_for_agent(carol.id()).await?;

    let doc_a_ident: Identifier = doc_a_id.into();
    let mut defining: Vec<StaticEvent<[u8; 32]>> = vec![];
    let mut rest: Vec<StaticEvent<[u8; 32]>> = vec![];
    for event in all_events.into_values() {
        match &event {
            StaticEvent::Delegated(signed) if issued_by(signed, doc_a_ident) => {
                defining.push(event);
            }
            _ => rest.push(event),
        }
    }
    assert_eq!(
        defining.len(),
        1,
        "expected exactly one root delegation defining Doc A"
    );

    // Carol receives everything except Doc A's defining delegation first.
    let pending = carol.ingest_unsorted_static_events(rest).await;

    // Doc A's genesis key agreement cites its root edge, so without it the
    // operation waits, and Doc A is not yet known as a document.
    assert!(
        !pending.is_empty(),
        "Doc A's key agreement waits on its defining delegation"
    );
    assert!(
        !carol.has_document(doc_a_id).await,
        "Doc A is not a document before its defining delegation arrives"
    );

    // Deliver Doc A's defining delegation; the waiting events go through.
    carol.ingest_unsorted_static_events(defining).await;
    assert!(
        carol.has_document(doc_a_id).await,
        "Doc A is a document once its key agreement is authorized"
    );
    assert!(
        carol
            .membered_reachable_by_agent(alice_id)
            .await?
            .contains_key(&doc_a_id.into()),
        "and Keyline answers about it as a document"
    );

    Ok(())
}

/// Companion to the document case: a group that is a member of a document is
/// known as a group whatever order its events arrive in, and never becomes a
/// document, since it has no key agreement.
#[tokio::test]
async fn test_group_member_is_known_before_its_defining_delegation() -> TestResult {
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;

    // Alice owns Group G and Doc B, and adds Group G as a Read member of Doc B.
    let group_id = alice.generate_group(vec![]).await?;
    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

    alice.add_member(group_id, doc_b_id, Power::Read).await?;

    // Split out Group G's defining (root) delegation, issued by G itself.
    // CGKA operations are left out: Carol is not a member of Doc B,
    // and certificates are what this is about.
    let alice_id = { alice.active().id() };
    let all_events = alice.static_events_for_agent(alice_id).await?;
    let all_events: Vec<_> = all_events
        .into_values()
        .filter(|event| !matches!(event, StaticEvent::CgkaOperation(_)))
        .collect();

    let group_ident: Identifier = group_id.into();
    let mut defining: Vec<StaticEvent<[u8; 32]>> = vec![];
    let mut rest: Vec<StaticEvent<[u8; 32]>> = vec![];
    for event in all_events {
        match &event {
            StaticEvent::Delegated(signed) if issued_by(signed, group_ident) => {
                defining.push(event);
            }
            _ => rest.push(event),
        }
    }
    assert_eq!(
        defining.len(),
        1,
        "expected exactly one root delegation defining Group G"
    );

    let carol = make_simple_keyhive().await?;
    let pending = carol.ingest_unsorted_static_events(rest).await;

    // Certificates never wait: Group G's membership in Doc B is known before
    // G's own root edge arrives.
    assert!(
        pending.is_empty(),
        "nothing waits on Group G's defining delegation"
    );
    assert_eq!(
        carol.reachable_members(doc_b_id).await?.get(&group_ident),
        Some(&Power::Read),
        "Group G reads Doc B"
    );

    carol.ingest_unsorted_static_events(defining).await;

    // Group G is a subject in Keyline, and never a DocumentState.
    assert!(
        carol
            .reachable_members(group_id)
            .await?
            .contains_key(&alice_id.into()),
        "Group G's root edge makes Alice its member"
    );
    assert!(
        carol
            .get_document(DocumentId::from(group_ident))
            .await
            .is_none(),
        "Group G must not be modeled as a DocumentState"
    );

    Ok(())
}

/// Whether `signed` is a delegation `issuer` signed: a root edge, when the
/// issuer is the subject itself.
fn issued_by(signed: &Signed<Delegation>, issuer: Identifier) -> bool {
    signed.issuer() == issuer
}
