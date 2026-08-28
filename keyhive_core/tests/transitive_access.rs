use dupe::Dupe;
use keyhive_core::{
    access::Access,
    event::static_event::StaticEvent,
    principal::{agent::Agent, document::id::DocumentId, identifier::Identifier, public::Public},
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
use nonempty::nonempty;
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
    // Test: After Bob adds Carol, Bob should also be able to revoke Carol.
    test_utils::init_logging();

    let bob_signer = MemorySigner::generate(&mut rand::rngs::OsRng);

    let alice = make_simple_keyhive().await?;
    let bob = keyhive_core::keyhive::Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
        bob_signer.clone(),
        keyhive_core::store::ciphertext::memory::MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        keyhive_core::listener::no_listener::NoListener,
        rand::rngs::OsRng,
    )
    .await?;
    let carol = make_simple_keyhive().await?;

    let bob_contact = bob.generate_contact_card().await?;
    let bob_id = alice.receive_contact_card(&bob_contact).await?;

    let carol_contact = carol.generate_contact_card().await?;
    let carol_id = alice.receive_contact_card(&carol_contact).await?;
    let carol_on_alice = alice.get_individual(carol_id).await.expect("just received");

    let doc_a_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b = alice.get_document(doc_b_id).await.expect("just created");

    // Alice adds Doc A as Admin of Doc B, Bob as Admin of Doc A
    alice
        .add_member(doc_a_id, doc_b_id, Access::Admin, &[])
        .await?;
    alice
        .add_member(bob_id, doc_a_id, Access::Admin, &[])
        .await?;

    // Bob adds Carol to Doc B
    {
        let mut locked = doc_b.lock().await;
        locked
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                Access::Edit,
                &bob_signer,
                &[],
            )
            .await?;
    }

    // Verify Carol can reach Doc B
    let carol_reachable = alice.docs_reachable_by_agent(carol_id).await?;
    assert_eq!(
        carol_reachable.len(),
        1,
        "Carol should reach Doc B before revoke"
    );

    // Bob revokes Carol from Doc B
    {
        let carol_identifier: Identifier = carol_id.into();
        let mut locked = doc_b.lock().await;
        locked
            .revoke_member(
                carol_identifier,
                true,
                &bob_signer,
                &mut std::collections::BTreeMap::new(),
            )
            .await?;
    }

    // Verify Carol can no longer reach Doc B
    let carol_reachable_after = alice.docs_reachable_by_agent(carol_id).await?;
    assert_eq!(
        carol_reachable_after.len(),
        0,
        "Carol should not reach Doc B after revoke"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_can_revoke_via_group() -> TestResult {
    // Same as above but with Group as intermediary.
    test_utils::init_logging();

    let bob_signer = MemorySigner::generate(&mut rand::rngs::OsRng);

    let alice = make_simple_keyhive().await?;
    let bob = keyhive_core::keyhive::Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
        bob_signer.clone(),
        keyhive_core::store::ciphertext::memory::MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        keyhive_core::listener::no_listener::NoListener,
        rand::rngs::OsRng,
    )
    .await?;
    let carol = make_simple_keyhive().await?;

    let bob_contact = bob.generate_contact_card().await?;
    let bob_id = alice.receive_contact_card(&bob_contact).await?;

    let carol_contact = carol.generate_contact_card().await?;
    let carol_id = alice.receive_contact_card(&carol_contact).await?;
    let carol_on_alice = alice.get_individual(carol_id).await.expect("just received");

    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };

    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b = alice.get_document(doc_b_id).await.expect("just created");

    // Alice adds Group G as Admin of Doc B, Bob as Admin of Group G
    alice
        .add_member(group_id, doc_b_id, Access::Admin, &[])
        .await?;
    alice
        .add_member(bob_id, group_id, Access::Admin, &[])
        .await?;

    // Bob adds Carol to Doc B
    {
        let mut locked = doc_b.lock().await;
        locked
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                Access::Edit,
                &bob_signer,
                &[],
            )
            .await?;
    }

    // Bob revokes Carol from Doc B
    {
        let carol_identifier: Identifier = carol_id.into();
        let mut locked = doc_b.lock().await;
        locked
            .revoke_member(
                carol_identifier,
                true,
                &bob_signer,
                &mut std::collections::BTreeMap::new(),
            )
            .await?;
    }

    // Verify Carol can no longer reach Doc B
    let carol_reachable = alice.docs_reachable_by_agent(carol_id).await?;
    assert_eq!(
        carol_reachable.len(),
        0,
        "Carol should not reach Doc B after revoke"
    );

    Ok(())
}

#[tokio::test]
async fn test_deep_chain_revocation() -> TestResult {
    // Regression test: the old add_revocation proof chain validation used a
    // try_fold that returned the outer `proof` variable instead of advancing
    // to `next_proof`. This kept `head` stuck at the first element, causing
    // valid revocations to be rejected when the proof's lineage had 2+ hops.
    //
    // Chain: Alice (owner) → Bob → Carol → Dave → Eve
    // Carol revokes Eve. The revocation proof is Carol→Dave, whose lineage
    // is [Bob→Carol, Alice→Bob]. At hop 2, the old code compared Carol's
    // key (stuck head) against Bob (Alice→Bob's delegate) and failed.
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
    test_utils::init_logging();

    let bob_signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    let carol_signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    let dave_signer = MemorySigner::generate(&mut rand::rngs::OsRng);

    let alice = make_simple_keyhive().await?;
    let bob = keyhive_core::keyhive::Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
        bob_signer.clone(),
        keyhive_core::store::ciphertext::memory::MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        keyhive_core::listener::no_listener::NoListener,
        rand::rngs::OsRng,
    )
    .await?;
    let carol =
        keyhive_core::keyhive::Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
            carol_signer.clone(),
            keyhive_core::store::ciphertext::memory::MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
            keyhive_core::listener::no_listener::NoListener,
            rand::rngs::OsRng,
        )
        .await?;
    let dave = keyhive_core::keyhive::Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
        dave_signer.clone(),
        keyhive_core::store::ciphertext::memory::MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        keyhive_core::listener::no_listener::NoListener,
        rand::rngs::OsRng,
    )
    .await?;
    let eve = make_simple_keyhive().await?;

    // Register everyone on Alice's keyhive
    let bob_contact = bob.generate_contact_card().await?;
    let bob_id = alice.receive_contact_card(&bob_contact).await?;

    let carol_contact = carol.generate_contact_card().await?;
    let carol_id = alice.receive_contact_card(&carol_contact).await?;
    let carol_on_alice = alice.get_individual(carol_id).await.expect("just received");

    let dave_contact = dave.generate_contact_card().await?;
    let dave_id = alice.receive_contact_card(&dave_contact).await?;
    let dave_on_alice = alice.get_individual(dave_id).await.expect("just received");

    let eve_contact = eve.generate_contact_card().await?;
    let eve_id = alice.receive_contact_card(&eve_contact).await?;
    let eve_on_alice = alice.get_individual(eve_id).await.expect("just received");

    // Alice creates Group G
    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };

    // Build the 5-level chain: Alice → Bob → Carol → Dave → Eve
    alice
        .add_member(bob_id, group_id, Access::Admin, &[])
        .await?;

    {
        let mut locked = group.lock().await;
        locked
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                Access::Admin,
                &bob_signer,
                &[],
            )
            .await?;
    }

    {
        let mut locked = group.lock().await;
        locked
            .add_member(
                Agent::Individual(dave_id, dave_on_alice.dupe()),
                Access::Admin,
                &carol_signer,
                &[],
            )
            .await?;
    }

    {
        let mut locked = group.lock().await;
        locked
            .add_member(
                Agent::Individual(eve_id, eve_on_alice.dupe()),
                Access::Edit,
                &dave_signer,
                &[],
            )
            .await?;
    }

    // Carol revokes Eve — proof is Carol→Dave, lineage [Bob→Carol, Alice→Bob].
    // The old buggy fold would reject this at the second lineage hop.
    {
        let eve_identifier: Identifier = eve_id.into();
        let mut locked = group.lock().await;
        locked
            .revoke_member(
                eve_identifier,
                true,
                &carol_signer,
                &std::collections::BTreeMap::new(),
            )
            .await?;
    }

    // Verify Eve is no longer a member
    let members = { group.lock().await.members().clone() };
    assert!(
        !members.contains_key(&eve_id.into()),
        "Eve should no longer be a member after revocation"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_can_make_public_via_sync() -> TestResult {
    // Simulates the full TPW scenario with sync:
    // 1. Alice creates the hierarchy (doc_a as admin of doc_b, Bob as admin of doc_a)
    // 2. Alice shares events to Bob
    // 3. Bob makes doc_b public on HIS keyhive (his own copy of the doc)
    // 4. Bob shares events back to Alice
    // 5. Alice should see doc_b as public
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;

    // Cross-register: Alice knows Bob, Bob knows Alice
    let bob_prekey_op = bob.expand_prekeys().await?;
    let bob_on_alice = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(bob_prekey_op),
        ),
    ));
    let bob_on_alice_id = bob_on_alice.lock().await.id();
    assert!(alice.register_individual(bob_on_alice.dupe()).await);

    let alice_prekey_op = alice.expand_prekeys().await?;
    let alice_on_bob = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(alice_prekey_op),
        ),
    ));
    let alice_on_bob_id = alice_on_bob.lock().await.id();
    assert!(bob.register_individual(alice_on_bob.dupe()).await);

    // Alice creates Account Doc A and Doc B
    let doc_a_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

    // Set up transitive admin: Bob -> Doc A -> Doc B
    alice
        .add_member(doc_a_id, doc_b_id, Access::Admin, &[])
        .await?;
    alice
        .add_member(bob_on_alice_id, doc_a_id, Access::Admin, &[])
        .await?;

    // Alice shares events to Bob
    let events_for_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    let cgka_count = events_for_bob
        .values()
        .filter(|e| matches!(e, keyhive_core::event::Event::CgkaOperation(_)))
        .count();
    eprintln!(
        "Events for Bob: {} total, {} CGKA ops",
        events_for_bob.len(),
        cgka_count
    );
    assert!(
        cgka_count > 0,
        "Bob should receive CGKA ops for docs he can transitively reach"
    );
    bob.ingest_event_table(events_for_bob).await?;

    // Verify Bob's keyhive has doc_b
    let doc_b_on_bob = bob.get_document(doc_b_id).await;
    assert!(
        doc_b_on_bob.is_some(),
        "Bob's keyhive should have doc_b after ingesting events"
    );
    let _doc_b_on_bob = doc_b_on_bob.unwrap();

    // Bob makes doc_b public on HIS keyhive
    bob.add_member(Public.id(), doc_b_id, Access::Read, &[])
        .await?;

    // Verify Public can reach doc_b on Bob's keyhive
    let public_reachable_bob = bob.docs_reachable_by_agent(Public.id()).await?;
    assert_eq!(
        public_reachable_bob.len(),
        1,
        "Public should reach doc_b on Bob's keyhive"
    );

    // Bob shares events back to Alice
    let events_for_alice = bob
        .events_for_agent(&Agent::Individual(alice_on_bob_id, alice_on_bob.dupe()))
        .await;
    alice.ingest_event_table(events_for_alice).await?;

    // Verify Public can reach doc_b on Alice's keyhive
    let public_reachable_alice = alice.docs_reachable_by_agent(Public.id()).await?;
    assert_eq!(
        public_reachable_alice.len(),
        1,
        "Public should reach doc_b on Alice's keyhive after ingesting Bob's events"
    );
    assert_eq!(
        public_reachable_alice[&doc_b_id],
        Access::Read,
        "Public should have Read access to doc_b on Alice's keyhive"
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_cgka_adds_merge_correctly() -> TestResult {
    // Scenario: Alice and Bob both have the doc with CGKA initialized.
    // Alice adds Carol, Bob adds Public — concurrently.
    // Then they sync: Alice ingests Bob's events, Bob ingests Alice's events.
    // Both should end up with the same members.
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;

    // Cross-register
    let bob_prekey_op = bob.expand_prekeys().await?;
    let bob_on_alice = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(bob_prekey_op),
        ),
    ));
    let bob_on_alice_id = bob_on_alice.lock().await.id();
    assert!(alice.register_individual(bob_on_alice.dupe()).await);

    let alice_prekey_op = alice.expand_prekeys().await?;
    let alice_on_bob = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(alice_prekey_op),
        ),
    ));
    let alice_on_bob_id = alice_on_bob.lock().await.id();
    assert!(bob.register_individual(alice_on_bob.dupe()).await);

    // Alice creates doc, adds Bob as Admin
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    alice
        .add_member(bob_on_alice_id, doc_id, Access::Admin, &[])
        .await?;

    // Share ALL events (including CGKA) to Bob so his CGKA is initialized
    let events_for_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    bob.ingest_event_table(events_for_bob).await?;

    // Now both have the doc with CGKA initialized.
    // Alice adds Carol concurrently with Bob adding Public.
    let carol = make_simple_keyhive().await?;
    let carol_prekey_op = carol.expand_prekeys().await?;
    let carol_on_alice = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(carol_prekey_op.clone()),
        ),
    ));
    let carol_on_alice_id = carol_on_alice.lock().await.id();
    assert!(alice.register_individual(carol_on_alice.dupe()).await);

    // Also register Carol on Bob
    let carol_on_bob = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(carol_prekey_op),
        ),
    ));
    assert!(bob.register_individual(carol_on_bob.dupe()).await);

    // Alice adds Carol as Edit member
    alice
        .add_member(carol_on_alice_id, doc_id, Access::Edit, &[])
        .await?;

    // Bob adds Public as Read member (concurrently, before syncing)
    bob.add_member(Public.id(), doc_id, Access::Read, &[])
        .await?;

    // Now sync: Alice sends to Bob, Bob sends to Alice
    let events_alice_to_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    let events_bob_to_alice = bob
        .events_for_agent(&Agent::Individual(alice_on_bob_id, alice_on_bob.dupe()))
        .await;

    bob.ingest_event_table(events_alice_to_bob).await?;
    alice.ingest_event_table(events_bob_to_alice).await?;

    // Both should see Carol and Public on the doc
    let alice_reachable = alice.docs_reachable_by_agent(carol_on_alice_id).await?;
    assert_eq!(
        alice_reachable.len(),
        1,
        "Alice should see Carol on the doc"
    );

    let alice_public_reachable = alice.docs_reachable_by_agent(Public.id()).await?;
    assert_eq!(
        alice_public_reachable.len(),
        1,
        "Alice should see Public on the doc after ingesting Bob's events"
    );

    let bob_public_reachable = bob.docs_reachable_by_agent(Public.id()).await?;
    assert_eq!(
        bob_public_reachable.len(),
        1,
        "Bob should still see Public on the doc"
    );

    Ok(())
}

#[tokio::test]
async fn test_competing_cgka_init_adds() -> TestResult {
    // Scenario: Two peers independently initialize CGKA for the same doc.
    // This simulates what would happen if a workaround for "CGKA not initialized"
    // was to create a new CGKA from scratch on the second device.
    //
    // Alice creates doc (CGKA initialized with Alice's init add).
    // Bob receives only delegation events (no CGKA), then independently
    // initializes CGKA with his own init add.
    // Then they try to sync CGKA ops.
    test_utils::init_logging();

    let bob_signer = MemorySigner::generate(&mut rand::rngs::OsRng);

    let alice = make_simple_keyhive().await?;
    let bob = keyhive_core::keyhive::Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
        bob_signer.clone(),
        keyhive_core::store::ciphertext::memory::MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        keyhive_core::listener::no_listener::NoListener,
        rand::rngs::OsRng,
    )
    .await?;

    // Cross-register
    let bob_prekey_op = bob.expand_prekeys().await?;
    let bob_on_alice = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(bob_prekey_op),
        ),
    ));
    let bob_on_alice_id = bob_on_alice.lock().await.id();
    assert!(alice.register_individual(bob_on_alice.dupe()).await);

    let alice_prekey_op = alice.expand_prekeys().await?;
    let alice_on_bob = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(alice_prekey_op),
        ),
    ));
    let _alice_on_bob_id = alice_on_bob.lock().await.id();
    assert!(bob.register_individual(alice_on_bob.dupe()).await);

    // Alice creates doc with Bob as Admin
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;

    alice
        .add_member(bob_on_alice_id, doc_id, Access::Admin, &[])
        .await?;

    // Share only delegation events (no CGKA) to Bob
    let events_for_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    let events_without_cgka: std::collections::HashMap<_, _> = events_for_bob
        .into_iter()
        .filter(|(_, event)| !matches!(event, keyhive_core::event::Event::CgkaOperation(_)))
        .collect();
    bob.ingest_event_table(events_without_cgka).await?;

    // Bob has the doc but with cgka=None
    let doc_on_bob = bob.get_document(doc_id).await.unwrap();

    // Bob independently initializes CGKA with his own init add.
    {
        let mut locked = doc_on_bob.lock().await;
        let bob_active_id = bob.active().lock().await.id();
        let bob_pk = bob.active().lock().await.pick_prekey(doc_id).await;

        let doc_tree_id: beekem::id::TreeId = doc_id.verifying_key().into();
        let bob_member_id: beekem::id::MemberId = bob_active_id.verifying_key().into();
        let init_add =
            beekem::operation::CgkaOperation::init_add(doc_tree_id, bob_member_id, bob_pk);
        let signed_init = keyhive_crypto::signer::async_signer::try_sign_async::<
            future_form::Sendable,
            _,
            _,
        >(&bob_signer, init_add)
        .await?;

        locked.merge_cgka_op(std::sync::Arc::new(signed_init))?;
    }

    // Now Alice sends her CGKA ops to Bob (including Alice's init add)
    let all_events_for_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    let cgka_only: std::collections::HashMap<_, _> = all_events_for_bob
        .into_iter()
        .filter(|(_, event)| matches!(event, keyhive_core::event::Event::CgkaOperation(_)))
        .collect();

    // Try to ingest Alice's CGKA ops — this is where competing init adds collide
    let result = bob.ingest_event_table(cgka_only).await;
    eprintln!("Ingest result: {:?}", result);

    // Even if ingest succeeded, try to use the CGKA to see if it's consistent.
    // Bob tries to add Public as a reader — this exercises the CGKA add path.
    let add_result = bob.add_member(Public.id(), doc_id, Access::Read, &[]).await;
    eprintln!(
        "Add Public after competing init adds: {:?}",
        add_result.as_ref().map(|_| "ok")
    );

    // Check: can Bob still see the doc's transitive members?
    let bob_public_reachable = bob.docs_reachable_by_agent(Public.id()).await?;
    eprintln!(
        "Public reachable on Bob after competing init adds: {}",
        bob_public_reachable.len()
    );

    Ok(())
}

/// A Document referenced as a delegate (member of another doc) before its own
/// defining delegation arrives must be reified as a Document, not a Group.
///
/// When the cross-delegation `subject = Doc B, delegate = Doc A` is ingested
/// before Doc A's defining (root) delegation, Doc A is an unknown delegate.
/// The unknown-delegate recovery registers a placeholder Individual for Doc A's
/// id. Earlier, when Doc A's defining delegation finally arrived, that
/// placeholder was unconditionally promoted to a *Group*, dropping Doc A's
/// content heads. It must instead become a Document because the defining
/// delegation carries content heads for that id.
#[tokio::test]
async fn test_document_delegate_before_defining_event_reified_as_document() -> TestResult {
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;

    // Alice owns Doc A and Doc B, and adds Doc A as a Read member of Doc B.
    let doc_a_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

    alice
        .add_member(doc_a_id, doc_b_id, Access::Read, &[])
        .await?;

    // Collect all of Alice's events, then split out Doc A's defining (root)
    // delegation, i.e. the one issued by Doc A itself, so it is delivered last.
    let alice_agent: Agent<_, _, _, _> = alice.active().lock().await.clone().into();
    let all_events = alice.static_events_for_agent(&alice_agent).await;

    let doc_a_ident: Identifier = doc_a_id.into();
    let mut defining: Vec<StaticEvent<[u8; 32]>> = vec![];
    let mut rest: Vec<StaticEvent<[u8; 32]>> = vec![];
    for event in all_events.into_values() {
        match &event {
            StaticEvent::Delegated(signed)
                if Identifier(signed.issuer) == doc_a_ident && signed.payload.proof.is_none() =>
            {
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

    // Fresh peer receives everything except Doc A's defining delegation first.
    let carol = make_simple_keyhive().await?;
    let pending = carol.ingest_unsorted_static_events(rest).await;

    // Before its defining delegation arrives, Doc A is unknown: the delegation
    // that references it as a delegate stays pending rather than fabricating a
    // stand-in for it.
    assert!(
        !pending.is_empty(),
        "the delegation referencing Doc A should remain pending"
    );
    assert!(
        carol.get_agent(doc_a_ident).await.is_none(),
        "Doc A should be unknown before its defining delegation arrives"
    );
    assert!(
        carol.get_document(doc_a_id).await.is_none(),
        "Doc A should not yet be registered as a Document"
    );

    // Deliver Doc A's defining delegation (plus any pending events).
    carol.ingest_unsorted_static_events(defining).await;

    // Doc A must now be reified as a Document, not a Group.
    assert!(
        matches!(
            carol.get_agent(doc_a_ident).await,
            Some(Agent::Document(..))
        ),
        "Doc A must be reified as a Document, not a Group, after its defining delegation"
    );
    assert!(
        carol.get_document(doc_a_id).await.is_some(),
        "Doc A should be registered in the docs map"
    );

    Ok(())
}

/// Companion to the Document case: a Group referenced as a delegate before its
/// defining delegation arrives must still be reified as a Group. Its defining
/// delegation carries no content heads, so it must not become a Document.
#[tokio::test]
async fn test_group_delegate_before_defining_event_reified_as_group() -> TestResult {
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;

    // Alice owns Group G and Doc B, and adds Group G as a Read member of Doc B.
    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let doc_b_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

    alice
        .add_member(group_id, doc_b_id, Access::Read, &[])
        .await?;

    // Split out Group G's defining (root) delegation, issued by G itself.
    let alice_agent: Agent<_, _, _, _> = alice.active().lock().await.clone().into();
    let all_events = alice.static_events_for_agent(&alice_agent).await;

    let group_ident: Identifier = group_id.into();
    let mut defining: Vec<StaticEvent<[u8; 32]>> = vec![];
    let mut rest: Vec<StaticEvent<[u8; 32]>> = vec![];
    for event in all_events.into_values() {
        match &event {
            StaticEvent::Delegated(signed)
                if Identifier(signed.issuer) == group_ident && signed.payload.proof.is_none() =>
            {
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

    // Before its defining delegation arrives, Group G is unknown: the delegation
    // that references it as a delegate stays pending rather than fabricating a
    // stand-in for it.
    assert!(
        !pending.is_empty(),
        "the delegation referencing Group G should remain pending"
    );
    assert!(
        carol.get_agent(group_ident).await.is_none(),
        "Group G should be unknown before its defining delegation arrives"
    );

    carol.ingest_unsorted_static_events(defining).await;

    // Group G must be reified as a Group, and must not become a Document.
    assert!(
        matches!(carol.get_agent(group_ident).await, Some(Agent::Group(..))),
        "Group G must be reified as a Group after its defining delegation"
    );
    assert!(
        carol
            .get_document(DocumentId::from(group_ident))
            .await
            .is_none(),
        "Group G must not be modeled as a Document"
    );

    Ok(())
}
