use dupe::Dupe;
use keyhive_core::{
    access::Access,
    principal::{agent::Agent, identifier::Identifier, membered::Membered, peer::Peer},
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
use nonempty::nonempty;
use testresult::TestResult;

#[tokio::test]
async fn test_group_members_have_access_to_group_docs() -> TestResult {
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
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;

    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let bob_id = { bob_on_alice.lock().await.id() };
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Group(group_id, group.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    let doc = alice
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![[0u8; 32]],
        )
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    let reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(bob_id, bob_on_alice.dupe()))
        .await;
    assert_eq!(reachable.len(), 1);
    assert_eq!(reachable.get(&doc_id).unwrap().can(), Access::Read);
    Ok(())
}

#[tokio::test]
async fn test_individual_admin_on_doc_transitively_reaches_child_doc() -> TestResult {
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
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    // Alice creates Doc A (she is the owner/admin)
    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    // Alice creates Doc B (she is the owner/admin)
    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Alice grants Bob Admin access on Doc A
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Alice adds Doc A as an Admin member of Doc B
    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Check which docs Bob can reach transitively
    let reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(bob_id, bob_on_alice.dupe()))
        .await;

    // Bob should be able to reach both Doc A and Doc B
    assert_eq!(reachable.len(), 2, "Bob should reach both Doc A and Doc B");
    assert_eq!(
        reachable.get(&doc_a_id).unwrap().can(),
        Access::Admin,
        "Bob should have Admin access to Doc A"
    );
    assert_eq!(
        reachable.get(&doc_b_id).unwrap().can(),
        Access::Admin,
        "Bob should have Admin access to Doc B transitively through Doc A"
    );

    Ok(())
}

#[tokio::test]
async fn test_group_members_cycle() -> TestResult {
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
    test_utils::init_logging();

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;

    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let bob_id = { bob_on_alice.lock().await.id() };
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Group(group_id, group.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    let doc = alice
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![[0u8; 32]],
        )
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    alice
        .add_member(
            Agent::Group(group_id, group.dupe()),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    let reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(bob_id, bob_on_alice.dupe()))
        .await;

    assert_eq!(reachable.len(), 1);
    assert_eq!(reachable.get(&doc_id).unwrap().can(), Access::Read);
    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_can_delegate() -> TestResult {
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
    test_utils::init_logging();

    // Create Bob's signer externally so we can use it to sign directly.
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

    // Register Bob and Carol on Alice's keyhive
    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    let carol_contact = carol.contact_card().await?;
    let carol_on_alice = alice.receive_contact_card(&carol_contact).await?;
    let carol_id = { carol_on_alice.lock().await.id() };

    // Alice creates Account Doc A and Doc B
    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Alice adds Account Doc A as Admin member of Doc B
    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Alice adds Bob as Admin member of Account Doc A
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Verify Bob can reach Doc B transitively
    let reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(bob_id, bob_on_alice.dupe()))
        .await;
    assert_eq!(reachable.len(), 2, "Bob should reach both Doc A and Doc B");
    assert_eq!(
        reachable.get(&doc_b_id).unwrap().can(),
        Access::Admin,
        "Bob should have Admin access to Doc B transitively"
    );

    // KEY TEST: Bob (via his signer) adds Carol as Edit member of Doc B.
    // This exercises the transitive proof path in add_member_with_manual_content.
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

    // Verify Carol can now reach Doc B
    let carol_reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_id, carol_on_alice.dupe()))
        .await;
    assert_eq!(carol_reachable.len(), 1, "Carol should reach Doc B");
    assert_eq!(
        carol_reachable.get(&doc_b_id).unwrap().can(),
        Access::Edit,
        "Carol should have Edit access to Doc B"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_read_cannot_delegate_admin() -> TestResult {
    // Scenario:
    // Alice owns Doc A and Doc B.
    // Alice adds Doc A as Admin member of Doc B.
    // Alice adds Bob as READ member of Doc A.
    //
    // Bob has transitive Read access to Doc B.
    // Bob tries to add Carol as Admin of Doc B — should fail with AccessEscalation.
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

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    let carol_contact = carol.contact_card().await?;
    let carol_on_alice = alice.receive_contact_card(&carol_contact).await?;
    let carol_id = { carol_on_alice.lock().await.id() };

    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Doc A as Admin of Doc B
    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Bob as READ of Doc A (not Admin)
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // Bob tries to add Carol as Admin of Doc B — should fail
    let result = {
        let mut locked = doc_b.lock().await;
        locked
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                Access::Admin,
                &bob_signer,
                &[],
            )
            .await
    };

    assert!(
        result.is_err(),
        "Should fail: Bob has Read, tried to delegate Admin"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("escalation") || err_msg.contains("Escalation"),
        "Error should be an access escalation, got: {}",
        err_msg
    );

    // Bob should still be able to add Carol as Read (within his access level)
    {
        let mut locked = doc_b.lock().await;
        locked
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                Access::Read,
                &bob_signer,
                &[],
            )
            .await?;
    }

    let carol_reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_id, carol_on_alice.dupe()))
        .await;
    assert_eq!(
        carol_reachable.len(),
        1,
        "Carol should reach Doc B with Read"
    );
    assert_eq!(
        carol_reachable.get(&doc_b_id).unwrap().can(),
        Access::Read,
        "Carol should have Read access to Doc B"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_can_delegate_via_group() -> TestResult {
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

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    let carol_contact = carol.contact_card().await?;
    let carol_on_alice = alice.receive_contact_card(&carol_contact).await?;
    let carol_id = { carol_on_alice.lock().await.id() };

    // Alice creates Group G and Doc B
    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Alice adds Group G as Admin member of Doc B
    alice
        .add_member(
            Agent::Group(group_id, group.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Alice adds Bob as Admin member of Group G
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Group(group_id, group.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Verify Bob can reach Doc B transitively
    let reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(bob_id, bob_on_alice.dupe()))
        .await;
    assert_eq!(reachable.len(), 1, "Bob should reach Doc B");

    // KEY TEST: Bob adds Carol as Edit member of Doc B via transitive access.
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

    // Verify Carol can now reach Doc B
    let carol_reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_id, carol_on_alice.dupe()))
        .await;
    assert_eq!(carol_reachable.len(), 1, "Carol should reach Doc B");
    assert_eq!(
        carol_reachable.get(&doc_b_id).unwrap().can(),
        Access::Edit,
        "Carol should have Edit access to Doc B"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_can_revoke() -> TestResult {
    // Same hierarchy as test_transitive_admin_can_delegate.
    // After Bob adds Carol, Bob should also be able to revoke Carol.
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

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    let carol_contact = carol.contact_card().await?;
    let carol_on_alice = alice.receive_contact_card(&carol_contact).await?;
    let carol_id = { carol_on_alice.lock().await.id() };

    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Alice adds Doc A as Admin of Doc B, Bob as Admin of Doc A
    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Admin,
            &[],
        )
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
    let carol_reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_id, carol_on_alice.dupe()))
        .await;
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
    let carol_reachable_after = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_id, carol_on_alice.dupe()))
        .await;
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

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    let carol_contact = carol.contact_card().await?;
    let carol_on_alice = alice.receive_contact_card(&carol_contact).await?;
    let carol_id = { carol_on_alice.lock().await.id() };

    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Alice adds Group G as Admin of Doc B, Bob as Admin of Group G
    alice
        .add_member(
            Agent::Group(group_id, group.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Group(group_id, group.dupe()),
            Access::Admin,
            &[],
        )
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
    let carol_reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_id, carol_on_alice.dupe()))
        .await;
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
    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact).await?;
    let bob_id = { bob_on_alice.lock().await.id() };

    let carol_contact = carol.contact_card().await?;
    let carol_on_alice = alice.receive_contact_card(&carol_contact).await?;
    let carol_id = { carol_on_alice.lock().await.id() };

    let dave_contact = dave.contact_card().await?;
    let dave_on_alice = alice.receive_contact_card(&dave_contact).await?;
    let dave_id = { dave_on_alice.lock().await.id() };

    let eve_contact = eve.contact_card().await?;
    let eve_on_alice = alice.receive_contact_card(&eve_contact).await?;
    let eve_id = { eve_on_alice.lock().await.id() };

    // Alice creates Group G
    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };

    // Build the 5-level chain: Alice → Bob → Carol → Dave → Eve
    alice
        .add_member(
            Agent::Individual(bob_id, bob_on_alice.dupe()),
            &Membered::Group(group_id, group.dupe()),
            Access::Admin,
            &[],
        )
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
    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Set up transitive admin: Bob -> Doc A -> Doc B
    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;
    alice
        .add_member(
            Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Admin,
            &[],
        )
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
    let doc_b_on_bob = doc_b_on_bob.unwrap();

    // Bob makes doc_b public on HIS keyhive
    let public_individual = keyhive_core::principal::public::Public.individual();
    let public_agent: Agent<_, _, _, _> = Agent::Individual(
        public_individual.id(),
        std::sync::Arc::new(futures::lock::Mutex::new(public_individual)),
    );
    bob.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_b_id, doc_b_on_bob.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    // Verify Public can reach doc_b on Bob's keyhive
    let public_reachable_bob = bob.docs_reachable_by_agent(&public_agent).await;
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
    let public_reachable_alice = alice.docs_reachable_by_agent(&public_agent).await;
    assert_eq!(
        public_reachable_alice.len(),
        1,
        "Public should reach doc_b on Alice's keyhive after ingesting Bob's events"
    );
    assert_eq!(
        public_reachable_alice.get(&doc_b_id).unwrap().can(),
        Access::Read,
        "Public should have Read access to doc_b on Alice's keyhive"
    );

    Ok(())
}

#[tokio::test]
async fn test_transitive_admin_make_public_fails_without_cgka_ops() -> TestResult {
    // Simulates the scenario where Bob receives membership ops (delegations)
    // but NOT the CGKA ops. When Bob tries to make doc_b public (adding a
    // reader, which triggers CGKA), it should fail with "Cgka is not initialized".
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
    assert!(bob.register_individual(alice_on_bob.dupe()).await);

    // Alice creates hierarchy
    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;
    alice
        .add_member(
            Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Share events to Bob, but FILTER OUT CGKA ops to simulate partial sync
    let events_for_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    let events_without_cgka: std::collections::HashMap<_, _> = events_for_bob
        .into_iter()
        .filter(|(_, event)| !matches!(event, keyhive_core::event::Event::CgkaOperation(_)))
        .collect();
    bob.ingest_event_table(events_without_cgka).await?;

    // Bob should have doc_b but with CGKA uninitialized
    let doc_b_on_bob = bob.get_document(doc_b_id).await;
    assert!(
        doc_b_on_bob.is_some(),
        "Bob should have doc_b from delegation events"
    );
    let doc_b_on_bob = doc_b_on_bob.unwrap();

    // Bob tries to make doc_b public — this should fail because CGKA is not initialized
    let public_individual = keyhive_core::principal::public::Public.individual();
    let public_agent: Agent<_, _, _, _> = Agent::Individual(
        public_individual.id(),
        std::sync::Arc::new(futures::lock::Mutex::new(public_individual)),
    );
    let result = bob
        .add_member(
            public_agent.dupe(),
            &Membered::Document(doc_b_id, doc_b_on_bob.dupe()),
            Access::Read,
            &[],
        )
        .await;

    assert!(
        result.is_err(),
        "add_member should fail when CGKA is not initialized. Got: {:?}",
        result
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("not initialized"),
        "Error should mention CGKA not initialized, got: {}",
        err_msg
    );

    // KEY QUESTION: Even though add_member failed, the delegation was applied
    // locally (before the CGKA error). Check whether Bob's events for Alice
    // include the Public delegation.
    let alice_on_bob_id = alice_on_bob.lock().await.id();
    let events_for_alice = bob
        .events_for_agent(&Agent::Individual(alice_on_bob_id, alice_on_bob.dupe()))
        .await;
    let delegation_count = events_for_alice
        .values()
        .filter(|e| matches!(e, keyhive_core::event::Event::Delegated(_)))
        .count();
    eprintln!(
        "Events from Bob for Alice: {} total, {} delegations",
        events_for_alice.len(),
        delegation_count
    );

    // Check if the Public delegation is in the events
    let has_public_delegation = events_for_alice.values().any(|e| {
        if let keyhive_core::event::Event::Delegated(dlg) = e {
            dlg.payload.delegate().id() == public_agent.id()
        } else {
            false
        }
    });
    eprintln!(
        "Has Public delegation in events for Alice: {}",
        has_public_delegation
    );

    // Try ingesting on Alice's side to see if the delegation arrives
    if has_public_delegation {
        alice.ingest_event_table(events_for_alice).await?;
        let public_reachable = alice.docs_reachable_by_agent(&public_agent).await;
        eprintln!(
            "Public reachable on Alice after ingesting Bob's events (no CGKA): {}",
            public_reachable.len()
        );
    }

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
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    alice
        .add_member(
            Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Share ALL events (including CGKA) to Bob so his CGKA is initialized
    let events_for_bob = alice
        .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
        .await;
    bob.ingest_event_table(events_for_bob).await?;

    let doc_on_bob = bob.get_document(doc_id).await.unwrap();

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
        .add_member(
            Agent::Individual(carol_on_alice_id, carol_on_alice.dupe()),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Edit,
            &[],
        )
        .await?;

    // Bob adds Public as Read member (concurrently, before syncing)
    let public_individual = keyhive_core::principal::public::Public.individual();
    let public_agent: Agent<_, _, _, _> = Agent::Individual(
        public_individual.id(),
        std::sync::Arc::new(futures::lock::Mutex::new(public_individual)),
    );
    bob.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc_on_bob.dupe()),
        Access::Read,
        &[],
    )
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
    let alice_reachable = alice
        .docs_reachable_by_agent(&Agent::Individual(carol_on_alice_id, carol_on_alice.dupe()))
        .await;
    assert_eq!(
        alice_reachable.len(),
        1,
        "Alice should see Carol on the doc"
    );

    let alice_public_reachable = alice.docs_reachable_by_agent(&public_agent).await;
    assert_eq!(
        alice_public_reachable.len(),
        1,
        "Alice should see Public on the doc after ingesting Bob's events"
    );

    let bob_public_reachable = bob.docs_reachable_by_agent(&public_agent).await;
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
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    alice
        .add_member(
            Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Admin,
            &[],
        )
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
    let public_individual = keyhive_core::principal::public::Public.individual();
    let public_agent: Agent<_, _, _, _> = Agent::Individual(
        public_individual.id(),
        std::sync::Arc::new(futures::lock::Mutex::new(public_individual)),
    );
    let add_result = bob
        .add_member(
            public_agent.dupe(),
            &Membered::Document(doc_id, doc_on_bob.dupe()),
            Access::Read,
            &[],
        )
        .await;
    eprintln!(
        "Add Public after competing init adds: {:?}",
        add_result.as_ref().map(|_| "ok")
    );

    // Check: can Bob still see the doc's transitive members?
    let bob_public_reachable = bob.docs_reachable_by_agent(&public_agent).await;
    eprintln!(
        "Public reachable on Bob after competing init adds: {}",
        bob_public_reachable.len()
    );

    Ok(())
}

#[tokio::test]
async fn test_stuck_pending_events_dont_poison_new_events() -> TestResult {
    // Regression test for the pending event poisoning bug.
    //
    // Scenario (mirrors production):
    // 1. Alice creates a transitive hierarchy: doc_a as admin of doc_b,
    //    Bob as admin of doc_a, server as relay on both docs.
    // 2. Alice syncs to server (server ingests all events, 0 pending).
    // 3. Server syncs to Bob (Bob gets the full hierarchy).
    // 4. Bob makes doc_b public (creates delegation + CGKA events, ALL
    //    with proof chain dependencies — no root delegations).
    // 5. We extract ONLY Bob's NEW events (not already on the server).
    // 6. We inject permanently-stuck poison pending events on the server.
    // 7. We ingest Bob's new events on the server.
    // 8. Assert: server processes Bob's events despite the poison.
    //
    // Bug (old code): ingest_unsorted_static_events combines incoming
    // events with ALL pre-existing pending events, then retries in a
    // loop. Fixed-point detection checks the combined batch size. If
    // poison pending events prevent the batch from shrinking, ALL events
    // (including valid new ones) get swept into pending.
    //
    // Fix: process new events separately from old pending, so poison
    // pending events can't mask progress on new events.
    test_utils::init_logging();

    use keyhive_core::event::static_event::StaticEvent;
    use std::collections::HashSet;

    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let server = make_simple_keyhive().await?;

    // --- Register everyone with everyone ---

    let alice_prekey = alice.expand_prekeys().await?;
    let bob_prekey = bob.expand_prekeys().await?;
    let server_prekey = server.expand_prekeys().await?;

    // Alice's view of Bob and Server
    let bob_on_alice = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(bob_prekey.clone()),
        ),
    ));
    let bob_on_alice_id = bob_on_alice.lock().await.id();
    alice.register_individual(bob_on_alice.dupe()).await;

    let server_on_alice = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(server_prekey.clone()),
        ),
    ));
    let server_on_alice_id = server_on_alice.lock().await.id();
    alice.register_individual(server_on_alice.dupe()).await;

    // Bob's view of Alice and Server
    let alice_on_bob = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(alice_prekey.clone()),
        ),
    ));
    bob.register_individual(alice_on_bob.dupe()).await;

    let server_on_bob = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(server_prekey.clone()),
        ),
    ));
    let server_on_bob_id = server_on_bob.lock().await.id();
    bob.register_individual(server_on_bob.dupe()).await;

    // Server's view of Alice and Bob
    let alice_on_server = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(alice_prekey),
        ),
    ));
    server.register_individual(alice_on_server.dupe()).await;

    let bob_on_server = std::sync::Arc::new(futures::lock::Mutex::new(
        keyhive_core::principal::individual::Individual::new(
            keyhive_core::principal::individual::op::KeyOp::Add(bob_prekey),
        ),
    ));
    let bob_on_server_id = bob_on_server.lock().await.id();
    server.register_individual(bob_on_server.dupe()).await;

    // --- Step 1: Alice creates transitive hierarchy ---

    let doc_a = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let doc_a_id = { doc_a.lock().await.doc_id() };

    let doc_b = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
    let doc_b_id = { doc_b.lock().await.doc_id() };

    // Server as relay on both docs
    alice
        .add_member(
            Agent::Individual(server_on_alice_id, server_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Read,
            &[],
        )
        .await?;
    alice
        .add_member(
            Agent::Individual(server_on_alice_id, server_on_alice.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // doc_a as Admin of doc_b (transitive hierarchy)
    alice
        .add_member(
            Agent::Document(doc_a_id, doc_a.dupe()),
            &Membered::Document(doc_b_id, doc_b.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // Bob as Admin of doc_a
    alice
        .add_member(
            Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()),
            &Membered::Document(doc_a_id, doc_a.dupe()),
            Access::Admin,
            &[],
        )
        .await?;

    // --- Step 2: Alice syncs to Server ---

    let alice_events_for_server = alice
        .static_events_for_agent(&Agent::Individual(
            server_on_alice_id,
            server_on_alice.dupe(),
        ))
        .await;
    eprintln!("Alice -> Server: {} events", alice_events_for_server.len());

    let server_pending = server
        .ingest_unsorted_static_events(alice_events_for_server.into_values().collect())
        .await;
    assert_eq!(
        server_pending.len(),
        0,
        "Server should ingest all of Alice's events"
    );

    // --- Step 3: Server syncs to Bob ---

    let server_events_for_bob = server
        .static_events_for_agent(&Agent::Individual(bob_on_server_id, bob_on_server.dupe()))
        .await;
    eprintln!("Server -> Bob: {} events", server_events_for_bob.len());

    let bob_pending = bob
        .ingest_unsorted_static_events(server_events_for_bob.into_values().collect())
        .await;
    eprintln!("Bob pending: {}", bob_pending.len());

    // Verify Bob has doc_b
    let bob_doc_b = bob.get_document(doc_b_id).await;
    assert!(bob_doc_b.is_some(), "Bob should have doc_b after sync");
    let bob_doc_b = bob_doc_b.unwrap();

    // Capture Bob's event set BEFORE making public (to compute diff later)
    let bob_events_before: HashSet<_> = bob
        .static_events_for_agent(&Agent::Individual(server_on_bob_id, server_on_bob.dupe()))
        .await
        .keys()
        .cloned()
        .collect();

    // --- Step 4: Bob makes doc_b public ---

    let public_individual = keyhive_core::principal::public::Public.individual();
    let public_agent: Agent<_, _, _, _> = Agent::Individual(
        public_individual.id(),
        std::sync::Arc::new(futures::lock::Mutex::new(public_individual)),
    );
    bob.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_b_id, bob_doc_b.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    // --- Step 5: Extract ONLY Bob's new events ---

    let bob_events_after = bob
        .static_events_for_agent(&Agent::Individual(server_on_bob_id, server_on_bob.dupe()))
        .await;

    let new_events: Vec<_> = bob_events_after
        .into_iter()
        .filter(|(hash, _)| !bob_events_before.contains(hash))
        .map(|(_, event)| event)
        .collect();
    eprintln!(
        "Bob's new events: {} (all should have proof chain dependencies)",
        new_events.len()
    );
    assert!(
        !new_events.is_empty(),
        "Bob should have new events after making doc public"
    );

    // Verify all delegation events have proofs (no root delegations)
    for event in &new_events {
        if let StaticEvent::Delegated(d) = event {
            assert!(
                d.payload().proof.is_some(),
                "Bob's new delegation should have a proof (transitive delegation)"
            );
        }
    }

    // --- Step 6: Inject poison pending events on server ---

    // Create poison: delegation events from stranger keyhives whose proof
    // references don't exist on the server. These permanently fail with
    // MissingDelegation.
    let mut poison_events = Vec::new();
    for i in 0..30 {
        let s = make_simple_keyhive().await?;
        let sp = s.expand_prekeys().await?;
        let si = std::sync::Arc::new(futures::lock::Mutex::new(
            keyhive_core::principal::individual::Individual::new(
                keyhive_core::principal::individual::op::KeyOp::Add(sp),
            ),
        ));
        let si_id = si.lock().await.id();
        s.register_individual(si.dupe()).await;
        let sd = s.generate_doc(vec![], nonempty![[i as u8; 32]]).await?;
        let sd_id = { sd.lock().await.doc_id() };
        s.add_member(
            Agent::Individual(si_id, si.dupe()),
            &Membered::Document(sd_id, sd.dupe()),
            Access::Read,
            &[],
        )
        .await?;
        let sevents: Vec<_> = s
            .static_events_for_agent(&Agent::Individual(si_id, si.dupe()))
            .await
            .into_values()
            .filter(|e| matches!(e, StaticEvent::Delegated(d) if d.payload().proof.is_some()))
            .collect();
        poison_events.extend(sevents);
    }

    let poison_count = poison_events.len();
    eprintln!("Injecting {} poison pending events", poison_count);
    assert!(
        poison_count > new_events.len(),
        "Need more poison ({}) than new events ({})",
        poison_count,
        new_events.len()
    );

    server.inject_pending_events(poison_events).await;

    // --- Step 7: Ingest Bob's new events ---

    let pending_after = server.ingest_unsorted_static_events(new_events).await;
    eprintln!(
        "After ingesting Bob's events: {} pending (poison was {})",
        pending_after.len(),
        poison_count,
    );

    // --- Step 8: Assert server processed Bob's events ---

    // The pending count should be exactly the poison count — Bob's events
    // should have been processed, not swept into pending.
    assert_eq!(
        pending_after.len(),
        poison_count,
        "Pending should be exactly the poison count ({}), not more. \
         If pending is {}, Bob's events were poisoned by stuck pending events.",
        poison_count,
        pending_after.len(),
    );

    // Verify the server sees doc_b as public
    let public_reachable = server.docs_reachable_by_agent(&public_agent).await;
    assert_eq!(
        public_reachable.len(),
        1,
        "Server should see doc_b as public after ingesting Bob's events"
    );
    assert_eq!(
        public_reachable.get(&doc_b_id).unwrap().can(),
        Access::Read,
        "Public should have Read access to doc_b on server"
    );

    Ok(())
}
