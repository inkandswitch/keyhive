use dupe::Dupe;
use keyhive_core::{
    access::Access,
    principal::{agent::Agent, membered::Membered, peer::Peer},
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::signer::memory::MemorySigner;
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
