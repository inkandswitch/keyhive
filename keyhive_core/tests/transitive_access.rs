use dupe::Dupe;
use keyhive_core::{
    access::Access,
    principal::{agent::Agent, membered::Membered, peer::Peer},
    test_utils::make_simple_keyhive,
};
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
