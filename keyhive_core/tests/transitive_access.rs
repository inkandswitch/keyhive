use dupe::Dupe;
use keyhive_core::{access::Access, test_utils::make_simple_keyhive};
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

    let mut alice = make_simple_keyhive().await?;
    let mut bob = make_simple_keyhive().await?;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact)?;

    let group = alice.generate_group(vec![]).await?;
    alice
        .add_member(
            bob_on_alice.dupe().into(),
            &mut group.dupe().into(),
            Access::Read,
            &[],
        )
        .await?;

    let doc = alice
        .generate_doc(vec![group.dupe().into()], nonempty![[0u8; 32]])
        .await?;

    let reachable = alice.docs_reachable_by_agent(&bob_on_alice.dupe().into());
    let locked_doc = doc.lock().await;
    assert_eq!(reachable.len(), 1);
    assert_eq!(
        reachable.get(&locked_doc.doc_id()).unwrap().can(),
        Access::Read
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

    let mut alice = make_simple_keyhive().await?;
    let mut bob = make_simple_keyhive().await?;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact)?;

    let group = alice.generate_group(vec![]).await?;
    alice
        .add_member(
            bob_on_alice.dupe().into(),
            &mut group.dupe().into(),
            Access::Read,
            &[],
        )
        .await?;

    let doc = alice
        .generate_doc(vec![group.dupe().into()], nonempty![[0u8; 32]])
        .await?;

    alice
        .add_member(
            group.dupe().into(),
            &mut doc.dupe().into(),
            Access::Read,
            &[],
        )
        .await?;

    let reachable = alice.docs_reachable_by_agent(&bob_on_alice.dupe().into());
    assert_eq!(reachable.len(), 1);
    {
        let locked = doc.lock().await;
        assert_eq!(reachable.get(&locked.doc_id()).unwrap().can(), Access::Read);
    }
    Ok(())
}
