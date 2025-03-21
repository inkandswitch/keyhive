use dupe::Dupe;
use keyhive_core::{
    access::Access, crypto::signer::memory::MemorySigner, keyhive::Keyhive,
    listener::no_listener::NoListener, principal::individual::Individual,
};
use nonempty::nonempty;
use std::{cell::RefCell, rc::Rc};
use testresult::TestResult;

// TODO move to test utils
async fn make_keyhive() -> Keyhive<MemorySigner> {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    Keyhive::generate(sk, NoListener, rand::thread_rng())
        .await
        .unwrap()
}

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

    let mut alice = make_keyhive().await;
    let mut bob = make_keyhive().await;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact)?;

    let group = alice.generate_group(vec![]).await?;
    alice
        .add_member(
            bob_on_alice.dupe().into(),
            &mut group.dupe().into(),
            Access::Read,
            &vec![],
        )
        .await?;

    let doc = alice
        .generate_doc(vec![group.dupe().into()], nonempty![[0u8; 32]])
        .await?;

    let reachable = alice.docs_reachable_by_agent(&bob_on_alice.dupe().into());
    assert_eq!(reachable.len(), 1);
    assert_eq!(
        reachable.get(&doc.borrow().doc_id()).unwrap().can(),
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

    let mut alice = make_keyhive().await;
    let mut bob = make_keyhive().await;

    let bob_contact = bob.contact_card().await?;
    let bob_on_alice = alice.receive_contact_card(&bob_contact)?;

    let group = alice.generate_group(vec![]).await?;
    alice
        .add_member(
            bob_on_alice.dupe().into(),
            &mut group.dupe().into(),
            Access::Read,
            &vec![],
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
            &vec![],
        )
        .await?;

    let reachable = alice.docs_reachable_by_agent(&bob_on_alice.dupe().into());
    assert_eq!(reachable.len(), 1);
    assert_eq!(
        reachable.get(&doc.borrow().doc_id()).unwrap().can(),
        Access::Read
    );
    Ok(())
}
