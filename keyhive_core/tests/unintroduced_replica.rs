//! Syncing a revocation to a replica that has never met the member it revokes.

use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    principal::{
        document::id::DocumentId,
        individual::{id::IndividualId, op::KeyOp, Individual},
    },
    test_utils::make_simple_keyhive,
};
use nonempty::nonempty;
use std::sync::Arc;
use testresult::TestResult;

type Kh = keyhive_core::test_utils::Hive;

/// Introduce `who` to `observer`, so `observer` can add `who` to a document.
async fn introduce(observer: &Kh, who: &Kh) -> TestResult<IndividualId> {
    let prekey = who.expand_prekeys().await?;
    let indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(prekey))));
    let id = { indie.lock().await.id() };
    observer.register_individual(indie).await;
    Ok(id)
}

/// Deliver everything `from` holds that `to` is entitled to. Returns the number
/// of events `to` could not apply.
async fn sync_to(from: &Kh, to: &Kh) -> usize {
    let events = from.static_events_for_agent(to.id()).await;
    to.ingest_unsorted_static_events(events.into_values().collect())
        .await
        .len()
}

/// The individuals seated in `observer`'s tree for `doc`.
async fn seated(observer: &Kh, doc: DocumentId) -> Vec<IndividualId> {
    let mut ids: Vec<_> = observer
        .cgka_members_for(doc)
        .await
        .expect("knows the document")
        .expect("an initialized tree")
        .into_iter()
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn a_replica_that_never_met_the_revoked_member_takes_the_revocation_in() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let erin = make_simple_keyhive().await?;
    let dave = make_simple_keyhive().await?;
    let bob_id = introduce(&alice, &bob).await?;
    let dave_id = introduce(&alice, &dave).await?;

    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Access::Admin, &[]).await?;
    alice.add_member(dave_id, doc_id, Access::Read, &[]).await?;
    assert_eq!(sync_to(&alice, &bob).await, 0, "bob took the setup");

    // Bob's delegation to Erin is proved by Bob's own, which Alice revokes
    // below. Dave has met neither of them.
    let erin_id = introduce(&bob, &erin).await?;
    bob.add_member(erin_id, doc_id, Access::Read, &[]).await?;
    assert_eq!(
        sync_to(&bob, &alice).await,
        0,
        "alice took bob's delegation to erin"
    );
    assert!(
        dave.get_individual(erin_id).await.is_none(),
        "dave must not know erin yet, or the defect cannot arise"
    );
    alice.revoke_member(bob_id, true, doc_id).await?;

    let stuck = sync_to(&alice, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    let on_dave = seated(&dave, doc_id).await;
    assert_eq!(on_dave, seated(&alice, doc_id).await);
    assert!(on_dave.contains(&erin_id), "erin is in the tree");
    assert!(!on_dave.contains(&bob_id), "bob is not in the tree");
    Ok(())
}

#[tokio::test]
async fn a_replica_that_never_met_a_revoked_groups_members_takes_the_revocation_in() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let erin = make_simple_keyhive().await?;
    let dave = make_simple_keyhive().await?;
    let bob_id = introduce(&alice, &bob).await?;
    let erin_id = introduce(&alice, &erin).await?;
    let dave_id = introduce(&alice, &dave).await?;

    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let group_id = alice.generate_group(vec![]).await?;
    alice
        .add_member(group_id, doc_id, Access::Read, &[])
        .await?;
    for who in [bob_id, erin_id] {
        alice.add_member(who, group_id, Access::Read, &[]).await?;
    }
    alice
        .add_member(dave_id, doc_id, Access::Admin, &[])
        .await?;
    assert!(
        dave.get_individual(bob_id).await.is_none(),
        "dave must not know bob yet, or the defect cannot arise"
    );

    alice.revoke_member(group_id, true, doc_id).await?;

    let stuck = sync_to(&alice, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    let on_dave = seated(&dave, doc_id).await;
    assert_eq!(on_dave, seated(&alice, doc_id).await);
    assert!(!on_dave.contains(&bob_id), "bob is not in the tree");
    assert!(!on_dave.contains(&erin_id), "erin is not in the tree");
    assert!(
        dave.get_individual(bob_id).await.is_some(),
        "dave knows who bob is, or he could not have applied the delegations \
         naming him"
    );
    Ok(())
}
