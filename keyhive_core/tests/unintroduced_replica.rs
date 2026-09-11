//! Syncing to a replica that has never been introduced to one or more members.

use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    principal::individual::{id::IndividualId, op::KeyOp, Individual},
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
    assert!(
        dave.get_individual(bob_id).await.is_some(),
        "dave learned the revoked member's keys"
    );
    assert_eq!(
        dave.access_for_doc(bob_id, doc_id).await,
        None,
        "and holds him revoked, not merely unknown"
    );
    assert_eq!(
        dave.access_for_doc(erin_id, doc_id).await,
        Some(Access::Read),
        "dave keeps erin, whose delegation bob proved"
    );
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
    assert!(
        dave.get_individual(bob_id).await.is_some(),
        "dave knows who bob is, or he could not have applied the delegations \
         referencing him"
    );
    Ok(())
}

async fn a_revoked_chain_of_delegations() -> TestResult<(Kh, Kh, IndividualId)> {
    let owner = make_simple_keyhive().await?;
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let erin = make_simple_keyhive().await?;
    let dave = make_simple_keyhive().await?;

    let alice_id = introduce(&owner, &alice).await?;
    let dave_id = introduce(&owner, &dave).await?;

    let doc_id = owner.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    owner
        .add_member(alice_id, doc_id, Access::Admin, &[])
        .await?;
    owner
        .add_member(dave_id, doc_id, Access::Admin, &[])
        .await?;
    assert_eq!(sync_to(&owner, &alice).await, 0, "alice took the setup");

    let bob_id = introduce(&alice, &bob).await?;
    alice.add_member(bob_id, doc_id, Access::Admin, &[]).await?;
    assert_eq!(sync_to(&alice, &bob).await, 0, "bob took the setup");

    let erin_id = introduce(&bob, &erin).await?;
    bob.add_member(erin_id, doc_id, Access::Read, &[]).await?;
    assert_eq!(
        sync_to(&bob, &owner).await,
        0,
        "the owner took the delegation"
    );
    assert!(
        dave.get_individual(erin_id).await.is_none(),
        "dave must not know erin yet, or the defect cannot arise"
    );

    // Revoking bob alone leaves erin in place: the check is on the issuer of
    // erin's proof, which is alice. Revoking alice is what drops erin.
    owner.revoke_member(bob_id, false, doc_id).await?;
    owner.revoke_member(alice_id, false, doc_id).await?;
    assert_eq!(
        owner.access_for_doc(erin_id, doc_id).await,
        None,
        "erin has to be out and not referenced by a revocation for this to be the case"
    );

    Ok((owner, dave, erin_id))
}

#[tokio::test]
async fn a_replica_takes_in_a_delegate_dropped_without_a_revocation() -> TestResult {
    let (owner, dave, erin_id) = a_revoked_chain_of_delegations().await?;

    let stuck = sync_to(&owner, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    assert!(
        dave.get_individual(erin_id).await.is_some(),
        "dave knows who erin is, or he could not have applied the delegation \
         referencing her"
    );
    Ok(())
}

#[tokio::test]
async fn a_replica_takes_in_a_delegate_dropped_inside_a_member_group() -> TestResult {
    let owner = make_simple_keyhive().await?;
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let erin = make_simple_keyhive().await?;
    let dave = make_simple_keyhive().await?;

    let alice_id = introduce(&owner, &alice).await?;
    let dave_id = introduce(&owner, &dave).await?;

    let doc_id = owner.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let group_id = owner.generate_group(vec![]).await?;
    owner
        .add_member(group_id, doc_id, Access::Read, &[])
        .await?;
    owner
        .add_member(alice_id, group_id, Access::Admin, &[])
        .await?;
    owner
        .add_member(dave_id, doc_id, Access::Admin, &[])
        .await?;
    assert_eq!(sync_to(&owner, &alice).await, 0, "alice took the setup");

    let bob_id = introduce(&alice, &bob).await?;
    alice
        .add_member(bob_id, group_id, Access::Admin, &[])
        .await?;
    assert_eq!(sync_to(&alice, &bob).await, 0, "bob took the setup");

    let erin_id = introduce(&bob, &erin).await?;
    bob.add_member(erin_id, group_id, Access::Read, &[]).await?;
    assert_eq!(
        sync_to(&bob, &owner).await,
        0,
        "the owner took the delegation"
    );
    assert!(
        dave.get_individual(erin_id).await.is_none(),
        "dave must not know erin yet, or the defect cannot arise"
    );

    owner.revoke_member(bob_id, false, group_id).await?;
    owner.revoke_member(alice_id, false, group_id).await?;

    // Dave reaches the document, not the group. The delegations he is sent
    // include the group's, so the members they reference have to reach him too.
    let stuck = sync_to(&owner, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    assert!(
        dave.get_individual(erin_id).await.is_some(),
        "dave knows who erin is, or he could not have applied the delegation \
         referencing her"
    );
    Ok(())
}
