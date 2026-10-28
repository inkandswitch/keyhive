//! Syncing to a replica that has never been introduced to one or more members.

use keyhive_core::{
    principal::individual::{id::IndividualId, op::KeyOp, IndividualState},
    test_utils::{make_simple_keyhive, Hive},
};
use keyline::power::Power;
use nonempty::nonempty;
use testresult::TestResult;

/// Introduce `who` to `observer`, so `observer` can add `who` to a document.
async fn introduce(observer: &Hive, who: &Hive) -> TestResult<IndividualId> {
    let prekey = who.expand_prekeys().await?;
    let indie = IndividualState::new(KeyOp::Add(prekey));
    let id = indie.id();
    observer.register_individual(indie).await;
    Ok(id)
}

/// Introduce `who` to `observer` by contact card, which contains a lone rotation
/// rather than the op that added the rotated key.
async fn introduce_by_contact_card(observer: &Hive, who: &Hive) -> TestResult<IndividualId> {
    let card = who.generate_contact_card().await?;
    Ok(observer.receive_contact_card(&card).await?)
}

/// Deliver everything `from` holds that `to` is entitled to. Returns the number
/// of events `to` could not apply.
async fn sync_to(from: &Hive, to: &Hive) -> usize {
    let events = from
        .static_events_for_agent(to.id())
        .await
        .expect("selects events");
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
    alice.add_member(bob_id, doc_id, Power::Admin).await?;
    alice.add_member(dave_id, doc_id, Power::Read).await?;
    assert_eq!(sync_to(&alice, &bob).await, 0, "bob took the setup");

    // Bob grants Erin; Alice revokes Bob below, adopting Bob's grants. Dave
    // has met neither of them.
    let erin_id = introduce(&bob, &erin).await?;
    bob.add_member(erin_id, doc_id, Power::Read).await?;
    assert_eq!(
        sync_to(&bob, &alice).await,
        0,
        "alice took bob's delegation to erin"
    );
    assert!(
        dave.get_individual(erin_id).await.is_none(),
        "dave does not know erin before the sync"
    );
    alice.revoke_member(bob_id, true, doc_id).await?;

    let stuck = sync_to(&alice, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    assert!(
        dave.get_individual(bob_id).await.is_some(),
        "dave is sent the revoked member's keys: the delegation revoked names him"
    );
    assert_eq!(
        dave.access_for_doc(bob_id, doc_id).await?,
        None,
        "and holds him revoked, not merely unknown"
    );
    assert_eq!(
        dave.access_for_doc(erin_id, doc_id).await?,
        Some(Power::Read),
        "dave keeps erin, whom alice adopted"
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
    alice.add_member(group_id, doc_id, Power::Read).await?;
    for who in [bob_id, erin_id] {
        alice.add_member(who, group_id, Power::Read).await?;
    }
    alice.add_member(dave_id, doc_id, Power::Admin).await?;
    assert!(
        dave.get_individual(bob_id).await.is_none(),
        "dave does not know bob before the sync"
    );

    alice.revoke_member(group_id, true, doc_id).await?;

    let stuck = sync_to(&alice, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    assert!(
        dave.get_individual(bob_id).await.is_some(),
        "dave is sent the keys of bob, whom the delegations he is sent name"
    );
    Ok(())
}

async fn a_revoked_chain_of_delegations() -> TestResult<(Hive, Hive, IndividualId)> {
    let owner = make_simple_keyhive().await?;
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let erin = make_simple_keyhive().await?;
    let dave = make_simple_keyhive().await?;

    let alice_id = introduce(&owner, &alice).await?;
    let dave_id = introduce(&owner, &dave).await?;

    let doc_id = owner.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    owner.add_member(alice_id, doc_id, Power::Admin).await?;
    owner.add_member(dave_id, doc_id, Power::Admin).await?;
    assert_eq!(sync_to(&owner, &alice).await, 0, "alice took the setup");

    let bob_id = introduce(&alice, &bob).await?;
    alice.add_member(bob_id, doc_id, Power::Admin).await?;
    assert_eq!(sync_to(&alice, &bob).await, 0, "bob took the setup");

    let erin_id = introduce(&bob, &erin).await?;
    bob.add_member(erin_id, doc_id, Power::Read).await?;
    assert_eq!(
        sync_to(&bob, &owner).await,
        0,
        "the owner took the delegation"
    );
    assert!(
        dave.get_individual(erin_id).await.is_none(),
        "dave does not know erin before the sync"
    );

    // Revoking bob cuts erin off: bob's grant to erin dies with bob's
    // standing. Alice is revoked too, so no adoption keeps erin.
    owner.revoke_member(bob_id, false, doc_id).await?;
    owner.revoke_member(alice_id, false, doc_id).await?;
    assert_eq!(
        owner.access_for_doc(erin_id, doc_id).await?,
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
        "dave is sent the keys of erin, whom a delegation he is sent names"
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
    owner.add_member(group_id, doc_id, Power::Read).await?;
    owner.add_member(alice_id, group_id, Power::Admin).await?;
    owner.add_member(dave_id, doc_id, Power::Admin).await?;
    assert_eq!(sync_to(&owner, &alice).await, 0, "alice took the setup");

    let bob_id = introduce(&alice, &bob).await?;
    alice.add_member(bob_id, group_id, Power::Admin).await?;
    assert_eq!(sync_to(&alice, &bob).await, 0, "bob took the setup");

    let erin_id = introduce(&bob, &erin).await?;
    bob.add_member(erin_id, group_id, Power::Read).await?;
    assert_eq!(
        sync_to(&bob, &owner).await,
        0,
        "the owner took the delegation"
    );
    assert!(
        dave.get_individual(erin_id).await.is_none(),
        "dave does not know erin before the sync"
    );

    owner.revoke_member(bob_id, false, group_id).await?;
    owner.revoke_member(alice_id, false, group_id).await?;

    // Dave reaches the document, not the group. The delegations he is sent
    // include the group's; the members they name need not reach him.
    let stuck = sync_to(&owner, &dave).await;

    assert_eq!(stuck, 0, "dave cannot apply {stuck} events");
    assert!(
        dave.get_individual(erin_id).await.is_some(),
        "dave is sent the keys of erin, whom a delegation he is sent names"
    );
    Ok(())
}

#[tokio::test]
async fn a_replica_takes_in_a_delegation_to_a_member_known_by_contact_card() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let relay = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let relay_id = introduce(&alice, &relay).await?;
    let bob_id = introduce_by_contact_card(&alice, &bob).await?;

    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(relay_id, doc_id, Power::Relay).await?;
    alice.add_member(bob_id, doc_id, Power::Edit).await?;

    assert_eq!(
        sync_to(&alice, &relay).await,
        0,
        "the relay took everything"
    );
    assert_eq!(
        relay.access_for_doc(bob_id, doc_id).await?,
        Some(Power::Edit),
        "the relay knows bob is a member"
    );
    Ok(())
}

/// Membership and key agreement reach bob through a relay that knows everyone
/// only by contact card. Bob never syncs with alice.
#[tokio::test]
async fn a_member_decrypts_through_a_relay_known_by_contact_card() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let relay = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let relay_id = introduce_by_contact_card(&alice, &relay).await?;
    let bob_id = introduce_by_contact_card(&alice, &bob).await?;

    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(relay_id, doc_id, Power::Relay).await?;
    alice.add_member(bob_id, doc_id, Power::Edit).await?;
    let encrypted = alice
        .try_encrypt_content(doc_id, &[1u8; 32], &[], b"from alice")
        .await?;

    assert_eq!(
        sync_to(&alice, &relay).await,
        0,
        "the relay received everything"
    );
    assert_eq!(
        sync_to(&relay, &bob).await,
        0,
        "bob received everything the relay holds"
    );
    assert_eq!(
        bob.access_for_doc(bob_id, doc_id).await?,
        Some(Power::Edit),
        "and knows he is a member"
    );
    assert!(
        bob.has_document(doc_id).await,
        "the relay passed on the key agreement"
    );
    assert_eq!(
        bob.try_decrypt_content(doc_id, encrypted.encrypted_content())
            .await?
            .plaintext,
        b"from alice".to_vec(),
        "bob decrypts what alice wrote"
    );
    Ok(())
}
