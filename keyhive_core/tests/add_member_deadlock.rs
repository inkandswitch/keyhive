/// Incremental tests to reproduce the add_member deadlock described in the
/// keyhive-bugs progress doc. Each test starts from a known-working pattern
/// and introduces one change at a time. Tests use tokio::time::timeout to
/// detect hangs (10 seconds should be more than enough for any of these).
use std::sync::Arc;
use std::time::Duration;

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    crypto::signer::memory::MemorySigner,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{agent::Agent, membered::Membered, peer::Peer, public::Public},
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::make_simple_keyhive,
};
use nonempty::nonempty;
use testresult::TestResult;

const TIMEOUT: Duration = Duration::from_secs(10);

// =============================================================================
// Step 1: Exact copy of the working test_add_member from keyhive.rs
// Adds Public.individual() to a doc with Public.individual() as co-parent.
// EXPECTED: PASS
// =============================================================================
#[tokio::test]
async fn step1_baseline_public_individual() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let keyhive = make_simple_keyhive().await.unwrap();

        let doc = keyhive
            .generate_doc(
                vec![Peer::Individual(
                    Public.individual().id(),
                    Arc::new(Mutex::new(Public.individual())),
                )],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();

        let member: Agent<MemorySigner, [u8; 32], NoListener> = Public.individual().into();
        let membered = Membered::Document(doc.lock().await.doc_id(), doc.dupe());
        let dlg = keyhive
            .add_member(member, &membered, Access::Read, &[])
            .await
            .unwrap();

        assert_eq!(
            dlg.delegation.subject_id(),
            doc.lock().await.doc_id().into()
        );
    })
    .await;

    assert!(result.is_ok(), "step1 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 2: Same as baseline but add a fresh Individual instead of Public.
// generate_doc still uses Public.individual() as co-parent.
// Change: member type (Public → fresh Individual from another keyhive)
// EXPECTED: PASS (matches test_encrypt_to_added_member pattern)
// =============================================================================
#[tokio::test]
async fn step2_fresh_individual_no_coparents() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();

        // Doc with no co-parents (like test_encrypt_to_added_member)
        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Get bob's individual
        let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
        alice
            .add_member(
                Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step2 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 3: Fresh individual, doc has Public.individual() as co-parent.
// Change from step 2: doc has a co-parent (more delegations from generate_doc)
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step3_fresh_individual_with_public_coparent() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();

        // Doc WITH Public.individual() as co-parent
        let doc = alice
            .generate_doc(
                vec![Peer::Individual(
                    Public.individual().id(),
                    Arc::new(Mutex::new(Public.individual())),
                )],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
        alice
            .add_member(
                Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step3 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 4: Use contact card path to get bob's individual on alice's side.
// Change from step 3: contact card registration vs direct clone
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step4_contact_card_path() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Use contact card path instead of direct clone
        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step4 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 5: Contact card path + doc has co-parent.
// Change from step 4: doc has Public.individual() as co-parent
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step5_contact_card_with_coparent() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();

        let doc = alice
            .generate_doc(
                vec![Peer::Individual(
                    Public.individual().id(),
                    Arc::new(Mutex::new(Public.individual())),
                )],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step5 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 6: Doc has bob as co-parent, then add carol.
// Change from step 5: co-parent is a real individual (not Public)
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step6_real_coparent_then_add_another() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();
        let carol = make_simple_keyhive().await.unwrap();

        // Register bob on alice via contact card
        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        // Create doc with bob as co-parent
        let doc = alice
            .generate_doc(
                vec![Peer::Individual(bob_id, bob_on_alice.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Now add carol
        let carol_contact = carol.contact_card().await.unwrap();
        let carol_on_alice = alice.receive_contact_card(&carol_contact).await.unwrap();
        let carol_id = { carol_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step6 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 7: Access::Write instead of Access::Read.
// Change from step 6: different access level
// This changes the CGKA path (Write skips add_cgka_member)
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step7_write_access() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step7 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 8: Double add_member — add bob, then add carol to the same doc.
// Change from step 6: previous add_member already happened
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step8_double_add_member() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();
        let carol = make_simple_keyhive().await.unwrap();

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Add bob first
        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Then add carol
        let carol_contact = carol.contact_card().await.unwrap();
        let carol_on_alice = alice.receive_contact_card(&carol_contact).await.unwrap();
        let carol_id = { carol_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step8 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 9: Add member via group intermediary — add bob to group, group is
// co-parent of doc, then add carol directly to the doc.
// Change: doc's delegation graph includes a group
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step9_group_coparent_then_add_individual() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let bob = make_simple_keyhive().await.unwrap();
        let carol = make_simple_keyhive().await.unwrap();

        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        // Create group, add bob to it
        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Create doc with group as co-parent
        let doc = alice
            .generate_doc(
                vec![Peer::Group(group_id, group.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Now add carol directly to the doc
        let carol_contact = carol.contact_card().await.unwrap();
        let carol_on_alice = alice.receive_contact_card(&carol_contact).await.unwrap();
        let carol_id = { carol_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step9 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 10: Archive/restore cycle, then add_member.
// Change: keyhive state comes from archive restoration + event ingestion
// This mirrors the production scenario (IndexedDB persistence).
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step10_archive_restore_then_add_member() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();

        // Create alice with a known signer so we can reuse it for restore
        let alice_signer = MemorySigner::generate(&mut rand::rngs::OsRng);
        let alice: Keyhive<
            MemorySigner,
            [u8; 32],
            Vec<u8>,
            MemoryCiphertextStore<[u8; 32], Vec<u8>>,
            NoListener,
            rand::rngs::OsRng,
        > = Keyhive::generate(
            alice_signer.clone(),
            MemoryCiphertextStore::new(),
            NoListener,
            rand::rngs::OsRng,
        )
        .await
        .unwrap();

        let bob = make_simple_keyhive().await.unwrap();

        // Create doc
        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Get events before archive
        let indie_alice: Agent<MemorySigner, [u8; 32], NoListener> = {
            alice
                .active()
                .lock()
                .await
                .individual()
                .lock()
                .await
                .clone()
                .into()
        };
        let events = alice
            .events_for_agent(&indie_alice)
            .await
            .unwrap()
            .into_values()
            .map(keyhive_core::event::static_event::StaticEvent::from)
            .collect::<Vec<_>>();

        // Archive and restore
        let archive = alice.into_archive().await;
        let alice_restored = Keyhive::try_from_archive(
            &archive,
            alice_signer,
            MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
            NoListener,
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await
        .unwrap();
        alice_restored.ingest_unsorted_static_events(events).await;

        // Now add bob to the restored doc
        let doc_restored = alice_restored.get_document(doc_id).await.unwrap();
        let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };

        alice_restored
            .add_member(
                Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
                &Membered::Document(doc_id, doc_restored.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step10 TIMED OUT — deadlock detected");
    Ok(())
}

// =============================================================================
// Step 11: Create a true cycle — group has doc as member, doc has group as
// co-parent — then try to add a new individual to the doc.
// This would cause transitive_members() to traverse group → doc → deadlock
// if doc is already locked.
// EXPECTED: HANG (this is the likely deadlock trigger)
// =============================================================================
#[tokio::test]
async fn step11_cyclic_group_doc_then_add_member() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();

        // Create group
        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        // Create doc with group as co-parent
        let doc = alice
            .generate_doc(
                vec![Peer::Group(group_id, group.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Add the DOC to the GROUP (creates cycle: group→doc, doc→group)
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Now try to add carol to the doc — this may deadlock because:
        // 1. Keyhive::add_member acquires doc.lock()
        // 2. Document::add_member → Group::add_member_with_manual_content
        // 3. Group::add_cgka_member → transitive_members()
        // 4. transitive_members() finds group member, traverses into group
        // 5. group has doc as member → membered.members().await → doc.lock() → DEADLOCK
        let carol = make_simple_keyhive().await.unwrap();
        let carol_contact = carol.contact_card().await.unwrap();
        let carol_on_alice = alice.receive_contact_card(&carol_contact).await.unwrap();
        let carol_id = { carol_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(carol_id, carol_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "step11 TIMED OUT — deadlock detected (cyclic group-doc)"
    );
    Ok(())
}

// =============================================================================
// Step 11b: Just create the cycle, don't do a second add_member.
// Isolates whether the cycle CREATION deadlocks vs the second add_member.
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step11b_just_create_cycle() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();

        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        let doc = alice
            .generate_doc(
                vec![Peer::Group(group_id, group.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Just create the cycle — does this alone deadlock?
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "step11b TIMED OUT — cycle creation itself deadlocks"
    );
    Ok(())
}

// =============================================================================
// Step 11c: Same as 11b but add doc to group with Write access.
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step11c_just_create_cycle_write() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();

        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        let doc = alice
            .generate_doc(
                vec![Peer::Group(group_id, group.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Create cycle with Write access
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "step11c TIMED OUT — cycle creation (Write) itself deadlocks"
    );
    Ok(())
}

// =============================================================================
// Step 11d: Add doc to group, but doc does NOT have the group as co-parent.
// No cycle — should be safe.
// EXPECTED: PASS (no cycle, so no re-entrant lock)
// =============================================================================
#[tokio::test]
async fn step11d_doc_to_group_no_cycle() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();

        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        // Doc WITHOUT the group as co-parent (no cycle)
        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Add doc to group — should NOT deadlock (doc doesn't reference group)
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "step11d TIMED OUT — deadlock even without cycle!"
    );
    Ok(())
}

// =============================================================================
// Step 11e: Add doc to group, NO cycle, Write access (may skip CGKA).
// Isolates: is the deadlock in CGKA or in rebuild/add_delegation?
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step11e_doc_to_group_no_cycle_write() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();

        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Add doc to group with Write (no cycle, no CGKA for Write)
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "step11e TIMED OUT — deadlock even without cycle and with Write!"
    );
    Ok(())
}

// =============================================================================
// Step 11f: Minimal repro with debug output.
// Breaks the operation into sub-steps to find exactly where it hangs.
// EXPECTED: ?
// =============================================================================
#[tokio::test]
async fn step11f_debug_minimal_repro() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();

        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };
        eprintln!("DEBUG: group created");

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };
        eprintln!("DEBUG: doc created");

        // Call through Keyhive::add_member
        eprintln!("DEBUG: about to call add_member");
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
        eprintln!("DEBUG: add_member completed");
    })
    .await;

    assert!(result.is_ok(), "step11f TIMED OUT");
    Ok(())
}

// =============================================================================
// Step 12: Same cycle scenario but with Access::Write (skips CGKA path).
// If step 11 hangs, this isolates whether the deadlock is in the CGKA path
// (add_cgka_member) vs elsewhere (rebuild, add_delegation, etc.).
// EXPECTED: If step 11 hangs and this passes, deadlock is in CGKA path.
// =============================================================================
#[tokio::test]
async fn step12_cyclic_group_doc_write_access() -> TestResult {
    let result = tokio::time::timeout(TIMEOUT, async {
        test_utils::init_logging();
        let alice = make_simple_keyhive().await.unwrap();
        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = { group.lock().await.group_id() };

        let doc = alice
            .generate_doc(
                vec![Peer::Group(group_id, group.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = { doc.lock().await.doc_id() };

        // Create cycle
        alice
            .add_member(
                Agent::Document(doc_id, doc.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();

        // Add bob with WRITE (skips CGKA)
        let bob = make_simple_keyhive().await.unwrap();
        let bob_contact = bob.contact_card().await.unwrap();
        let bob_on_alice = alice.receive_contact_card(&bob_contact).await.unwrap();
        let bob_id = { bob_on_alice.lock().await.id() };

        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
    })
    .await;

    assert!(result.is_ok(), "step12 TIMED OUT — deadlock detected");
    Ok(())
}
