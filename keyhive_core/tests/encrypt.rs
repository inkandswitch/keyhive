use future_form::Local;
use std::{collections::HashMap, sync::Arc};

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::{log::Log, no_listener::NoListener},
    principal::{agent::Agent, membered::Membered, peer::Peer},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{digest::Digest, signer::memory::MemorySigner};
use nonempty::nonempty;
use rand::rngs::OsRng;
use testresult::TestResult;

/// Build the well-known `Public` principal as an [`Agent`].
fn public_agent<F, S, T, L>() -> Agent<F, S, T, L>
where
    F: future_form::FutureForm,
    S: keyhive_crypto::signer::async_signer::AsyncSigner<F>,
    T: keyhive_crypto::content::reference::ContentRef,
    L: keyhive_core::listener::membership::MembershipListener<F, S, T>,
{
    let public_individual = keyhive_core::principal::public::Public.individual();
    Agent::Individual(
        public_individual.id(),
        Arc::new(Mutex::new(public_individual)),
    )
}

#[allow(clippy::type_complexity)]
struct NewKeyhive {
    signer: MemorySigner,
    log: Log<Local, MemorySigner>,
    keyhive: Keyhive<
        Local,
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        Log<Local, MemorySigner>,
        rand::rngs::ThreadRng,
    >,
}

async fn make_keyhive() -> NewKeyhive {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    let log = Log::<Local, _, _>::new();
    let keyhive = Keyhive::<Local, _, _, _, _, _, _>::generate(
        sk.clone(),
        store,
        log.clone(),
        rand::thread_rng(),
    )
    .await
    .unwrap();
    NewKeyhive {
        signer: sk,
        log,
        keyhive,
    }
}

#[tokio::test]
async fn test_encrypt_to_added_member() -> TestResult {
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
    alice
        .add_member(
            Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // Sync everything to bob
    let alice_events = alice
        .static_events_for_agent(&bob.active().lock().await.clone().into())
        .await;
    bob.ingest_unsorted_static_events(alice_events.into_values().collect())
        .await;

    // Attempt to decrypt on bob
    let doc_id = { doc.lock().await.doc_id() };
    let doc_on_bob = bob.get_document(doc_id).await.unwrap();
    let decrypted = bob
        .try_decrypt_content(doc_on_bob.clone(), encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// The application secret key surfaced on encrypt round-trips: it equals the
/// key the reader derives, and it decrypts the envelope directly.
#[tokio::test]
async fn test_application_secret_key_round_trips() -> TestResult {
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;
    let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
    alice
        .add_member(
            Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // Encrypt after adding Bob so Bob can reach the key via CGKA.
    let (encrypted, encrypt_key) = alice
        .try_encrypt_content_keyed(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // The surfaced key decrypts the envelope directly, with no CGKA.
    let direct = encrypted.encrypted_content().try_decrypt(encrypt_key)?;
    assert_eq!(direct, init_content);

    // Sync to Bob.
    let alice_events = alice
        .static_events_for_agent(&bob.active().lock().await.clone().into())
        .await;
    bob.ingest_unsorted_static_events(alice_events.into_values().collect())
        .await;

    // Bob's CGKA-derived key matches Alice's encrypt key, and decrypts.
    let doc_on_bob = bob.get_document(doc_id).await.unwrap();
    let (decrypted, decrypt_key) = bob
        .try_decrypt_content_keyed(doc_on_bob.clone(), encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);
    assert_eq!(decrypt_key, encrypt_key);

    Ok(())
}

/// Encrypt before adding Bob, with no re-key or re-encryption afterwards.
///
/// Bob must not be able to decrypt that content. The content was encrypted
/// with a PCS key derived from the CGKA tree root at an epoch when only
/// Alice was in the tree. The path secrets that climb to that root were
/// only ever encrypted to Alice's path, never to Bob, so Bob has no key
/// material to recover the key. This is the forward-secrecy boundary of
/// CGKA: a member added at epoch N cannot compute group secrets from
/// epochs before N.
///
/// This document is forward-secret (the default), so there is no predecessor
/// key chain: a member added later cannot read content from before they joined,
/// even after a rekey. See `test_encrypt_to_added_member` for the working case
/// where encryption happens after the add, and the forward-secrecy-disabled
/// tests below for the model where later members can read prior history.
#[tokio::test]
async fn test_cannot_decrypt_content_from_before_joining() -> TestResult {
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Encrypt first (before adding Bob)
    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // Then add Bob
    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;
    let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
    alice
        .add_member(
            Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // Sync everything to bob
    let alice_events = alice
        .static_events_for_agent(&bob.active().lock().await.clone().into())
        .await;
    bob.ingest_unsorted_static_events(alice_events.into_values().collect())
        .await;

    // Sanity check the other side of the boundary: Alice, who encrypted the
    // content at that epoch, can still decrypt it. This proves the ciphertext
    // is valid and that the failure below is specific to Bob lacking the
    // pre-join key material, not a generally broken encryption.
    let doc_on_alice = alice.get_document(doc_id).await.unwrap();
    let alice_decrypted = alice
        .try_decrypt_content(doc_on_alice, encrypted.encrypted_content())
        .await?;
    assert_eq!(alice_decrypted, init_content);

    // Bob cannot derive the pre-join epoch key, so decryption must fail.
    let doc_on_bob = bob.get_document(doc_id).await.unwrap();
    let result = bob
        .try_decrypt_content(doc_on_bob.clone(), encrypted.encrypted_content())
        .await;
    assert!(
        matches!(
            result,
            Err(keyhive_core::principal::document::DecryptError::KeyNotFound)
        ),
        "Bob should not be able to decrypt content from before he joined, got: {:?}",
        result.map(|_| "decrypted"),
    );

    Ok(())
}

#[tokio::test]
async fn test_decrypt_after_to_from_archive() {
    test_utils::init_logging();
    let NewKeyhive {
        keyhive: alice,
        signer: sk,
        log,
    } = make_keyhive().await;

    let archive = alice.into_archive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await
        .unwrap();

    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await
        .unwrap();

    let alice = Keyhive::<Local, _, _, _, _, _, _>::try_from_archive(
        &archive,
        sk,
        MemoryCiphertextStore::new(),
        NoListener,
        Arc::new(Mutex::new(OsRng)),
    )
    .await
    .unwrap();
    let mut events = Vec::new();
    while let Some(evt) = log.pop().await {
        events.push(StaticEvent::from(evt));
    }
    alice.ingest_unsorted_static_events(events).await;

    let doc = {
        let locked_doc = doc.lock().await;
        alice.get_document(locked_doc.doc_id()).await.unwrap()
    };

    let decrypted = alice
        .try_decrypt_content(doc.dupe(), encrypted.encrypted_content())
        .await
        .unwrap();

    assert_eq!(decrypted, init_content);
}

#[tokio::test]
async fn test_decrypt_after_fork_and_merge() {
    test_utils::init_logging();
    let NewKeyhive {
        keyhive: alice,
        signer: sk,
        log,
    } = make_keyhive().await;

    let archive1 = alice.into_archive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await
        .unwrap();

    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await
        .unwrap();

    let archive2 = alice.into_archive().await;
    let indie = {
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

    let mut events = log
        .0
        .lock()
        .await
        .clone()
        .into_iter()
        .chain(alice.events_for_agent(&indie).await.into_values())
        .map(StaticEvent::from)
        .collect::<Vec<_>>();

    if let Some(op) = encrypted.update_op() {
        events.push(StaticEvent::from(Box::new(op.clone())));
    }

    let reloaded = {
        let keyhive = Keyhive::<Local, _, _, _, _, _, _>::try_from_archive(
            &archive1,
            sk.clone(),
            MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
            Log::<Local, _, _>::new(),
            Arc::new(Mutex::new(OsRng)),
        )
        .await
        .unwrap();

        keyhive.ingest_archive(archive2).await.unwrap();
        keyhive.ingest_unsorted_static_events(events).await;

        keyhive
    };

    let doc = {
        let locked_doc = doc.lock().await;
        reloaded.get_document(locked_doc.doc_id()).await.unwrap()
    };

    let decrypted = reloaded
        .try_decrypt_content(doc.clone(), encrypted.encrypted_content())
        .await
        .unwrap();

    assert_eq!(decrypted, init_content);
}

#[tokio::test]
async fn test_encrypt_decrypt_via_group_transitive_access() -> TestResult {
    // Scenario:
    // Alice creates a doc and a group.
    // Alice gives the group Edit access to the doc.
    // Alice adds A and B with Edit access to the group.
    // A encrypts content to the doc, B decrypts it.
    //
    // ┌─────────────────────┐
    // │        Alice        │  (owner)
    // └─────────────────────┘
    //            │
    //            ▼
    // ┌─────────────────────┐
    // │        Group        │  ← A and B are Edit members
    // └─────────────────────┘
    //            │ Edit
    //            ▼
    // ┌─────────────────────┐
    // │         Doc         │  ← A encrypts, B decrypts
    // └─────────────────────┘
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;
    let NewKeyhive {
        keyhive: peer_a, ..
    } = make_keyhive().await;
    let NewKeyhive {
        keyhive: peer_b, ..
    } = make_keyhive().await;

    let init_content = "hello from peer A".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    // Alice creates group and doc (group controls the doc)
    let group = alice.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };

    let doc = alice
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![init_hash.into()],
        )
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Register A and B on Alice, add both to the group with Edit access
    let indie_a = {
        peer_a
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone()
    };
    let indie_b = {
        peer_b
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone()
    };

    alice
        .add_member(
            Agent::Individual(indie_a.id(), Arc::new(Mutex::new(indie_a.clone()))),
            &Membered::Group(group_id, group.dupe()),
            Access::Edit,
            &[],
        )
        .await?;
    alice
        .add_member(
            Agent::Individual(indie_b.id(), Arc::new(Mutex::new(indie_b.clone()))),
            &Membered::Group(group_id, group.dupe()),
            Access::Edit,
            &[],
        )
        .await?;

    // Sync Alice's events to A
    let events_for_a = alice
        .static_events_for_agent(&peer_a.active().lock().await.clone().into())
        .await;
    peer_a
        .ingest_unsorted_static_events(events_for_a.into_values().collect())
        .await;

    // A encrypts content
    let doc_on_a = peer_a.get_document(doc_id).await.unwrap();
    let encrypted = peer_a
        .try_encrypt_content(doc_on_a.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // Sync Alice's events + A's events to B
    let events_for_b = alice
        .static_events_for_agent(&peer_b.active().lock().await.clone().into())
        .await;
    peer_b
        .ingest_unsorted_static_events(events_for_b.into_values().collect())
        .await;

    let a_events_for_b = peer_a
        .static_events_for_agent(&peer_b.active().lock().await.clone().into())
        .await;
    peer_b
        .ingest_unsorted_static_events(a_events_for_b.into_values().collect())
        .await;

    // B decrypts
    let doc_on_b = peer_b.get_document(doc_id).await.unwrap();
    let decrypted = peer_b
        .try_decrypt_content(doc_on_b.clone(), encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

#[tokio::test]
async fn test_encrypt_decrypt_as_public() -> TestResult {
    // Scenario:
    // Alice creates a doc and adds Public as a Read member.
    // A and B are not members of the doc.
    // A and B receive the doc events via the Public agent (simulating
    // the sync server checking Public access).
    // A encrypts content as Public, B decrypts as Public.
    //
    // ┌─────────────────────┐
    // │        Alice        │  (owner)
    // └─────────────────────┘
    //            │
    //            │ Read
    //            ▼
    // ┌─────────────────────┐
    // │       Public        │  (well-known identity)
    // └─────────────────────┘
    //
    // A and B are not members. They receive doc events because Public
    // has access, and encrypt/decrypt using Public's well-known keys.
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;
    let NewKeyhive {
        keyhive: peer_a, ..
    } = make_keyhive().await;
    let NewKeyhive {
        keyhive: peer_b, ..
    } = make_keyhive().await;

    let init_content = "public message from A".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Add Public as a Read member
    let public_agent: Agent<_, _, _, _> = public_agent();
    alice
        .add_member(
            public_agent.dupe(),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // PCS update after adding Public to establish root key with current tree
    alice.force_pcs_update(doc.dupe()).await?;

    // Get events via Public (simulates sync server checking Public access)
    let public_events = alice.static_events_for_agent(&public_agent).await;

    // A ingests Public events
    peer_a
        .ingest_unsorted_static_events(public_events.values().cloned().collect())
        .await;

    // A encrypts (falls back to Public's leaf automatically)
    let doc_on_a = peer_a.get_document(doc_id).await.unwrap();
    let encrypted = peer_a
        .try_encrypt_content(doc_on_a.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // B ingests the same Public events
    peer_b
        .ingest_unsorted_static_events(public_events.into_values().collect())
        .await;

    // B decrypts (falls back to Public's leaf automatically)
    let doc_on_b = peer_b.get_document(doc_id).await.unwrap();
    let decrypted = peer_b
        .try_decrypt_content(doc_on_b.clone(), encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

// A member (alice) encrypts content after adding Public and force_pcs_update,
// and a fresh non-member peer decrypts it as Public.
#[tokio::test]
async fn test_member_encrypt_public_reader_decrypt() -> TestResult {
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;
    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = "init".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    let public_agent: Agent<_, _, _, _> = public_agent();
    alice
        .add_member(
            public_agent.dupe(),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;
    alice.force_pcs_update(doc.dupe()).await?;

    // Alice (a member) encrypts the content under her own leaf's PCS key.
    let content = "member-encrypted public message".as_bytes().to_vec();
    let content_hash = blake3::hash(&content);
    let encrypted = alice
        .try_encrypt_content(doc.dupe(), &content_hash.into(), &vec![], &content)
        .await?;

    // Bob (non-member) ingests the public events and decrypts as Public.
    let public_events = alice.static_events_for_agent(&public_agent).await;
    bob.ingest_unsorted_static_events(public_events.into_values().collect())
        .await;
    let doc_on_b = bob.get_document(doc_id).await.unwrap();
    let decrypted = bob
        .try_decrypt_content(doc_on_b.clone(), encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, content);

    Ok(())
}

#[allow(clippy::type_complexity)]
async fn make_keyhive_with_signer(
    sk: MemorySigner,
) -> Keyhive<
    Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    Log<Local, MemorySigner>,
    rand::rngs::ThreadRng,
> {
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    let log = Log::<Local, _, _>::new();
    Keyhive::<Local, _, _, _, _, _, _>::generate(sk, store, log, rand::thread_rng())
        .await
        .unwrap()
}

/// A dual-instance sender creates a doc with a fresh group coparent (no
/// Public), adds Bob (CGKA Add), SW encrypts (has_pcs_key=false due to
/// Add blanking root, generates PCS Update), Bob receives all events and
/// tries to decrypt.
///
/// This mirrors a real client flow where document generation creates a
/// fresh group and passes it as a coparent. The CGKA tree has DocOwner +
/// Alice's individual (from the group) + Bob. No Public member.
#[tokio::test]
async fn test_dual_instance_with_added_member_decrypt() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"hello from dual-instance Alice to Bob".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // Tab creates doc with a fresh group coparent.
    // No Public in the CGKA tree. CGKA has: doc identity + Alice's individual.
    let group = tab.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let doc = tab
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![init_hash],
        )
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Tab adds Bob to the doc. This creates a CGKA Add(Bob) op which
    // blanks the root key in the CGKA tree.
    let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
    tab.add_member(
        Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events_for_self = tab.static_events_for_agent(&tab_active_agent).await;

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events_for_self.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} stuck",
        sw_pending.len()
    );

    let sw_doc = sw
        .get_document(doc_id)
        .await
        .expect("SW should have doc after ingesting Tab events");
    let encrypted = sw
        .try_encrypt_content(sw_doc.clone(), &init_hash, &vec![], &init_content)
        .await?;

    let bob_agent: Agent<_, _, _, _> = bob.active().lock().await.clone().into();
    let tab_events_for_bob = tab.static_events_for_agent(&bob_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&bob_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Same as above but Bob receives events in two rounds: Tab events first
/// (which don't include SW's PCS Update), then SW events in a second sync.
/// This tests whether partial event delivery + re-ingestion works.
#[tokio::test]
async fn test_dual_instance_with_added_member_two_round_sync() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"two-round sync test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // Fresh group coparent, no Public, no force_pcs_update.
    let group = tab.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let doc = tab
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![init_hash],
        )
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    let indie_bob = { bob.active().lock().await.individual().lock().await.clone() };
    tab.add_member(
        Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob))),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    // Sync Tab to SW, then SW encrypts
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events_for_self = tab.static_events_for_agent(&tab_active_agent).await;
    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events_for_self.into_values().collect())
        .await;
    assert!(sw_pending.is_empty(), "SW pending: {}", sw_pending.len());

    let sw_doc = sw.get_document(doc_id).await.expect("SW should have doc");
    let encrypted = sw
        .try_encrypt_content(sw_doc.clone(), &init_hash, &vec![], &init_content)
        .await?;

    // Round 1: Bob receives only Tab events (no SW events yet)
    let bob_agent: Agent<_, _, _, _> = bob.active().lock().await.clone().into();
    let tab_events_for_bob = tab.static_events_for_agent(&bob_agent).await;
    let mut round1_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    round1_events.extend(tab_events_for_bob);

    let round1_pending = bob
        .ingest_unsorted_static_events(round1_events.into_values().collect())
        .await;

    // Round 2: Bob receives SW events (includes the PCS Update)
    let sw_events_for_bob = sw.static_events_for_agent(&bob_agent).await;
    let mut round2_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    round2_events.extend(sw_events_for_bob);

    // Also re-ingest any pending from round 1
    let pending_from_round1: Vec<_> = round1_pending
        .into_iter()
        .map(|e| e.as_ref().clone())
        .collect();
    let round2_pending = bob
        .ingest_unsorted_static_events(
            round2_events
                .into_values()
                .chain(pending_from_round1)
                .collect(),
        )
        .await;

    assert!(
        round2_pending.is_empty(),
        "Bob should have 0 pending after round 2. {} stuck",
        round2_pending.len()
    );

    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Two keyhive instances with the same identity (Tab + SW pattern).
/// Tab creates a doc with Public access, SW encrypts content.
/// Bob receives events from both instances and must decrypt.
///
/// This reproduces a client architecture where Tab and SW are separate
/// keyhive instances sharing the same signing key and prekey secrets.
#[tokio::test]
async fn test_dual_instance_encrypt_decrypt() -> TestResult {
    test_utils::init_logging();

    // --- Setup: Alice has two instances (Tab and SW) with the same signer ---
    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    // Transfer Tab's prekey secrets to SW (simulates shared IndexedDB storage)
    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"hello from dual-instance Alice".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // --- Tab creates a doc with Public as a member ---
    let doc = tab.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    let public_agent: Agent<_, _, _, _> = public_agent();
    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    tab.force_pcs_update(doc.dupe()).await?;

    // --- Sync Tab's events to SW (simulates server relay) ---
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events_for_self = tab.static_events_for_agent(&tab_active_agent).await;

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events_for_self.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} events stuck in pending",
        sw_pending.len()
    );

    // --- SW encrypts content (generates PCS Update op) ---
    let sw_doc = sw
        .get_document(doc_id)
        .await
        .expect("SW should have the doc after ingesting Tab events");
    let encrypted = sw
        .try_encrypt_content(sw_doc.clone(), &init_hash, &vec![], &init_content)
        .await?;

    // --- Sync all events to Bob ---
    // Bob receives events from both Tab and SW (via server).
    // Merge and deduplicate by hash.
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} events stuck in pending",
        bob_pending.len()
    );

    // --- Bob decrypts ---
    let doc_on_bob = bob
        .get_document(doc_id)
        .await
        .expect("Bob should have the doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Test when SW does not have Tab's prekey secrets.
/// This happens if loadPrekeySecrets fails or the prekey
/// storage is empty. The SW can't process CGKA Add ops for the
/// active agent, leaving them pending.
#[tokio::test]
async fn test_dual_instance_without_prekey_secrets() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;
    // Deliberately not transferring prekey secrets

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"no prekey secrets test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let doc = tab.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    let public_agent: Agent<_, _, _, _> = public_agent();
    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;
    tab.force_pcs_update(doc.dupe()).await?;

    // Sync Tab's events to SW without prekey secrets. SW cannot process the
    // CGKA Add ops for the active agent, so they stay pending.
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;
    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(
        sw_pending
            .iter()
            .any(|e| matches!(e.as_ref(), StaticEvent::CgkaOperation(_))),
        "SW should have a stuck CGKA op without prekey secrets, {} pending",
        sw_pending.len()
    );

    // Transfer prekey secrets. import_prekey_secrets retries pending events,
    // so the previously-stuck CGKA ops should drain.
    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;
    let still_pending = sw.ingest_unsorted_static_events(vec![]).await;
    assert!(
        still_pending.is_empty(),
        "SW should have no pending events after importing prekey secrets. {} stuck",
        still_pending.len()
    );

    // With SW recovered, it can encrypt content under the doc's current PCS key.
    let sw_doc = sw
        .get_document(doc_id)
        .await
        .expect("SW should have the doc after importing prekey secrets");
    let encrypted = sw
        .try_encrypt_content(sw_doc.clone(), &init_hash, &vec![], &init_content)
        .await?;

    // Now collect events from both and send to Bob. With SW recovered, Bob
    // should ingest everything via Public.
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;
    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events once SW has recovered. {} stuck",
        bob_pending.len()
    );

    // The real end-state: Bob reads the content SW encrypted, via Public.
    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Test the scenario where both Tab and SW independently create docs.
/// Both instances can generate documents.
/// If both create docs before syncing, their events may have cross-
/// dependencies that only resolve after event exchange.
#[tokio::test]
async fn test_dual_instance_both_create_docs() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;
    // Also transfer SW's prekeys to Tab
    let sw_prekeys = sw.export_prekey_secrets().await?;
    tab.import_prekey_secrets(&sw_prekeys).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let public_agent: Agent<_, _, _, _> = public_agent();

    // Tab creates 2 docs
    let tab_content1 = b"tab doc 1".to_vec();
    let tab_hash1: [u8; 32] = *blake3::hash(&tab_content1).as_bytes();
    let tab_doc1 = tab.generate_doc(vec![], nonempty![tab_hash1]).await?;
    let tab_doc1_id = { tab_doc1.lock().await.doc_id() };
    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(tab_doc1_id, tab_doc1.dupe()),
        Access::Read,
        &[],
    )
    .await?;
    tab.force_pcs_update(tab_doc1.dupe()).await?;

    let tab_content2 = b"tab doc 2".to_vec();
    let tab_hash2: [u8; 32] = *blake3::hash(&tab_content2).as_bytes();
    let tab_doc2 = tab.generate_doc(vec![], nonempty![tab_hash2]).await?;
    let tab_doc2_id = { tab_doc2.lock().await.doc_id() };
    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(tab_doc2_id, tab_doc2.dupe()),
        Access::Read,
        &[],
    )
    .await?;
    tab.force_pcs_update(tab_doc2.dupe()).await?;

    // SW independently creates 2 docs (before syncing with Tab)
    let sw_content1 = b"sw doc 1".to_vec();
    let sw_hash1: [u8; 32] = *blake3::hash(&sw_content1).as_bytes();
    let sw_doc1 = sw.generate_doc(vec![], nonempty![sw_hash1]).await?;
    let sw_doc1_id = { sw_doc1.lock().await.doc_id() };
    sw.add_member(
        public_agent.dupe(),
        &Membered::Document(sw_doc1_id, sw_doc1.dupe()),
        Access::Read,
        &[],
    )
    .await?;
    sw.force_pcs_update(sw_doc1.dupe()).await?;

    let sw_content2 = b"sw doc 2".to_vec();
    let sw_hash2: [u8; 32] = *blake3::hash(&sw_content2).as_bytes();
    let sw_doc2 = sw.generate_doc(vec![], nonempty![sw_hash2]).await?;
    let sw_doc2_id = { sw_doc2.lock().await.doc_id() };
    sw.add_member(
        public_agent.dupe(),
        &Membered::Document(sw_doc2_id, sw_doc2.dupe()),
        Access::Read,
        &[],
    )
    .await?;
    sw.force_pcs_update(sw_doc2.dupe()).await?;

    // Now sync between Tab and SW (simulates eventual consistency)
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;
    let sw_active_agent: Agent<_, _, _, _> = sw.active().lock().await.clone().into();
    let sw_events = sw.static_events_for_agent(&sw_active_agent).await;

    // Tab ingests SW events
    let tab_pending = tab
        .ingest_unsorted_static_events(sw_events.into_values().collect())
        .await;
    assert!(
        tab_pending.is_empty(),
        "Tab should ingest all SW events. {} stuck",
        tab_pending.len()
    );

    // SW ingests Tab events
    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} stuck",
        sw_pending.len()
    );

    // Tab encrypts its docs, SW encrypts its docs
    let enc_tab1 = tab
        .try_encrypt_content(tab_doc1.dupe(), &tab_hash1, &vec![], &tab_content1)
        .await?;
    let enc_tab2 = tab
        .try_encrypt_content(tab_doc2.dupe(), &tab_hash2, &vec![], &tab_content2)
        .await?;

    let enc_sw1 = sw
        .try_encrypt_content(sw_doc1.dupe(), &sw_hash1, &vec![], &sw_content1)
        .await?;
    let enc_sw2 = sw
        .try_encrypt_content(sw_doc2.dupe(), &sw_hash2, &vec![], &sw_content2)
        .await?;

    // Collect all events for Bob
    let tab_bob_events = tab.static_events_for_agent(&public_agent).await;
    let sw_bob_events = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_bob_events.clone());
    all_events.extend(sw_bob_events.clone());

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    // Bob decrypts all 4 docs
    let doc_on_bob = bob.get_document(tab_doc1_id).await.unwrap();
    assert_eq!(
        bob.try_decrypt_content(doc_on_bob, enc_tab1.encrypted_content())
            .await?,
        tab_content1
    );
    let doc_on_bob = bob.get_document(tab_doc2_id).await.unwrap();
    assert_eq!(
        bob.try_decrypt_content(doc_on_bob, enc_tab2.encrypted_content())
            .await?,
        tab_content2
    );
    let doc_on_bob = bob.get_document(sw_doc1_id).await.unwrap();
    assert_eq!(
        bob.try_decrypt_content(doc_on_bob, enc_sw1.encrypted_content())
            .await?,
        sw_content1
    );
    let doc_on_bob = bob.get_document(sw_doc2_id).await.unwrap();
    assert_eq!(
        bob.try_decrypt_content(doc_on_bob, enc_sw2.encrypted_content())
            .await?,
        sw_content2
    );

    Ok(())
}

/// Test with revoke_member to generate revocations and after_revocations
/// in delegations. This scenario shows pending revocations and delegations
/// with after_revocations dependencies.
#[tokio::test]
async fn test_dual_instance_with_revocations() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let public_agent: Agent<_, _, _, _> = public_agent();

    let init_content = b"revocation test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // Tab creates doc, adds Public, then revokes and re-adds
    let doc = tab.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    // Revoke Public and re-add. This generates revocations and new delegations
    // with after_revocations dependencies.
    tab.revoke_member(
        keyhive_core::principal::public::Public
            .individual()
            .id()
            .into(),
        true,
        &Membered::Document(doc_id, doc.dupe()),
    )
    .await?;

    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    tab.force_pcs_update(doc.dupe()).await?;

    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} stuck",
        sw_pending.len()
    );

    // SW encrypts
    let sw_doc = sw.get_document(doc_id).await.expect("SW should have doc");
    let encrypted = sw
        .try_encrypt_content(sw_doc, &init_hash, &vec![], &init_content)
        .await?;

    // Sync to Bob
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob.clone());
    all_events.extend(sw_events_for_bob.clone());

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Test the scenario where SW's events are collected via the Log listener
/// (as in the real sync protocol) rather than via static_events_for_agent.
/// The Log captures events fired during ingestion, which might include
/// re-emitted Tab events alongside SW-generated events.
#[tokio::test]
async fn test_dual_instance_log_based_sync() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;

    // SW uses a Log listener to capture events (simulates sync protocol)
    let sw_log = Log::<Local, MemorySigner>::new();
    let sw = Keyhive::<Local, _, _, _, _, _, _>::generate(
        alice_signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        sw_log.clone(),
        rand::thread_rng(),
    )
    .await
    .unwrap();

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"log-based sync test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let public_agent: Agent<_, _, _, _> = public_agent();

    // Tab creates doc with Public, revokes and re-adds (generates revocations)
    let doc = tab.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    tab.revoke_member(
        keyhive_core::principal::public::Public
            .individual()
            .id()
            .into(),
        true,
        &Membered::Document(doc_id, doc.dupe()),
    )
    .await?;

    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    tab.force_pcs_update(doc.dupe()).await?;

    // Sync Tab events to SW
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;

    // Clear SW log before ingestion so we only capture events from this ingestion
    while sw_log.pop().await.is_some() {}

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(sw_pending.is_empty(), "SW pending: {}", sw_pending.len());

    // SW encrypts
    let sw_doc = sw.get_document(doc_id).await.expect("SW should have doc");
    let encrypted = sw
        .try_encrypt_content(sw_doc, &init_hash, &vec![], &init_content)
        .await?;

    // Collect SW events from Log (this is what the sync protocol would send)
    let mut sw_log_events: Vec<StaticEvent<[u8; 32]>> = Vec::new();
    while let Some(evt) = sw_log.pop().await {
        sw_log_events.push(StaticEvent::from(evt));
    }

    // Bob receives Tab's events (via server) plus SW's log events (via server)
    // This simulates the server relaying events from both instances
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;

    // Merge: Tab's state-based events + SW's log-based events
    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    for evt in sw_log_events {
        all_events.insert(Digest::hash(&evt), evt);
    }

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Same as above but with multiple docs, closely matching a real client
/// bootstrap scenario (filesystem doc, account doc, etc.).
#[tokio::test]
async fn test_dual_instance_multiple_docs() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let public_agent: Agent<_, _, _, _> = public_agent();

    // Tab creates 4 docs (simulating bootstrap docs)
    let mut docs = Vec::new();
    let mut contents = Vec::new();
    for i in 0..4 {
        let content = format!("doc {} content", i).into_bytes();
        let hash: [u8; 32] = *blake3::hash(&content).as_bytes();

        let doc = tab.generate_doc(vec![], nonempty![hash]).await?;
        let doc_id = { doc.lock().await.doc_id() };

        tab.add_member(
            public_agent.dupe(),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

        tab.force_pcs_update(doc.dupe()).await?;
        contents.push((content, hash, doc_id));
        docs.push(doc);
    }

    // Sync Tab events to SW
    let tab_active_agent2: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent2).await;

    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(
        sw_pending.is_empty(),
        "SW should ingest all Tab events. {} stuck",
        sw_pending.len()
    );

    // SW encrypts each doc
    let mut encrypted_contents = Vec::new();
    for (content, hash, doc_id) in &contents {
        let sw_doc = sw.get_document(*doc_id).await.expect("SW should have doc");
        let encrypted = sw
            .try_encrypt_content(sw_doc, hash, &vec![], content)
            .await?;
        encrypted_contents.push(encrypted);
    }

    // Sync all events to Bob
    let tab_events_for_bob = tab.static_events_for_agent(&public_agent).await;
    let sw_events_for_bob = sw.static_events_for_agent(&public_agent).await;

    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(tab_events_for_bob);
    all_events.extend(sw_events_for_bob);

    let bob_pending = bob
        .ingest_unsorted_static_events(all_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    // Bob decrypts all docs
    for (i, (content, _, doc_id)) in contents.iter().enumerate() {
        let doc_on_bob = bob
            .get_document(*doc_id)
            .await
            .expect("Bob should have doc");
        let decrypted = bob
            .try_decrypt_content(doc_on_bob, encrypted_contents[i].encrypted_content())
            .await?;
        assert_eq!(&decrypted, content);
    }

    Ok(())
}

/// Individual delegation fails when receiver has a dual-instance
/// keyhive (Tab + SW) and the sender picks a prekey from one instance that
/// the other instance doesn't have the secret key for.
///
/// Scenario: Bob has Tab and SW (same signing key, different prekeys).
/// Alice (the server) has Bob registered with Tab-generated prekeys.
/// Alice creates a doc, individually delegates to Bob, generating a CGKA
/// Add(Bob, tab_prekey). Bob's SW tries to ingest events but doesn't have
/// the secret key for tab_prekey. Result: UnknownInvitePrekey, CGKA ops
/// stuck in pending.
///
/// After ingestion leaves pending events,
/// the SW imports prekey secrets from shared storage (which the Tab has
/// written to). `import_prekey_secrets` automatically drains pending.
#[tokio::test]
async fn test_dual_instance_receiver_unknown_invite_prekey() -> TestResult {
    test_utils::init_logging();

    // Bob has two keyhive instances with the same signing key.
    // At init, each generates 7 random prekeys independently.
    let bob_signer = MemorySigner::generate(&mut rand::thread_rng());
    let bob_tab = make_keyhive_with_signer(bob_signer.clone()).await;
    let bob_sw = make_keyhive_with_signer(bob_signer.clone()).await;

    // Simulate the real startup: Tab saves its prekey secrets to shared
    // storage (persistent storage in a real client). We hold onto the bytes as our "storage."
    let shared_storage = bob_tab.export_prekey_secrets().await?;

    // Alice (the server/sender) is a separate identity
    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;

    // Alice registers Bob using Bob-Tab's individual. This means Alice
    // only knows Bob's Tab-generated prekeys. When Alice picks a prekey
    // for CGKA Add(Bob), she'll pick a Tab-generated one.
    let indie_bob_tab = {
        bob_tab
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone()
    };

    // Alice creates a doc and individually delegates to Bob.
    let init_content = b"individual delegation test content".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let doc = alice.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    alice
        .add_member(
            Agent::Individual(indie_bob_tab.id(), Arc::new(Mutex::new(indie_bob_tab))),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // Alice encrypts so there's a PCS Update op in the tree
    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash, &vec![], &init_content)
        .await?;

    // Collect events for Bob from Alice
    let bob_agent: Agent<_, _, _, _> = bob_sw.active().lock().await.clone().into();
    let events_for_bob = alice.static_events_for_agent(&bob_agent).await;

    // Bob's SW ingests. The CGKA Add(Bob, tab_prekey) goes to pending
    // because SW doesn't have Tab's prekey secret.
    let pending = bob_sw
        .ingest_unsorted_static_events(events_for_bob.into_values().collect())
        .await;
    assert!(
        pending
            .iter()
            .any(|e| matches!(e.as_ref(), StaticEvent::CgkaOperation(_))),
        "Expected a stuck CGKA op (the Add blocked on the missing invite prekey), {} pending",
        pending.len()
    );

    // Simulate the retry path: pending events exist, so SW loads
    // prekey secrets from shared storage and re-ingests.
    bob_sw.import_prekey_secrets(&shared_storage).await?;
    let still_pending = bob_sw.pending_event_hashes().await;
    assert!(
        still_pending.is_empty(),
        "After importing prekey secrets and re-ingesting, \
         SW should have no pending events. {} stuck",
        still_pending.len()
    );

    // The real end-state: after recovering the invite prekey, SW can derive the
    // key and read the content Alice encrypted.
    let doc_on_sw = bob_sw
        .get_document(doc_id)
        .await
        .expect("SW should have the doc after draining the pending CGKA ops");
    let decrypted = bob_sw
        .try_decrypt_content(doc_on_sw, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// After a public delegation (setPublicAccess) with a
/// server relay present, the receiver's CGKA owner_id may be set to the
/// receiver's own identity instead of Public.
///
/// Scenario:
/// 1. Sender creates a doc
/// 2. Sender adds a server relay to the doc
/// 3. Sender calls setPublicAccess (addMember(Public) + forcePcsUpdate)
/// 4. Sender encrypts content
/// 5. Receiver ingests all events via Public
/// 6. Receiver attempts tryDecrypt
///
/// Expected: CGKA owner is Public, receiver can derive PCS key, decryption
/// succeeds. Bug: owner_id is receiver instead of Public, rebuild fails
/// with IdentifierNotFound because receiver is not in the CGKA tree.
#[tokio::test]
async fn test_public_delegation_with_server_relay_decrypt() -> TestResult {
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;
    let NewKeyhive {
        keyhive: server, ..
    } = make_keyhive().await;
    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"public doc with server relay".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let doc = alice.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Add server relay to the doc
    let indie_server = {
        server
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone()
    };
    alice
        .add_member(
            Agent::Individual(indie_server.id(), Arc::new(Mutex::new(indie_server))),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // setPublicAccess: addMember(Public) + forcePcsUpdate
    let public_agent: Agent<_, _, _, _> = public_agent();
    alice
        .add_member(
            public_agent.dupe(),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;
    alice.force_pcs_update(doc.dupe()).await?;

    // Sender encrypts
    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash, &vec![], &init_content)
        .await?;

    // Collect all sender events visible to Public
    let public_events = alice.static_events_for_agent(&public_agent).await;

    // Bob ingests all events
    let bob_pending = bob
        .ingest_unsorted_static_events(public_events.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all events. {} stuck",
        bob_pending.len()
    );

    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Verifies that a receiver can discover publicly-delegated docs via
/// docs_reachable_by_agent(Public). The doc is not in reachable_docs()
/// (which queries the receiver's own agent), matching the established
/// pattern where consumers union agent-specific and Public results
/// externally (as the server sync cache does).
#[tokio::test]
async fn test_public_doc_reachable_via_public_agent_query() -> TestResult {
    test_utils::init_logging();

    let NewKeyhive { keyhive: alice, .. } = make_keyhive().await;
    let NewKeyhive {
        keyhive: server, ..
    } = make_keyhive().await;
    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"public doc reachable test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    let doc = alice.generate_doc(vec![], nonempty![init_hash]).await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Add server relay
    let indie_server = {
        server
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone()
    };
    alice
        .add_member(
            Agent::Individual(indie_server.id(), Arc::new(Mutex::new(indie_server))),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;

    // Set public access
    let public_agent: Agent<_, _, _, _> = public_agent();
    alice
        .add_member(
            public_agent.dupe(),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;
    alice.force_pcs_update(doc.dupe()).await?;

    // Relay through server to bob (matching real sync path)
    let server_agent: Agent<_, _, _, _> = server.active().lock().await.clone().into();
    let events_for_server = alice.static_events_for_agent(&server_agent).await;
    let server_pending = server
        .ingest_unsorted_static_events(events_for_server.into_values().collect())
        .await;
    assert!(
        server_pending.is_empty(),
        "Server should ingest all. {} stuck",
        server_pending.len()
    );

    let events_for_bob = server.static_events_for_agent(&public_agent).await;
    assert!(
        !events_for_bob.is_empty(),
        "Server should have events for Public"
    );

    let bob_pending = bob
        .ingest_unsorted_static_events(events_for_bob.into_values().collect())
        .await;
    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all. {} stuck",
        bob_pending.len()
    );

    // Doc exists in Bob's documents map with correct CGKA state
    let bob_doc = bob
        .get_document(doc_id)
        .await
        .expect("Bob should have the doc in documents map");
    {
        let locked = bob_doc.lock().await;
        let cgka = locked.cgka().expect("Doc should have CGKA");
        assert!(cgka.has_pcs_key(), "CGKA should have PCS key");
    }

    // reachable_docs() (queries Bob's own agent) does not include the doc.
    // This is expected: Public docs require the external union pattern.
    let reachable = bob.reachable_docs().await;
    assert!(
        !reachable.contains_key(&doc_id),
        "reachable_docs() should not include publicly-delegated doc \
         (consumers must query Public separately and union the results)"
    );

    // docs_reachable_by_agent(Public) DOES include the doc
    let public_reachable = bob.docs_reachable_by_agent(&public_agent).await;
    assert!(
        public_reachable.contains_key(&doc_id),
        "docs_reachable_by_agent(Public) should include the doc"
    );
    assert_eq!(
        public_reachable.get(&doc_id).unwrap().can(),
        Access::Read,
        "Public should have Read access"
    );

    // Bob can decrypt via the doc handle (getDocument path, not reachable_docs)
    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash, &vec![], &init_content)
        .await?;
    let decrypted = bob
        .try_decrypt_content(bob_doc, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// Full dual-instance scenario: dual-instance sender (Tab + SW), group coparent,
/// server relay as intermediary. Events flow through the server before
/// reaching the receiver, matching the real sync path.
#[tokio::test]
async fn test_dual_instance_public_via_server_relay_decrypt() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let tab = make_keyhive_with_signer(alice_signer.clone()).await;
    let sw = make_keyhive_with_signer(alice_signer.clone()).await;

    let prekey_bytes = tab.export_prekey_secrets().await?;
    sw.import_prekey_secrets(&prekey_bytes).await?;

    let NewKeyhive {
        keyhive: server, ..
    } = make_keyhive().await;
    let NewKeyhive { keyhive: bob, .. } = make_keyhive().await;

    let init_content = b"dual instance public via server relay".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // Tab creates doc with group coparent
    let group = tab.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let doc = tab
        .generate_doc(
            vec![Peer::Group(group_id, group.dupe())],
            nonempty![init_hash],
        )
        .await?;
    let doc_id = { doc.lock().await.doc_id() };

    // Tab adds server relay
    let indie_server = {
        server
            .active()
            .lock()
            .await
            .individual()
            .lock()
            .await
            .clone()
    };
    tab.add_member(
        Agent::Individual(indie_server.id(), Arc::new(Mutex::new(indie_server))),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;

    // Tab calls setPublicAccess
    let public_agent: Agent<_, _, _, _> = public_agent();
    tab.add_member(
        public_agent.dupe(),
        &Membered::Document(doc_id, doc.dupe()),
        Access::Read,
        &[],
    )
    .await?;
    tab.force_pcs_update(doc.dupe()).await?;

    // Sync Tab events to SW
    let tab_active_agent: Agent<_, _, _, _> = tab.active().lock().await.clone().into();
    let tab_events = tab.static_events_for_agent(&tab_active_agent).await;
    let sw_pending = sw
        .ingest_unsorted_static_events(tab_events.into_values().collect())
        .await;
    assert!(sw_pending.is_empty(), "SW pending: {}", sw_pending.len());

    // SW encrypts
    let sw_doc = sw.get_document(doc_id).await.expect("SW should have doc");
    let encrypted = sw
        .try_encrypt_content(sw_doc, &init_hash, &vec![], &init_content)
        .await?;

    // Events flow through server: Alice (Tab + SW) → Server → Bob
    let server_agent: Agent<_, _, _, _> = server.active().lock().await.clone().into();
    let tab_events_for_server = tab.static_events_for_agent(&server_agent).await;
    let sw_events_for_server = sw.static_events_for_agent(&server_agent).await;
    let mut server_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    server_events.extend(tab_events_for_server);
    server_events.extend(sw_events_for_server);

    let server_pending = server
        .ingest_unsorted_static_events(server_events.into_values().collect())
        .await;
    assert!(
        server_pending.is_empty(),
        "Server should ingest all. {} stuck",
        server_pending.len()
    );

    // Server serves events to Bob via Public visibility
    let events_for_bob = server.static_events_for_agent(&public_agent).await;

    let bob_pending = bob
        .ingest_unsorted_static_events(events_for_bob.into_values().collect())
        .await;

    assert!(
        bob_pending.is_empty(),
        "Bob should ingest all. {} stuck",
        bob_pending.len()
    );

    let doc_on_bob = bob.get_document(doc_id).await.expect("Bob should have doc");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}
