use future_form::Local;
use std::{collections::HashMap, sync::Arc};

use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::{log::Log, no_listener::NoListener},
    principal::{identifier::Identifier, public::Public},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{digest::Digest, signer::memory::MemorySigner};
use nonempty::nonempty;
use rand::rngs::OsRng;
use testresult::TestResult;

#[allow(clippy::type_complexity)]
async fn make_keyhive() -> Keyhive<
    Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    Log<Local, MemorySigner>,
    rand::rngs::ThreadRng,
> {
    make_keyhive_with_signer(MemorySigner::generate(&mut rand::thread_rng())).await
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

/// One identity running two instances, where the second instance's events are collected
/// from a `Log` listener rather than from `static_events_for_agent`.
#[tokio::test]
async fn test_dual_instance_log_based_sync() -> TestResult {
    test_utils::init_logging();

    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let alice = make_keyhive_with_signer(alice_signer.clone()).await;

    // The second instance keeps a Log listener, which is how a sync protocol collects
    // what an instance produced.
    let worker_log = Log::<Local, MemorySigner>::new();
    let alice_worker = Keyhive::<Local, _, _, _, _, _, _>::generate(
        alice_signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        worker_log.clone(),
        rand::thread_rng(),
    )
    .await
    .unwrap();

    let prekey_bytes = alice.export_prekey_secrets().await?;
    alice_worker.import_prekey_secrets(&prekey_bytes).await?;

    let bob = make_keyhive().await;

    let init_content = b"log-based sync test".to_vec();
    let init_hash: [u8; 32] = *blake3::hash(&init_content).as_bytes();

    // The first instance makes the document public, revokes that, and grants it again, so
    // there are revocations in the graph the second instance has to apply.
    let doc_id = alice.generate_doc(vec![], nonempty![init_hash]).await?;

    alice
        .add_member(Public.id(), doc_id, Access::Read, &[])
        .await?;

    alice
        .revoke_member(
            keyhive_core::principal::public::Public.individual().id(),
            true,
            doc_id,
        )
        .await?;

    alice
        .add_member(Public.id(), doc_id, Access::Read, &[])
        .await?;

    alice.force_pcs_update(doc_id).await?;

    // The first instance's events to the second.
    let alice_id = { alice.active().lock().await.id() };
    let alice_events = alice.static_events_for_agent(alice_id).await;

    // Emptied first, so the log holds only what this ingestion fires.
    while worker_log.pop().await.is_some() {}

    let worker_pending = alice_worker
        .ingest_unsorted_static_events(alice_events.into_values().collect())
        .await;
    assert!(
        worker_pending.is_empty(),
        "the second instance has {} events stuck",
        worker_pending.len()
    );

    // The second instance writes.
    let encrypted = alice_worker
        .try_encrypt_content(doc_id, &init_hash, &vec![], &init_content)
        .await?;

    // What the sync protocol would send: the second instance's events, from its log.
    let mut worker_log_events: Vec<StaticEvent<[u8; 32]>> = Vec::new();
    while let Some(evt) = worker_log.pop().await {
        worker_log_events.push(StaticEvent::from(evt));
    }

    // Bob gets the first instance's events and the second's log events together.
    let alice_events_for_bob = alice.static_events_for_agent(Public.id()).await;

    // One set collected from state, the other from the log.
    let mut all_events: HashMap<Digest<StaticEvent<[u8; 32]>>, StaticEvent<[u8; 32]>> =
        HashMap::new();
    all_events.extend(alice_events_for_bob);
    for evt in worker_log_events {
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

    let decrypted = bob
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

    Ok(())
}

/// A complete PCS rotation by another authorized member must leave the original
/// member able to derive the new root and encrypt immediately.
#[tokio::test]
async fn test_authorized_remote_rotation_preserves_local_encryption() -> TestResult {
    test_utils::init_logging();
    let alice = make_keyhive().await;
    let bob = make_keyhive().await;

    let initial = b"before-rotation".to_vec();
    let initial_hash: [u8; 32] = *blake3::hash(&initial).as_bytes();
    let doc_id = alice.generate_doc(vec![], nonempty![initial_hash]).await?;

    let bob_id: Identifier = bob.active().lock().await.id().into();
    alice
        .receive_contact_card(&bob.get_existing_contact_card().await)
        .await?;
    alice.add_member(bob_id, doc_id, Access::Read, &[]).await?;

    let alice_events = alice.static_events_for_agent(bob_id).await;
    let pending = bob
        .ingest_unsorted_static_events(alice_events.into_values().collect())
        .await;
    assert!(pending.is_empty());
    bob.force_pcs_update(doc_id).await?;

    let alice_id: Identifier = alice.active().lock().await.id().into();
    let bob_events = bob.static_events_for_agent(alice_id).await;
    let pending = alice
        .ingest_unsorted_static_events(bob_events.into_values().collect())
        .await;
    assert!(pending.is_empty());

    let after = b"after-remote-rotation".to_vec();
    let after_hash: [u8; 32] = *blake3::hash(&after).as_bytes();
    alice
        .try_encrypt_content(doc_id, &after_hash, &vec![], &after)
        .await?;

    Ok(())
}

/// Concurrent PCS rotations by authorized members must merge into a state from
/// which both members can derive a current key for subsequent encryption.
#[tokio::test]
async fn test_concurrent_authorized_rotations_preserve_encryption() -> TestResult {
    test_utils::init_logging();
    let alice = make_keyhive().await;
    let bob = make_keyhive().await;

    let initial = b"before-concurrent-rotations".to_vec();
    let initial_hash: [u8; 32] = *blake3::hash(&initial).as_bytes();
    let doc_id = alice.generate_doc(vec![], nonempty![initial_hash]).await?;

    let bob_id: Identifier = bob.active().lock().await.id().into();
    alice
        .receive_contact_card(&bob.get_existing_contact_card().await)
        .await?;
    alice.add_member(bob_id, doc_id, Access::Read, &[]).await?;

    let alice_events = alice.static_events_for_agent(bob_id).await;
    assert!(bob
        .ingest_unsorted_static_events(alice_events.into_values().collect())
        .await
        .is_empty());

    alice.force_pcs_update(doc_id).await?;
    bob.force_pcs_update(doc_id).await?;

    let alice_id: Identifier = alice.active().lock().await.id().into();
    let bob_events = bob.static_events_for_agent(alice_id).await;
    let alice_events = alice.static_events_for_agent(bob_id).await;
    assert!(alice
        .ingest_unsorted_static_events(bob_events.into_values().collect())
        .await
        .is_empty());
    assert!(bob
        .ingest_unsorted_static_events(alice_events.into_values().collect())
        .await
        .is_empty());

    let after = b"after-concurrent-rotations".to_vec();
    let after_hash: [u8; 32] = *blake3::hash(&after).as_bytes();
    alice
        .try_encrypt_content(doc_id, &after_hash, &vec![], &after)
        .await?;

    Ok(())
}

/// A PCS update written after a membership change must survive an archive round trip
/// once its locally generated private leaf key is re-imported and the update op is
/// replayed.
#[tokio::test]
async fn test_encrypt_after_membership_archive_plus_update_replay() -> TestResult {
    test_utils::init_logging();
    let alice_signer = MemorySigner::generate(&mut rand::thread_rng());
    let alice_log = Log::<Local, MemorySigner>::new();
    let alice = Keyhive::<Local, _, _, _, _, _, _>::generate(
        alice_signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        alice_log.clone(),
        rand::thread_rng(),
    )
    .await
    .unwrap();
    let bob = make_keyhive().await;

    let initial = b"initial".to_vec();
    let initial_hash: [u8; 32] = *blake3::hash(&initial).as_bytes();
    let doc_id = alice.generate_doc(vec![], nonempty![initial_hash]).await?;
    let initial_encrypted = alice
        .try_encrypt_content(doc_id, &initial_hash, &vec![], &initial)
        .await?;
    assert!(initial_encrypted.local_cgka_secret().is_none());

    let bob_id: Identifier = bob.active().lock().await.id().into();
    alice
        .receive_contact_card(&bob.get_existing_contact_card().await)
        .await?;
    alice.add_member(bob_id, doc_id, Access::Read, &[]).await?;
    let archive = alice.into_archive().await;
    while alice_log.pop().await.is_some() {}

    let checkpoint = b"membership-checkpoint".to_vec();
    let checkpoint_hash: [u8; 32] = *blake3::hash(&checkpoint).as_bytes();
    let checkpoint_encrypted = alice
        .try_encrypt_content(doc_id, &checkpoint_hash, &vec![initial_hash], &checkpoint)
        .await?;
    let local_secret = *checkpoint_encrypted
        .local_cgka_secret()
        .expect("the PCS update must expose its locally generated private leaf key");
    assert_eq!(
        local_secret.share_key(),
        local_secret.share_secret_key().share_key()
    );
    assert_eq!(
        keyhive_core::principal::document::id::DocumentId::from(local_secret.tree_id()),
        doc_id
    );
    let local_secret = bincode::deserialize(&bincode::serialize(&local_secret)?)?;

    let mut events = Vec::new();
    while let Some(event) = alice_log.pop().await {
        events.push(StaticEvent::from(event));
    }
    assert!(
        events
            .iter()
            .any(|event| matches!(event, StaticEvent::CgkaOperation(_))),
        "the first post-membership write must emit a PCS update"
    );

    let restored = Keyhive::<Local, _, _, _, _, _, _>::try_from_archive(
        &archive,
        alice_signer,
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        NoListener,
        Arc::new(Mutex::new(OsRng)),
    )
    .await?;
    restored.import_local_cgka_secret(local_secret).await?;
    let pending = restored.ingest_unsorted_static_events(events).await;
    assert!(pending.is_empty());
    let after = b"after-replay".to_vec();
    let after_hash: [u8; 32] = *blake3::hash(&after).as_bytes();
    restored
        .try_encrypt_content(doc_id, &after_hash, &vec![checkpoint_hash], &after)
        .await?;

    Ok(())
}
