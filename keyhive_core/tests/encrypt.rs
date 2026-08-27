use future_form::Local;
use std::{collections::HashMap, sync::Arc};

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access, event::static_event::StaticEvent, keyhive::Keyhive, listener::log::Log,
    principal::agent::Agent, store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{digest::Digest, signer::memory::MemorySigner};
use nonempty::nonempty;
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

    let public_agent: Agent<_, _, _, _> = public_agent();

    // The first instance makes the document public, revokes that, and grants it again, so
    // there are revocations in the graph the second instance has to apply.
    let doc_id = alice.generate_doc(vec![], nonempty![init_hash]).await?;

    alice
        .add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;

    alice
        .revoke_member(
            keyhive_core::principal::public::Public.individual().id(),
            true,
            doc_id,
        )
        .await?;

    alice
        .add_member(public_agent.dupe().id(), doc_id, Access::Read, &[])
        .await?;

    alice.force_pcs_update(doc_id).await?;

    // The first instance's events to the second.
    let alice_active_agent: Agent<_, _, _, _> = alice.active().lock().await.clone().into();
    let alice_events = alice.static_events_for_agent(&alice_active_agent).await;

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
    let alice_events_for_bob = alice.static_events_for_agent(&public_agent).await;

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
