use std::sync::Arc;

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    crypto::signer::memory::MemorySigner,
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::{log::Log, no_listener::NoListener},
    principal::{agent::Agent, membered::Membered},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use nonempty::nonempty;
use rand::rngs::OsRng;
use testresult::TestResult;

#[allow(clippy::type_complexity)]
struct NewKeyhive {
    signer: MemorySigner,
    log: Log<MemorySigner>,
    keyhive: Keyhive<
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        Log<MemorySigner>,
        rand::rngs::ThreadRng,
    >,
}

async fn make_keyhive() -> NewKeyhive {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    let log = Log::new();
    let keyhive = Keyhive::generate(sk.clone(), store, log.clone(), rand::thread_rng())
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

    let indie_bob = { bob.active().lock().await.individual().clone() };
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
        .await?;
    bob.ingest_unsorted_static_events(alice_events.into_values().collect())
        .await?;

    // Attempt to decrypt on bob
    let doc_id = { doc.lock().await.doc_id() };
    let doc_on_bob = bob.get_document(doc_id).await.unwrap();
    let decrypted = bob
        .try_decrypt_content(doc_on_bob.clone(), encrypted.encrypted_content())
        .await?;
    assert_eq!(decrypted, init_content);

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

    let alice = Keyhive::try_from_archive(
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
    alice.ingest_unsorted_static_events(events).await.unwrap();

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
    let mut events = log
        .0
        .lock()
        .await
        .clone()
        .into_iter()
        .chain(
            alice
                .events_for_agent(&alice.individual().await.into())
                .await
                .unwrap()
                .into_values(),
        )
        .map(StaticEvent::from)
        .collect::<Vec<_>>();

    if let Some(op) = encrypted.update_op() {
        events.push(StaticEvent::from(Box::new(op.clone())));
    }

    let reloaded = {
        let keyhive = Keyhive::try_from_archive(
            &archive1,
            sk.clone(),
            MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
            Log::new(),
            Arc::new(Mutex::new(OsRng)),
        )
        .await
        .unwrap();

        keyhive.ingest_archive(archive2).await.unwrap();
        keyhive.ingest_unsorted_static_events(events).await.unwrap();

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
