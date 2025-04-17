use std::rc::Rc;

use keyhive_core::{
    access::Access,
    crypto::signer::memory::MemorySigner,
    event::static_event::StaticEvent,
    keyhive::Keyhive,
    listener::{log::Log, no_listener::NoListener},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use nonempty::nonempty;
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

    let NewKeyhive {
        keyhive: mut alice, ..
    } = make_keyhive().await;

    let init_content = "hello world".as_bytes().to_vec();
    let init_hash = blake3::hash(&init_content);

    let doc = alice
        .generate_doc(vec![], nonempty![init_hash.into()])
        .await?;

    let NewKeyhive {
        keyhive: mut bob, ..
    } = make_keyhive().await;

    alice
        .add_member(
            bob.active().clone().into(),
            &mut doc.clone().into(),
            Access::Read,
            &[],
        )
        .await?;

    let encrypted = alice
        .try_encrypt_content(doc.clone(), &init_hash.into(), &vec![], &init_content)
        .await?;

    // now sync everything to bob
    let events = alice.static_events_for_agent(&bob.active().clone().into())?;
    bob.ingest_unsorted_static_events(events.into_values().collect())
        .await?;

    // Now attempt to decrypt on bob
    let doc_on_bob = bob.get_document(doc.borrow().doc_id()).unwrap();
    let decrypted = bob.try_decrypt_content(doc_on_bob.clone(), encrypted.encrypted_content())?;

    assert_eq!(decrypted, init_content);
    Ok(())
}

#[tokio::test]
async fn test_decrypt_after_to_from_archive() {
    test_utils::init_logging();
    let NewKeyhive {
        keyhive: mut alice,
        signer: sk,
        log,
    } = make_keyhive().await;

    let archive = alice.into_archive();

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

    let mut alice = Keyhive::try_from_archive(
        &archive,
        sk,
        MemoryCiphertextStore::new(),
        NoListener,
        rand::thread_rng(),
    )
    .unwrap();
    let mut events = Vec::new();
    while let Some(evt) = log.pop() {
        events.push(StaticEvent::from(evt));
    }
    alice.ingest_unsorted_static_events(events).await.unwrap();

    let doc = alice.get_document(doc.borrow().doc_id()).unwrap();

    let decrypted = alice
        .try_decrypt_content(doc.clone(), encrypted.encrypted_content())
        .unwrap();

    assert_eq!(decrypted, init_content);
}

#[tokio::test]
async fn test_decrypt_after_fork_and_merge() {
    test_utils::init_logging();
    let NewKeyhive {
        keyhive: mut alice,
        signer: sk,
        log,
    } = make_keyhive().await;

    let archive1 = alice.into_archive();

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

    let archive2 = alice.into_archive();
    let mut events = Rc::unwrap_or_clone(log.0)
        .into_inner()
        .into_iter()
        .chain(
            alice
                .events_for_agent(&alice.individual().into())
                .unwrap()
                .into_values(),
        )
        .map(StaticEvent::from)
        .collect::<Vec<_>>();

    if let Some(op) = encrypted.update_op() {
        events.push(StaticEvent::from(Box::new(op.clone())));
    }

    let mut reloaded = {
        let mut keyhive = Keyhive::try_from_archive(
            &archive1,
            sk.clone(),
            MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
            Log::new(),
            rand::thread_rng(),
        )
        .unwrap();

        keyhive.ingest_archive(archive2).await.unwrap();
        keyhive.ingest_unsorted_static_events(events).await.unwrap();

        keyhive
    };

    let doc = reloaded.get_document(doc.borrow().doc_id()).unwrap();

    let decrypted = reloaded
        .try_decrypt_content(doc.clone(), encrypted.encrypted_content())
        .unwrap();

    assert_eq!(decrypted, init_content);
}
