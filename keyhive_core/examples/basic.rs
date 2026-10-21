//! A minimal end-to-end tour of keyhive's authorization flow.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p keyhive_core --example basic
//! ```
//!
//! The example walks through five steps:
//!
//! 1. Create two entities, `alice` and `bob`, as independent peers.
//! 2. Alice creates a document she owns.
//! 3. Alice delegates pull and read access on that document to bob.
//! 4. Alice edits the document.
//! 5. Bob syncs alice's changes and reads the edit.
//!
//! One thing to keep in mind: a keyhive [`Document`] is a capability and
//! key-agreement object, not a content store. It tracks content reference
//! hashes and manages the per-epoch symmetric keys (via CGKA) that authorize
//! reading and writing. The actual content bytes live outside keyhive, in an
//! application or a [`CiphertextStore`]. So "edit the document" here means
//! "encrypt a new version of the bytes under the document's keys," and "see the
//! update" means "ingest alice's membership and key-agreement events, then
//! decrypt the ciphertext she produced." A real application would ship that
//! ciphertext over the network; this example hands it to bob directly.
//!
//! [`Document`]: keyhive_core::principal::document::Document
//! [`CiphertextStore`]: keyhive_core::store::ciphertext::CiphertextStore

use std::sync::Arc;

use dupe::Dupe;
use future_form::Local;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{agent::Agent, membered::Membered},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::signer::memory::MemorySigner;
use nonempty::nonempty;

/// A fully in-memory keyhive peer.
///
/// The type parameters fix the simplest concrete choices: local (single
/// threaded) futures, an in-memory signer, 32-byte blake3 content references,
/// raw `Vec<u8>` plaintext, an in-memory ciphertext store, no membership event
/// listener, and a thread-local CSPRNG.
type Peer = Keyhive<
    Local,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    rand::rngs::ThreadRng,
>;

/// Generates a fresh in-memory peer with its own signing key.
async fn make_peer() -> Peer {
    let signer = MemorySigner::generate(&mut rand::thread_rng());
    let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
    Keyhive::generate(signer, store, NoListener, rand::thread_rng())
        .await
        .expect("failed to generate keyhive instance")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create two entities. Alice and bob are independent peers, each with
    //    their own signing key and local state.
    let alice = make_peer().await;
    let bob = make_peer().await;
    println!("1. created two peers: alice and bob");

    // 2. Alice creates a document she owns. We hash the initial content to get
    //    a content reference; the document is created with that reference as its
    //    first content head. Passing no coparents means alice is the sole owner
    //    (and automatically an admin).
    let v1 = b"hello world".to_vec();
    let v1_ref: [u8; 32] = blake3::hash(&v1).into();
    let doc = alice.generate_doc(vec![], nonempty![v1_ref]).await?;
    let doc_id = doc.lock().await.doc_id();
    println!(
        "2. alice created a document ({doc_id}) with initial content {:?}",
        String::from_utf8_lossy(&v1)
    );

    // 3. Alice delegates pull and read access to bob. We grant `Access::Read`:
    //    access is ordered `Relay < Read < Edit < Admin`, so read already
    //    implies relay (the "pull" capability to fetch bytes without decrypting).
    let indie_bob = bob.active().lock().await.individual().lock().await.clone();
    let bob_agent = Agent::Individual(indie_bob.id(), Arc::new(Mutex::new(indie_bob)));
    alice
        .add_member(
            bob_agent,
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await?;
    println!("3. alice delegated pull + read access to bob");

    // 4. Alice edits the document. We encrypt a new version of the bytes under
    //    the document's keys, naming v1 as the predecessor so the history
    //    records that v2 follows v1.
    let v2 = b"hello world, now with edits".to_vec();
    let v2_ref: [u8; 32] = blake3::hash(&v2).into();
    let encrypted = alice
        .try_encrypt_content(doc.dupe(), &v2_ref, &vec![v1_ref], &v2)
        .await?;
    println!(
        "4. alice edited the document to {:?}",
        String::from_utf8_lossy(&v2)
    );

    // 5. Bob syncs and reads the update. `static_events_for_agent` collects the
    //    membership and key-agreement events bob is entitled to (his delegation
    //    plus the CGKA operations needed to derive the decryption key), and
    //    `ingest_unsorted_static_events` applies them in dependency order. Bob
    //    can then decrypt the ciphertext alice produced.
    let events = alice
        .static_events_for_agent(&bob.active().lock().await.clone().into())
        .await;
    bob.ingest_unsorted_static_events(events.into_values().collect())
        .await;

    let doc_on_bob = bob
        .get_document(doc_id)
        .await
        .expect("bob should now know about the document");
    let decrypted = bob
        .try_decrypt_content(doc_on_bob, encrypted.encrypted_content())
        .await?;

    assert_eq!(decrypted, v2);
    println!(
        "5. bob synced and decrypted alice's edit: {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    Ok(())
}
