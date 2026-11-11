//! A walkthrough of Keyhive: who may read a document, and how that changes.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p keyhive_core --example basic
//! ```
//!
//! Three peers share one document. Here is the walkthrough as a rain diagram,
//! the notation of [Keyhive lab note 08]: time runs down the page, rows are
//! certificates, and dashed lines show where each one's authority comes from.
//!
//! ```text
//!      (Doc)             (Alice)       (Bob)       (Carol)
//!        │╰┄┄┄┄╮ ╭┄┄┄┄┄┄┄┄┄┄┼┄┄┄┄┄╮      │            │
//!        ├─ [Admin] ───────▶│     ┆      │            │   2. The Doc grants Alice Admin
//!        │     ┆ ┆          │     ┆      │            │
//!        │     ┆ ┆          │     ┆      │            │
//!        │     ┆ ┆          ├─ [Relay] ──┼───────────▶│   3. a) Alice gives Carol Relay
//!        │     ┆ ┆          │            │            │
//!        │     ┆ ╰┄┄┄┄┄┄┄┄┄┄┼┄┄┄┄┄╮      │            │
//!        │     ┆            ├─ [Read] ──▶│            │      b) and gives Bob Read
//!        │     ┆            │     ✗      │            │
//!        │◀════╪═ [write] ══┤     │      │            │   4. a) Alice writes v1
//!        │     ┆            │     │      │            │
//!        │◀════╪═ [write] ══┤     │      │            │     b) and edits it to v2
//!        │     ┆            │     │      │            │
//!        │     ┆            │     │      │            │   5. Bob syncs and reads v2;
//!        │     ┆            │     │      │            │      Carol syncs, but has no key
//!        │     ┆            │     │      │            │
//!        │     ╰┄┄┄┄┄┄┄┄┄┄┄┄o──<Revoke>  │            │   6. Alice revokes Bob's Read
//!        │                  │            │            │
//!        │◀══════ [write] ══┤            │            │      and writes v3, which Bob
//!        │                  │            │            │      cannot read
//!        ▼                  ▼            ▼            ▼ time
//! ```
//!
//! Step 1, introductions, happens before the document exists, so it is not
//! drawn.
//!
//! [Keyhive lab note 08]: https://www.inkandswitch.com/keyhive/notebook/08/
//!
//! The steps:
//!
//! 1. Identities. Each peer is a signing key, and peers introduce themselves
//!    with contact cards.
//! 2. A document. Alice creates one and, as its creator, owns it.
//! 3. Delegation. Alice gives Carol Relay and Bob Read, each with a signed
//!    certificate.
//! 4. Content. Alice writes v1, then edits it to v2.
//! 5. Sync. Each peer gets the events it is entitled to. Bob can decrypt v2;
//!    Carol holds the same ciphertext and cannot.
//! 6. Revocation. Alice removes Bob and writes v3. Bob keeps what he could
//!    already read, but cannot read anything written after.
//!
//! A Keyhive document holds no content. It is an authority graph (who may do
//! what) and a key agreement (the keys that let its readers decrypt). The bytes
//! themselves are encrypted under those keys and stored and sent by the
//! application. Here they are handed from peer to peer directly.

use future_form::Sendable;
use keyhive_content::store::memory::MemoryCiphertextStore;
use keyhive_core::{
    content::heads::ContentHeads, keyhive::Keyhive, listener::no_listener::NoListener,
    principal::document::id::DocumentId,
};
use keyhive_crypto::signer::memory::MemorySigner;
use keyline::power::Power;
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::rngs::OsRng;

/// A Keyhive peer that keeps everything in memory.
///
/// The type parameters are the simplest concrete choices: futures that are
/// `Send`, an in-memory signer, 32-byte BLAKE3 hashes as content references,
/// raw bytes as plaintext, an in-memory ciphertext store, no event listener,
/// the OS's CSPRNG, and an in-memory store for the authority graph.
type Peer = Keyhive<
    Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    OsRng,
    MemoryKeyline<ContentHeads<[u8; 32]>>,
>;

type Error = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // 1. Identities.
    //
    // A peer is identified by its signing key. Nothing else names it: no
    // account, no server. A contact card is the signed public half: the
    // peer's identifier and a prekey, the public key others use to include it
    // in a document's key agreement. Peers swap cards however the application
    // likes, much as people swap phone numbers.
    println!("\n1. identities");
    let alice = new_peer().await?;
    let bob = new_peer().await?;
    let carol = new_peer().await?;
    for (a, b) in [(&alice, &bob), (&alice, &carol), (&bob, &carol)] {
        a.receive_contact_card(&b.get_existing_contact_card().await)
            .await?;
        b.receive_contact_card(&a.get_existing_contact_card().await)
            .await?;
    }
    println!("   Alice, Bob and Carol each made a signing key and swapped contact cards");

    // 2. A document.
    //
    // A document's identifier is a fresh public key. Its secret half signs a
    // single certificate giving Alice the Admin power, and is then thrown
    // away, so nothing can ever again be signed as the document itself:
    // every later change traces back to Alice. The initial content heads say
    // where its history starts: here, at the hash of the first version Alice
    // is about to write.
    println!("\n2. a document");
    let v1 = b"Design doc, v1".to_vec();
    let v1_ref = content_ref(&v1);
    let doc = alice.generate_doc(vec![], nonempty![v1_ref]).await?;
    println!("   Alice created a document, {}", short(doc));

    // 3. Delegation.
    //
    // For each delegation, Alice signs a certificate giving a power over the
    // document. Powers are ordered `Relay < Read < Edit < Admin`, each
    // including those below it: Relay can store and forward ciphertext
    // without reading it, Read can decrypt, Edit can write, and Admin
    // governs: an admin's revocations reach delegations it did not issue. Any
    // member can pass its power on, but a delegation conveys no more than its
    // issuer holds. Readers join the document's key agreement, which is what
    // lets them derive its keys; a relay does not, so it can serve the
    // document to readers without being able to read it.
    println!("\n3. delegation");
    alice.add_member(carol.id(), doc, Power::Relay).await?;
    alice.add_member(bob.id(), doc, Power::Read).await?;
    println!("   Alice delegated Relay to Carol and Read to Bob");

    // 4. Content.
    //
    // A version is named by a content reference, here its BLAKE3 hash, and
    // encrypted under a key derived from the document's current shared
    // secret. An edit names the version it follows, its predecessor, and
    // carries the predecessor's key: whoever can read v2 can read v1 through
    // it. This is causal encryption.
    println!("\n4. content");
    alice.try_encrypt_content(doc, &v1_ref, &[], &v1).await?;
    let v2 = b"Design doc, v2: now with diagrams".to_vec();
    let v2_ref = content_ref(&v2);
    let v2_encrypted = alice
        .try_encrypt_content(doc, &v2_ref, &[v1_ref], &v2)
        .await?;
    println!(
        "   Alice wrote {} and edited it to {}",
        as_text(&v1),
        as_text(&v2)
    );

    // 5. Sync.
    //
    // Keyhive's state travels as signed events: certificates and
    // key-agreement operations. `static_events_for_agent` is what Alice would
    // send one peer, all the events that peer is entitled to see, and
    // `ingest_unsorted_static_events` applies them in dependency order,
    // whatever order they arrive in. The ciphertext itself is the
    // application's to send; here every peer is handed it.
    println!("\n5. sync");
    sync(&alice, &bob).await?;
    sync(&alice, &carol).await?;

    let opened = bob
        .try_decrypt_content(doc, v2_encrypted.encrypted_content())
        .await?;
    assert_eq!(opened.plaintext, v2);
    assert!(opened.ancestors.contains_key(&v1_ref));
    println!("   Bob decrypts v2: {}", as_text(&opened.plaintext));
    println!("     and finds v1's key inside it");

    let Err(refusal) = carol
        .try_decrypt_content(doc, v2_encrypted.encrypted_content())
        .await
    else {
        panic!("a relay decrypted the document");
    };
    println!("   Carol holds the same ciphertext but cannot decrypt it: {refusal}");

    // 6. Revocation.
    //
    // Alice revokes Bob. The revocation is another signed certificate, and it
    // also removes Bob from the key agreement, so the next shared secret is
    // one he cannot derive (post-compromise security). Whatever Bob
    // could read stays readable to him: he may have kept a copy anyway, and a
    // CRDT needs its whole history. What changes is everything written next.
    //
    // Revoking Bob would also cut off anyone whose access came through him.
    // Retaining the others has Alice re-issue those delegations herself, so
    // only Bob loses access. Bob delegated to no one, so here there is no one
    // else to keep.
    println!("\n6. revocation");
    let retain_all_other_members = true;
    alice
        .revoke_member(bob.id(), retain_all_other_members, doc)
        .await?;
    let v3 = b"Design doc, v3: after Bob left".to_vec();
    let v3_ref = content_ref(&v3);
    let v3_encrypted = alice
        .try_encrypt_content(doc, &v3_ref, &[v2_ref], &v3)
        .await?;
    sync(&alice, &bob).await?;
    println!("   Alice revoked Bob and wrote {}", as_text(&v3));

    let still = bob
        .try_decrypt_content(doc, v2_encrypted.encrypted_content())
        .await?;
    assert_eq!(still.plaintext, v2);
    println!("   Bob still decrypts v2: {}", as_text(&still.plaintext));

    let Err(refusal) = bob
        .try_decrypt_content(doc, v3_encrypted.encrypted_content())
        .await
    else {
        panic!("a revoked reader decrypted what was written after");
    };
    println!("   but cannot decrypt v3: {refusal}");

    Ok(())
}

/// A fresh peer with its own signing key.
async fn new_peer() -> Result<Peer, Error> {
    Ok(Keyhive::generate(
        MemorySigner::generate(&mut OsRng),
        MemoryCiphertextStore::new(),
        NoListener,
        MemoryKeyline::new(),
        OsRng,
    )
    .await?)
}

/// Send `to` every event `from` holds that `to` is entitled to see.
async fn sync(from: &Peer, to: &Peer) -> Result<(), Error> {
    let events = from.static_events_for_agent(to.id()).await?;
    let waiting = to
        .ingest_unsorted_static_events(events.into_values().collect())
        .await;
    assert!(
        waiting.is_empty(),
        "every event's dependencies were sent too"
    );
    Ok(())
}

/// A version's content reference: its BLAKE3 hash.
fn content_ref(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).into()
}

/// `bytes` as text, in quotes, for the output.
fn as_text(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}

/// The start of a document's id, enough to recognise it in the output.
fn short(doc: DocumentId) -> String {
    doc.to_string().chars().take(12).collect::<String>() + "…"
}
