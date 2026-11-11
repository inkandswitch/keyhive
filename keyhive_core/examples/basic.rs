//! A walkthrough of Keyhive: who may read a document, and how that changes.
//!
//! A Keyhive document holds no content. It is an authority graph, a set of
//! signed certificates saying who may do what, and a key agreement, the
//! shared secrets from which its readers derive the keys to decrypt. The
//! content itself is encrypted under those keys, and the application stores
//! and sends it however it likes. Here it is handed from peer to peer.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p keyhive_core --example basic
//! ```
//!
//! Three peers, Alice, Bob and Carol, share one document:
//!
//! 1. Identities. Each peer is a signing key, and peers introduce themselves
//!    with contact cards.
//! 2. A document. Alice creates one, and is its first admin.
//! 3. Delegation. Alice gives Carol Relay and Bob Read, each with a signed
//!    certificate.
//! 4. Content. Alice writes v1, then edits it to v2.
//! 5. Sync and relay. Each peer gets the events it is entitled to, and Carol
//!    forwards v2 to Bob. Bob can decrypt it; Carol, who carried it, cannot.
//! 6. Revocation. Alice removes Bob and writes v3. Bob keeps what he could
//!    already read, but cannot read what is written after.
//!
//! The same walkthrough as a rain diagram, the notation of [Keyhive lab note
//! 08]: time runs down the page, rows are certificates and writes, and dashed
//! lines show where each one's authority comes from. Step 1 happens before the
//! document exists, so it is not drawn.
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
//!        │◀════╪═ [write] ══┤     │      │            │      b) and edits it to v2
//!        │     ┆            │     │      │            │
//!        │     ┆            │     │      │            │   5. Carol relays v2 to Bob,
//!        │     ┆            │     │      │            │      who reads it; she cannot
//!        │     ┆            │     │      │            │
//!        │     ├┄┄┄┄┄┄┄┄┄┄┄┄o──<Revoke>  │            │   6. a) Alice revokes Bob's Read
//!        │     ┆            │            │            │
//!        │◀════╧═ [write] ══┤            │            │      b) and writes v3, which Bob
//!        │                  │            │            │         cannot read
//!        ▼                  ▼            ▼            ▼ time
//! ```
//!
//! # What next
//!
//! - Give Bob `Edit`, and have him try to delegate `Admin` to a fourth peer.
//!   Keyhive refuses: a delegation never conveys more than its issuer holds.
//! - Revoke Bob with `retain_all_other_members` set to `false`, and see who
//!   else loses access.
//! - Read [`design/keyline/README.md`] for how authority is computed, and
//!   [`design/causal_encryption.md`] for how keys travel with content.
//!
//! # Dependencies
//!
//! Copied into a project of its own, this example needs `blake3`,
//! `future_form`, `keyhive_codec`, `keyhive_content`, `keyhive_core`,
//! `keyhive_crypto`, `keyline`, `keyline_memory`, `nonempty`, `rand`, and
//! `tokio` with the `macros` and `rt-multi-thread` features.
//!
//! [Keyhive lab note 08]: https://www.inkandswitch.com/keyhive/notebook/08/
//! [`design/keyline/README.md`]: https://github.com/inkandswitch/keyhive/blob/main/design/keyline/README.md
//! [`design/causal_encryption.md`]: https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md

use future_form::Sendable;
use keyhive_codec::traits::{Decode, Encode};
use keyhive_content::{
    encrypted::EncryptedContent, envelope::Envelope, store::memory::MemoryCiphertextStore,
};
use keyhive_core::{
    content::heads::ContentHeads, keyhive::Keyhive, listener::no_listener::NoListener,
};
use keyhive_crypto::signer::memory::MemorySigner;
use keyline::power::Power;
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::rngs::OsRng;

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
    // A document's identifier is a fresh public key. Its secret half signs
    // one certificate for each creator, giving them the Admin power, and is
    // then thrown away, so nothing can ever again be signed as the document
    // itself: every later change traces back to its creators. Here Alice
    // creates it alone; `coparents` would name others who administer it too.
    //
    // The content heads are the latest versions this replica knows of, and
    // start at the first version Alice is about to write. Keyhive does not
    // follow content itself: the application updates the heads as it writes,
    // and each revocation records them, so the content layer can tell what a
    // revoked member wrote after it.
    println!("\n2. a document");
    let v1 = b"Design doc, v1".to_vec();
    let v1_ref = content_ref(&v1);
    let coparents = vec![];
    let doc = alice.generate_doc(coparents, nonempty![v1_ref]).await?;
    let doc_id = doc.to_string();
    println!("   Alice created a document, {}…", &doc_id[..12]);

    // 3. Delegation.
    //
    // For each delegation, Alice signs a certificate giving a power over the
    // document. Powers are ordered `Relay < Read < Edit < Admin`, each
    // including those below it: Relay may store and forward ciphertext
    // without reading it, Read may decrypt, Edit may write, and Admin
    // governs: an admin's revocations reach delegations it did not issue.
    // Keyhive enforces who can decrypt; that a reader may not write is
    // recorded here, but enforced by the application's CRDT layer, which
    // refuses their edits. Any member can pass its power on, but a delegation
    // conveys no more than its issuer holds. Readers join the document's key
    // agreement, which is what lets them derive its keys; a relay does not.
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
    // it, without the key agreement. This is causal encryption.
    println!("\n4. content");
    let v1_encrypted = alice.try_encrypt_content(doc, &v1_ref, &[], &v1).await?;
    let v2 = b"Design doc, v2: now with diagrams".to_vec();
    let v2_ref = content_ref(&v2);
    let v2_encrypted = alice
        .try_encrypt_content(doc, &v2_ref, &[v1_ref], &v2)
        .await?;
    alice.set_content_heads(doc, [v2_ref]).await?;
    println!(
        "   Alice wrote {} and edited it to {}",
        as_text(&v1),
        as_text(&v2)
    );

    // 5. Sync and relay.
    //
    // Keyhive's own state travels as signed events: certificates, prekey
    // operations, and key-agreement operations, in a serializable ("static")
    // form. `static_events_for_agent` is what Alice would send one peer: all
    // the events that peer is entitled to see. `ingest_unsorted_static_events`
    // applies them in dependency order, whatever order they arrive in.
    //
    // Content travels separately, as bytes. Alice gives v2 to Carol, who
    // stores it and forwards it to Bob. To Carol it is opaque.
    println!("\n5. sync and relay");
    sync(&alice, &bob).await?;
    sync(&alice, &carol).await?;

    let held_by_carol = v2_encrypted.encrypted_content().encode().into_bytes();
    let Err(refusal) = carol
        .try_decrypt_content(doc, &EncryptedContent::decode(&held_by_carol)?)
        .await
    else {
        return Err("a relay decrypted the document".into());
    };
    println!(
        "   Carol stores v2 but cannot decrypt it (relays are not in the key agreement): {refusal}"
    );

    let forwarded = EncryptedContent::decode(&held_by_carol)?;
    let opened = bob.try_decrypt_content(doc, &forwarded).await?;
    assert_eq!(opened.plaintext, v2);
    println!(
        "   Bob decrypts the copy Carol forwarded: {}",
        as_text(&opened.plaintext)
    );

    let v1_key = opened
        .ancestors
        .get(&v1_ref)
        .ok_or("v2 carries no key for v1")?;
    let (from_v2, _) = Envelope::open(v1_encrypted.encrypted_content(), v1_key, doc.into())?;
    assert_eq!(from_v2.plaintext, v1);
    println!(
        "   and opens v1 with the key v2 carries: {}",
        as_text(&from_v2.plaintext)
    );

    // 6. Revocation.
    //
    // Alice revokes Bob. The revocation is another signed certificate, and on
    // Alice's replica it also removes Bob from the key agreement, so the next
    // shared secret is one he cannot derive. This is post-compromise
    // security. Other replicas do not yet remove him themselves, and a
    // revoked member can put a key of his own back: see gaps G1 and G4 in
    // `design/threat_model.md`. Whatever Bob could read stays readable to
    // him: he may have kept a copy anyway, and a CRDT (a data type whose
    // replicas merge without coordination) needs its whole history.
    //
    // `retain_all_other_members` keeps anyone whose access came through Bob,
    // re-issued by Alice. Bob delegated to no one, so here it changes nothing.
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
    alice.set_content_heads(doc, [v3_ref]).await?;
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
        return Err("a revoked reader decrypted what was written after".into());
    };
    println!("   but not v3, encrypted under a secret made after his removal: {refusal}");

    Ok(())
}

/// A Keyhive peer that keeps everything in memory.
///
/// The type parameters are the simplest concrete choices: futures that are
/// `Send`, an in-memory signer, 32-byte content references (BLAKE3 hashes
/// here), raw bytes as plaintext, an in-memory ciphertext store, no event
/// listener, the OS's CSPRNG, and an in-memory Keyline store. Keyline is
/// Keyhive's authority graph: the certificates, and who they make powerful.
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
    if !waiting.is_empty() {
        return Err(format!("{} events are missing a dependency", waiting.len()).into());
    }
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
