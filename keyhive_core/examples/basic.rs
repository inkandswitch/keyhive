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
//!    forwards v1 and v2 to Bob. Bob can decrypt them; Carol, who carried
//!    them, cannot.
//! 6. Revocation. Alice removes Bob and writes v3. Bob keeps what he could
//!    already read, but cannot read what is written after.
//!
//! The same walkthrough as a rain diagram, the notation of Keyhive lab note 08
//! (<https://www.inkandswitch.com/keyhive/notebook/08/>): time runs down the
//! page, rows are certificates and writes, and dashed lines show where each
//! one's authority comes from. Step 1 happens before the document exists, and
//! step 5 moves only bytes, so neither is drawn. A `✗` marks a certificate
//! that is later revoked, and `o` is where the revocation is issued.
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
//!        │◀════╪═ [[Edit]] ═┤     │      │            │   4. a) Alice writes v1
//!        │     ┆            │     │      │            │
//!        │◀════╪═ [[Edit]] ═┤     │      │            │      b) and edits it to v2
//!        │     ┆            │     │      │            │
//!        │     ┆            │     │      │            │   5. Carol forwards v1 and v2
//!        │     ┆            │     │      │            │      to Bob; she cannot read
//!        │     ┆            │     │      │            │      them, but he can
//!        │     ├┄┄┄┄┄┄┄┄┄┄┄┄o──<Revoke>  │            │   6. a) Alice revokes Bob's Read
//!        │     ┆            │            │            │
//!        │◀════╧═ [[Edit]] ═┤            │            │      b) and writes v3, which Bob
//!        │                  │            │            │         cannot read
//!        ▼                  ▼            ▼            ▼ time
//! ```
//!
//! # What next
//!
//! - Introduce a fourth peer, give Bob `Edit`, and have him try to delegate
//!   `Admin` to it. Keyhive refuses: a delegation never conveys more than its
//!   issuer holds.
//! - Have Bob delegate `Read` to that fourth peer, then revoke Bob with
//!   `retain_all_other_members` set to `false`: the fourth peer loses access
//!   too. With `true`, Alice re-issues its delegation and it keeps access.
//! - Read `design/keyline/README.md` for how authority is computed,
//!   `design/causal_encryption.md` for how keys travel with content, and
//!   `design/threat_model.md` for what Keyhive does and does not protect.
//!
//! # Dependencies
//!
//! Copied into a project of its own, this example needs `blake3`,
//! `future_form`, `keyhive_codec`, `keyhive_content`, `keyhive_core`,
//! `keyhive_crypto`, `keyline`, `keyline_memory`, `nonempty`, `rand`, and
//! `tokio` with the `macros` and `rt-multi-thread` features.

use future_form::Sendable;
use keyhive_codec::traits::{Decode, Encode};
use keyhive_content::{
    encrypted::EncryptedContent, envelope::Envelope, store::memory::MemoryCiphertextStore,
};
use keyhive_core::{
    content::heads::ContentHeads, keyhive::Keyhive, listener::no_listener::NoListener,
    principal::document::id::DocumentId,
};
use keyhive_crypto::{identifier::Identifier, signer::memory::MemorySigner};
use keyline::power::Power;
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // 1. Identities.
    //
    // A peer is identified by its verifying key, and proves it is that peer
    // by signing with the matching signing key. Nothing else names it: no
    // account, no server. A contact card is signed and public: the peer's
    // identifier and a prekey, the public key others use to include it in a
    // document's key agreement. Peers swap cards however the application
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
    let names = [
        ("Alice", Identifier::from(alice.id())),
        ("Bob", Identifier::from(bob.id())),
        ("Carol", Identifier::from(carol.id())),
    ];
    println!("   Alice, Bob and Carol each made a signing key and swapped contact cards");

    // 2. A document.
    //
    // A document's identifier is a fresh verifying key. Its signing key signs
    // one certificate for each creator, giving them the Admin power, and is
    // then thrown away, so nothing can ever again be signed as the document
    // itself: every later change traces back to its creators. Here Alice
    // creates it alone; `coparents` would name others who administer it too.
    //
    // The content heads are the latest versions this peer knows of, and start
    // at the first version Alice is about to write. Keyhive does not follow
    // content itself: the application updates the heads as it writes, and
    // each revocation records them, so the content layer can tell what a
    // revoked member wrote after it.
    println!("\n2. a document");
    let v1 = b"Design doc, v1".to_vec();
    let v1_ref = content_ref(&v1);
    let coparents = vec![];
    let doc = alice.generate_doc(coparents, nonempty![v1_ref]).await?;
    println!("   Alice created a document, {:.12}…", doc.to_string());

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
    print_members(&alice, doc, &names).await?;

    // 4. Content.
    //
    // A version is named by a content reference, here its BLAKE3 hash, and
    // encrypted under a key derived from the document's current shared
    // secret. An edit names the version it follows, its predecessor, and
    // carries the predecessor's key: whoever can read v2 can read v1 through
    // it, with no key agreement at all. This is causal encryption.
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
    // Content travels separately, as bytes. Alice gives v1 and v2 to Carol,
    // who stores them and forwards them to Bob. To Carol they are opaque: her
    // refusal is what anyone without Read would get. What Relay gives her is
    // standing: she is sent the document's events, and so can serve its
    // ciphertext, but only to peers that hold Relay or better (A1 in
    // `design/threat_model.md`).
    println!("\n5. sync and relay");
    sync(&alice, &bob).await?;
    sync(&alice, &carol).await?;

    let carol_holds = [&v1_encrypted, &v2_encrypted]
        .map(|written| written.encrypted_content().encode().into_bytes());
    let [v1_forwarded, v2_forwarded] = carol_holds
        .each_ref()
        .map(|bytes| EncryptedContent::<Vec<u8>, [u8; 32]>::decode(bytes));
    let (v1_forwarded, v2_forwarded) = (v1_forwarded?, v2_forwarded?);

    let Err(refusal) = carol.try_decrypt_content(doc, &v2_forwarded).await else {
        return Err("a relay decrypted the document".into());
    };
    println!(
        "   Carol stores v1 and v2 but cannot decrypt them (relays are not in the key agreement): {refusal}"
    );

    let opened = bob.try_decrypt_content(doc, &v2_forwarded).await?;
    ensure(opened.plaintext == v2, "Bob's v2 differs from Alice's")?;
    println!(
        "   Bob decrypts the v2 Carol forwarded: {}",
        as_text(&opened.plaintext)
    );

    // `Envelope::open` takes only a ciphertext, a key, and the document the
    // key is bound to. It uses none of Bob's Keyhive state: the key v2
    // carries is enough to read v1.
    let v1_key = opened
        .ancestors
        .get(&v1_ref)
        .ok_or("v2 carries no key for v1")?;
    let (from_v2, _) = Envelope::open(&v1_forwarded, v1_key, doc.into())?;
    ensure(
        from_v2.plaintext == v1,
        "the key v2 carries opened the wrong v1",
    )?;
    println!(
        "   and opens the v1 Carol forwarded with the key v2 carries: {}",
        as_text(&from_v2.plaintext)
    );

    // 6. Revocation.
    //
    // Alice revokes Bob. The revocation is another signed certificate, and on
    // Alice's peer it also removes Bob from the key agreement, so the next
    // shared secret is one he cannot derive. This is the mechanism behind
    // post-compromise security: a member who is removed, or whose keys leak,
    // cannot read what comes after. Two gaps remain, listed in
    // `design/threat_model.md`: other peers do not yet remove Bob themselves
    // (G4), and a revoked member can put a key of his own back (G1).
    //
    // Whatever Bob could read stays readable to him: he may have kept a copy
    // anyway, and a CRDT (a data type whose replicas merge without
    // coordination) needs its whole history.
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
    print_members(&alice, doc, &names).await?;

    let still = bob
        .try_decrypt_content(doc, v2_encrypted.encrypted_content())
        .await?;
    ensure(
        still.plaintext == v2,
        "Bob's v2 changed after his revocation",
    )?;
    println!("   Bob still decrypts v2: {}", as_text(&still.plaintext));

    // Alice no longer sends Bob the document's key-agreement operations, but
    // they would not help him: the secret v3 is under was made for a group
    // he is not in.
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
    ensure(
        waiting.is_empty(),
        &format!("{} events are missing a dependency", waiting.len()),
    )
}

/// Who `peer` sees holding a power over `doc`, by name.
async fn print_members(
    peer: &Peer,
    doc: DocumentId,
    names: &[(&str, Identifier)],
) -> Result<(), Error> {
    let members = peer.reachable_members(doc).await?;
    let holders: Vec<String> = names
        .iter()
        .filter_map(|(name, id)| members.get(id).map(|power| format!("{name} {power}")))
        .collect();
    println!("   who holds what: {}", holders.join(", "));
    Ok(())
}

/// An error carrying `message` unless `holds`.
fn ensure(holds: bool, message: &str) -> Result<(), Error> {
    if holds {
        Ok(())
    } else {
        Err(message.into())
    }
}

/// A version's content reference: its BLAKE3 hash.
fn content_ref(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).into()
}

/// `bytes` as text, in quotes, for the output.
fn as_text(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}
