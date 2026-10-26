use beekem::{
    id::{MemberId, TreeId},
    operation::{CgkaOperation, CitationId},
};
use future_form::{FutureForm, Sendable};
use keyhive_codec::traits::Decode;
use keyhive_core::{
    content::heads::ContentHeads,
    crypto::digest::Digest,
    keyhive::{Keyhive, ReceiveCgkaOpError},
    listener::no_listener::NoListener,
    principal::{
        document::id::DocumentId,
        individual::{
            id::IndividualId,
            op::{add_key::AddKeyOp, KeyOp},
            IndividualState,
        },
    },
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::{make_simple_keyhive, Hive, KeylineStore},
};
use keyhive_crypto::{
    identifier::Identifier,
    share_key::ShareKey,
    signed::{SerdeSigned, SigningError},
    signer::{async_signer::AsyncSigner, memory::MemorySigner},
    verifiable::Verifiable,
    verified::Signed,
};
use keyline::{
    certificate::VerifiedCertificate, contract::Keyline, delegation::Delegation, power::Power,
    revocation::Revocation,
};
use nonempty::nonempty;
use rand::rngs::OsRng;
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use testresult::TestResult;

/// The current CGKA op heads for `doc` as `observer` sees them.
async fn cgka_heads(observer: &Hive, doc: DocumentId) -> Vec<Digest<SerdeSigned<CgkaOperation>>> {
    let ops = observer
        .cgka_ops_for_doc(&doc)
        .await
        .expect("the observer holds the document");
    let referenced: HashSet<_> = ops
        .iter()
        .flat_map(|op| op.payload.predecessors())
        .collect();
    ops.iter()
        .map(|op| Digest::hash(op.as_ref()))
        .filter(|d| !referenced.contains(d))
        .collect()
}

/// Register `who`'s identity with `observer` so it can be added.
async fn learn(observer: &Hive, who: &Hive) -> IndividualId {
    let prekey = who.expand_prekeys().await.expect("prekeys expand");
    let indie = IndividualState::new(KeyOp::Add(prekey));
    let id = indie.id();
    observer.register_individual(indie).await;
    id
}

/// A fresh prekey of `who`'s, and the key proof an add of `who` carries.
async fn proven_prekey(who: &Hive) -> (ShareKey, Vec<u8>) {
    let op = who.expand_prekeys().await.expect("prekeys expand");
    (op.payload().share_key, KeyOp::Add(op).to_key_proof())
}

/// Alice creates a document and adds Bob as a reader.
async fn doc_with_alice_and_bob() -> TestResult<(Hive, Hive, DocumentId)> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let bob_id = learn(&alice, &bob).await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Power::Read).await?;
    Ok((alice, bob, doc_id))
}

/// The members of `observer`'s CGKA group for `doc`.
async fn cgka_members(observer: &Hive, doc: DocumentId) -> Vec<IndividualId> {
    observer
        .cgka_members_for(doc)
        .await
        .expect("knows the document")
        .expect("observer has joined the CGKA group")
        .into_iter()
        .collect()
}

/// The adds of `member` in `observer`'s CGKA graph for `doc`.
async fn adds_of(
    observer: &Hive,
    doc: DocumentId,
    member: IndividualId,
) -> TestResult<Vec<Arc<SerdeSigned<CgkaOperation>>>> {
    Ok(observer
        .cgka_ops_for_doc(&doc)
        .await
        .ok_or("the observer holds the document")?
        .into_iter()
        .filter(|op| match &op.payload {
            CgkaOperation::Add { added_id, .. } => *added_id == MemberId::from(member),
            _ => false,
        })
        .collect())
}

fn kl(id: impl Into<Identifier>) -> Identifier {
    id.into()
}

fn citation<W>(cert: &VerifiedCertificate<W>) -> CitationId {
    CitationId(cert.id().to_bytes())
}

/// `signer`'s signature on `delegation`, not yet received by anyone.
async fn signed_delegation(
    signer: &Hive,
    delegation: Delegation,
) -> TestResult<VerifiedCertificate<ContentHeads<[u8; 32]>>> {
    Ok(signer.sign_certificate(&delegation).await?.into())
}

/// `signer`'s revocation of a delegation from `subject` to `audience` that
/// `holder` holds, not yet received by anyone.
async fn signed_revocation(
    signer: &Hive,
    holder: &Hive,
    subject: impl Into<Identifier>,
    audience: impl Into<Identifier>,
) -> TestResult<VerifiedCertificate<ContentHeads<[u8; 32]>>> {
    let target = *Keyline::<Sendable>::delegations_to(holder.keyline(), kl(subject), kl(audience))
        .await?
        .value
        .keys()
        .next()
        .ok_or("a delegation to revoke")?;
    let revocation: Revocation<ContentHeads<[u8; 32]>> = Revocation::new(target);
    Ok(signer.sign_certificate(&revocation).await?.into())
}

/// `issuer`'s grant of `power` over `doc` to `audience`, received by `issuer`.
async fn issue_grant(
    issuer: &Hive,
    audience: impl Into<Identifier>,
    doc: DocumentId,
    power: Power,
) -> TestResult<VerifiedCertificate<ContentHeads<[u8; 32]>>> {
    let cert = signed_delegation(issuer, Delegation::new(kl(audience), kl(doc), power)).await?;
    receive(issuer, &cert).await;
    Ok(cert)
}

async fn receive(observer: &Hive, cert: &VerifiedCertificate<ContentHeads<[u8; 32]>>) {
    observer
        .receive_certificate(cert.clone().into_certificate())
        .await
        .expect("a valid certificate is received");
}

fn cites(certs: &[&VerifiedCertificate<ContentHeads<[u8; 32]>>]) -> Vec<CitationId> {
    let mut cited: Vec<CitationId> = certs.iter().map(|c| citation(c)).collect();
    cited.sort_unstable();
    cited.dedup();
    cited
}

/// An add of `added` with key `pk` on `doc`, on top of `observer`'s heads.
async fn add_op(
    observer: &Hive,
    doc: DocumentId,
    added: IndividualId,
    (pk, key_proof): (ShareKey, Option<Vec<u8>>),
    citations: Vec<CitationId>,
) -> CgkaOperation {
    CgkaOperation::Add {
        added_id: MemberId::from(added),
        pk,
        leaf_index: 0,
        invitation: None,
        key_proof,
        predecessors: cgka_heads(observer, doc).await,
        doc_id: TreeId::from(doc),
        citations,
    }
}

/// Everything `from` would send `to`, delivered.
async fn send(from: &Hive, to: &Hive) {
    let events = from
        .static_events_for_agent(to.id())
        .await
        .expect("selects events");
    to.ingest_unsorted_static_events(events.into_values().collect())
        .await;
}

#[tokio::test]
async fn a_reader_no_writer_can_add_adds_itself() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    // Alice grants Bob Read without having any of his prekeys, so no writer
    // can add him.
    issue_grant(&alice, bob.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before")
        .await?;
    assert!(!cgka_members(&alice, doc_id).await.contains(&bob.id()));

    send(&alice, &bob).await;
    assert!(bob.add_self_to(doc_id).await?);
    send(&bob, &alice).await;
    assert!(cgka_members(&alice, doc_id).await.contains(&bob.id()));

    let ct = alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"for bob")
        .await?;
    send(&alice, &bob).await;
    assert_eq!(
        bob.try_decrypt_content(doc_id, ct.encrypted_content())
            .await?,
        b"for bob".to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn a_member_added_under_a_key_it_rotated_away_rotates_before_writing() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    let carol_id = learn(&alice, &carol).await;
    let grant = issue_grant(&alice, carol_id, doc_id, Power::Read).await?;
    // Carol published this prekey and then rotated it away, perhaps because
    // it leaked. Her key proof for it is still valid, so a member can add
    // her under it.
    let (retired, proof) = proven_prekey(&carol).await;
    carol.rotate_prekey(retired).await?;
    let add = add_op(
        &alice,
        doc_id,
        carol_id,
        (retired, Some(proof)),
        cites(&[&grant]),
    )
    .await;
    alice.receive_cgka_op(alice.try_sign(add).await?).await?;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"from alice")
        .await?;
    send(&alice, &carol).await;

    carol
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"from carol")
        .await?;

    let rotated = carol
        .cgka_ops_for_doc(&doc_id)
        .await
        .ok_or("carol holds the document")?
        .iter()
        .any(|op| {
            matches!(op.payload(), CgkaOperation::Update { id, new_path, .. }
                if *id == MemberId::from(carol_id)
                    && !new_path.leaf_pk.contains_key(&retired))
        });
    assert!(rotated, "carol still writes under the key she rotated away");
    Ok(())
}

#[tokio::test]
async fn a_reader_whose_prekeys_arrive_after_a_write_is_added_at_the_next_write() -> TestResult {
    let (alice, _bob, doc_id) = doc_with_alice_and_bob().await?;
    let carol = make_simple_keyhive().await?;
    issue_grant(&alice, carol.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before her prekeys")
        .await?;

    learn(&alice, &carol).await;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after her prekeys")
        .await?;

    assert!(cgka_members(&alice, doc_id).await.contains(&carol.id()));
    Ok(())
}

/// Alice, her document, and Bob, who added himself to it, was removed when
/// Alice revoked his `Read`, and was then granted `Edit`.
async fn removed_and_granted_again() -> TestResult<(Hive, Hive, DocumentId)> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    issue_grant(&alice, bob.id(), doc_id, Power::Read).await?;
    alice
        .try_encrypt_content(doc_id, &[0u8; 32], &vec![], b"before")
        .await?;
    send(&alice, &bob).await;
    assert!(bob.add_self_to(doc_id).await?);
    send(&bob, &alice).await;

    let revocation = signed_revocation(&alice, &alice, doc_id, bob.id()).await?;
    receive(&alice, &revocation).await;
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"revoked")
        .await?;
    issue_grant(&alice, bob.id(), doc_id, Power::Edit).await?;
    send(&alice, &bob).await;
    assert!(!cgka_members(&bob, doc_id).await.contains(&bob.id()));
    Ok((alice, bob, doc_id))
}

#[tokio::test]
async fn a_reader_removed_and_granted_again_can_add_itself_again() -> TestResult {
    let (alice, bob, doc_id) = removed_and_granted_again().await?;
    assert!(bob.add_self_to(doc_id).await?);
    send(&bob, &alice).await;
    let ct = alice
        .try_encrypt_content(doc_id, &[2u8; 32], &vec![], b"for bob again")
        .await?;
    send(&alice, &bob).await;
    assert_eq!(
        bob.try_decrypt_content(doc_id, ct.encrypted_content())
            .await?,
        b"for bob again".to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn a_reader_removed_and_granted_again_adds_itself_when_it_writes() -> TestResult {
    let (_alice, bob, doc_id) = removed_and_granted_again().await?;

    bob.try_encrypt_content(doc_id, &[3u8; 32], &vec![], b"back again")
        .await?;

    assert!(cgka_members(&bob, doc_id).await.contains(&bob.id()));
    Ok(())
}

/// A signer that signs as many payloads as it is allowed, then refuses, as a
/// remote or hardware signer can.
#[derive(Debug, Clone)]
struct RationedSigner {
    inner: MemorySigner,
    allowed: Arc<AtomicUsize>,
}

impl RationedSigner {
    fn new() -> Self {
        RationedSigner {
            inner: MemorySigner::generate(&mut OsRng),
            allowed: Arc::new(AtomicUsize::new(usize::MAX)),
        }
    }

    fn allow(&self, signatures: usize) {
        self.allowed.store(signatures, Ordering::SeqCst);
    }
}

impl Verifiable for RationedSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl AsyncSigner<Sendable> for RationedSigner {
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> <Sendable as FutureForm>::Future<'a, Result<ed25519_dalek::Signature, SigningError>> {
        let allowed = self
            .allowed
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        Sendable::ready(match allowed {
            Ok(_) => self.inner.try_sign_bytes_sync(payload_bytes),
            Err(_) => Err(SigningError::SigningFailed(
                ed25519_dalek::SignatureError::new(),
            )),
        })
    }
}

#[tokio::test]
async fn a_reader_whose_remove_failed_to_sign_is_removed_at_the_next_write() -> TestResult {
    let signer = RationedSigner::new();
    let alice = Keyhive::generate(
        signer.clone(),
        MemoryCiphertextStore::<[u8; 32], Vec<u8>>::new(),
        NoListener,
        KeylineStore::new(),
        OsRng,
    )
    .await?;
    let bob = make_simple_keyhive().await?;
    let bob_id = bob.id();
    alice
        .register_individual(IndividualState::new(KeyOp::Add(
            bob.expand_prekeys().await?,
        )))
        .await;
    let doc_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc_id, Power::Read).await?;

    // The revocation is signed. The remove it calls for is not.
    signer.allow(1);
    alice.revoke_member(bob_id, false, doc_id).await?;
    let members = alice
        .cgka_members_for(doc_id)
        .await?
        .ok_or("alice has not joined the CGKA group")?;
    assert!(members.contains(&bob_id), "the failed remove removed bob");
    let readers = Keyline::<Sendable>::members(alice.keyline(), kl(doc_id))
        .await?
        .value;
    assert!(!readers.into_iter().any(|(id, _)| id == kl(bob_id)));

    signer.allow(usize::MAX);
    alice
        .try_encrypt_content(doc_id, &[1u8; 32], &vec![], b"after the revocation")
        .await?;
    let members = alice
        .cgka_members_for(doc_id)
        .await?
        .ok_or("alice has not joined the CGKA group")?;
    assert!(!members.contains(&bob_id));
    Ok(())
}

#[tokio::test]
async fn an_add_contains_the_prekey_operation_that_published_its_key() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let prekey = bob.expand_prekeys().await?;
    let published = prekey.signed().as_ref().clone();
    let bob = IndividualState::new(KeyOp::Add(prekey));
    let bob_id = bob.id();
    alice.register_individual(bob).await;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    alice.add_member(bob_id, doc, Power::Read).await?;

    let proofs: Vec<_> = adds_of(&alice, doc, bob_id)
        .await?
        .iter()
        .filter_map(|op| match &op.payload {
            CgkaOperation::Add { key_proof, .. } => key_proof.clone(),
            _ => None,
        })
        .map(|proof| Signed::<AddKeyOp>::decode(&proof))
        .collect::<Result<_, _>>()?;
    assert_eq!(proofs, vec![published]);
    Ok(())
}

#[tokio::test]
async fn an_operation_on_a_document_the_replica_cannot_read_is_refused() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    for cert in Keyline::<Sendable>::closure(alice.keyline(), kl(doc))
        .await?
        .value
    {
        carol.receive_certificate(cert).await?;
    }
    let root = alice
        .cgka_ops_for_doc(&doc)
        .await
        .ok_or("alice holds the document")?
        .into_iter()
        .find(|op| op.payload.predecessors().is_empty())
        .ok_or("the CGKA graph has a root")?;

    let received = carol.receive_cgka_op(root.as_ref().clone()).await;
    assert!(
        matches!(received, Err(ReceiveCgkaOpError::UnknownDocument(_))),
        "{received:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_replica_whose_read_was_revoked_adds_no_new_reader() -> TestResult {
    let (alice, bob, doc) = doc_with_alice_and_bob().await?;
    let dave = make_simple_keyhive().await?;
    send(&alice, &bob).await;
    let revocation = signed_revocation(&alice, &alice, doc, bob.id()).await?;
    receive(&alice, &revocation).await;
    send(&alice, &bob).await;
    learn(&alice, &dave).await;
    let dave_id = learn(&bob, &dave).await;
    let grant = issue_grant(&alice, dave_id, doc, Power::Read).await?;
    receive(&bob, &grant).await;

    // Bob removes himself first, which his signing set allows. The write then
    // fails because he is no longer a member.
    let _ = bob
        .try_encrypt_content(doc, &[1u8; 32], &vec![], b"after his revocation")
        .await;

    assert!(adds_of(&bob, doc, dave_id).await?.is_empty());
    Ok(())
}

/// Alice, who granted Carol `Read` on `doc` and wrote since, and a replica of
/// Alice rebuilt from her archive from before the grant, over a Keyline store
/// that holds the grant.
async fn restored_from_before_a_grant() -> TestResult<(Hive, Hive, Hive, DocumentId)> {
    let signer = MemorySigner::generate(&mut OsRng);
    let alice = Keyhive::generate(
        signer.clone(),
        MemoryCiphertextStore::new(),
        NoListener,
        KeylineStore::new(),
        OsRng,
    )
    .await?;
    let carol = make_simple_keyhive().await?;
    let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
    let archive = alice.into_archive().await?;
    issue_grant(&alice, carol.id(), doc, Power::Read).await?;
    learn(&alice, &carol).await;
    alice
        .try_encrypt_content(doc, &[0u8; 32], &vec![], b"for carol")
        .await?;

    let store = KeylineStore::new();
    let certs = Keyline::<Sendable>::closure(alice.keyline(), kl(doc))
        .await?
        .value
        .into_iter()
        .map(|cert| cert.verify())
        .collect::<Result<_, _>>()?;
    Keyline::<Sendable>::insert(&store, certs).await?;
    let restored = Keyhive::try_from_archive(
        &archive,
        signer,
        MemoryCiphertextStore::new(),
        NoListener,
        store,
        Arc::new(futures::lock::Mutex::new(OsRng)),
    )
    .await?;
    Ok((alice, restored, carol, doc))
}

#[tokio::test]
async fn a_rebuilt_replica_merges_an_operation_citing_what_only_its_store_has() -> TestResult {
    let (alice, restored, carol, doc) = restored_from_before_a_grant().await?;
    let add_of_carol = adds_of(&alice, doc, carol.id())
        .await?
        .pop()
        .ok_or("alice added carol")?;

    restored
        .receive_cgka_op(add_of_carol.as_ref().clone())
        .await?;

    assert!(cgka_members(&restored, doc).await.contains(&carol.id()));
    Ok(())
}

#[tokio::test]
async fn a_rebuilt_replica_cites_what_only_its_store_has() -> TestResult {
    let (_alice, restored, carol, doc) = restored_from_before_a_grant().await?;
    learn(&restored, &carol).await;

    restored
        .try_encrypt_content(doc, &[1u8; 32], &vec![], b"for carol")
        .await?;

    assert!(cgka_members(&restored, doc).await.contains(&carol.id()));
    Ok(())
}
