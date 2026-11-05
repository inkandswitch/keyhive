//! A reader added to a group is seated in the key tree of a document the granter never saw,
//! by a node that holds that tree.

use beekem::operation::{CgkaAuthorization, CgkaOperation};
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    principal::{
        document::id::DocumentId,
        group::id::GroupId,
        individual::{id::IndividualId, op::KeyOp, Individual},
    },
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::signed::Signed;
use nonempty::nonempty;
use std::sync::Arc;
use testresult::TestResult;

type Kh = keyhive_core::test_utils::Hive;

/// Introduce `who` to `observer`, so `observer` can add `who` to a group.
async fn introduce(observer: &Kh, who: &Kh) -> TestResult<IndividualId> {
    let prekey = who.expand_prekeys().await?;
    let indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(prekey))));
    let id = { indie.lock().await.id() };
    observer.register_individual(indie).await;
    Ok(id)
}

/// Deliver everything `from` holds that `to` is entitled to, asserting `to` applies all of it.
async fn sync_to(from: &Kh, to: &Kh) {
    let events = from.static_events_for_agent(to.id()).await;
    let stuck = to
        .ingest_unsorted_static_events(events.into_values().collect())
        .await;
    assert!(
        stuck.is_empty(),
        "{} events could not be applied",
        stuck.len()
    );
}

async fn seated(observer: &Kh, doc_id: DocumentId) -> Vec<IndividualId> {
    observer
        .cgka_members_for(doc_id)
        .await
        .expect("knows the document")
        .expect("an initialized tree")
        .into_iter()
        .collect()
}

/// Whether `reader` can read what `writer` encrypts into `doc_id` next.
async fn reads_next_write(
    writer: &Kh,
    reader: &Kh,
    doc_id: DocumentId,
    tag: u8,
) -> TestResult<bool> {
    let content = vec![tag; 16];
    let hash: [u8; 32] = *blake3::hash(&content).as_bytes();
    let encrypted = writer
        .try_encrypt_content(doc_id, &hash, &vec![], &content)
        .await?;
    sync_to(writer, reader).await;
    Ok(reader
        .try_decrypt_content(doc_id, encrypted.encrypted_content())
        .await
        .is_ok_and(|plain| plain == content))
}

struct Drawer {
    alice: Kh,
    bob: Kh,
    dave: Kh,
    group_id: GroupId,
    doc_id: DocumentId,
    dave_id: IndividualId,
}

/// Bob writes a note into Alice's group while Alice is away, then Alice, who never saw the
/// note, adds Dave to the group. Every other node in `others` is a reader of the group that
/// took the note before Dave was added.
async fn note_alice_never_saw(others: &[&Kh]) -> TestResult<Drawer> {
    let alice = make_simple_keyhive().await?;
    let bob = make_simple_keyhive().await?;
    let dave = make_simple_keyhive().await?;

    let group_id = alice.generate_group(vec![]).await?;
    let bob_id = introduce(&alice, &bob).await?;
    alice
        .add_member(bob_id, group_id, Access::Edit, &[])
        .await?;
    for other in others {
        let id = introduce(&alice, other).await?;
        alice.add_member(id, group_id, Access::Read, &[]).await?;
    }
    sync_to(&alice, &bob).await;

    let doc_id = bob
        .generate_doc(vec![group_id.into()], nonempty![[1u8; 32]])
        .await?;
    for other in others {
        sync_to(&bob, other).await;
    }

    let dave_id = introduce(&alice, &dave).await?;
    let update = alice
        .add_member(dave_id, group_id, Access::Read, &[])
        .await?;
    assert!(
        alice.get_document(doc_id).await.is_none(),
        "alice must never have seen the note, or the defect cannot arise"
    );
    assert!(
        update.cgka_ops.is_empty(),
        "the granter holds no document to seat dave in"
    );
    sync_to(&alice, &bob).await;
    for other in others {
        sync_to(&alice, other).await;
    }
    assert!(
        !seated(&bob, doc_id).await.contains(&dave_id),
        "receiving the grant seats nobody"
    );

    Ok(Drawer {
        alice,
        bob,
        dave,
        group_id,
        doc_id,
        dave_id,
    })
}

fn adds_of(ops: &[Signed<CgkaOperation>], who: IndividualId) -> usize {
    ops.iter()
        .filter(|op| {
            matches!(op.payload(), CgkaOperation::Add { added_id, .. }
                if IndividualId::from(*added_id) == who)
        })
        .count()
}

#[tokio::test]
async fn a_holder_seats_a_reader_the_granter_could_not() -> TestResult {
    let Drawer {
        alice,
        bob,
        dave,
        group_id,
        doc_id,
        dave_id,
    } = note_alice_never_saw(&[]).await?;

    let ops = bob.reconcile_doc_readers(doc_id).await?;

    assert_eq!(ops.len(), 1, "exactly dave's add: {ops:?}");
    assert_eq!(adds_of(&ops, dave_id), 1);
    let cited = alice
        .get_group(group_id)
        .await
        .expect("alice holds her group")
        .lock()
        .await
        .get_capability(&dave_id.into())
        .expect("dave has a delegation")
        .digest();
    let cited = CgkaAuthorization::Delegation(cited.into());
    assert!(
        matches!(ops[0].payload(), CgkaOperation::Add { authorization, .. } if *authorization == cited),
        "bob cites alice's delegation to dave"
    );
    assert!(seated(&bob, doc_id).await.contains(&dave_id));
    assert!(
        bob.reconcile_doc_readers(doc_id).await?.is_empty(),
        "a seated reader is not added again"
    );

    assert!(
        reads_next_write(&bob, &dave, doc_id, 2).await?,
        "dave reads the note"
    );
    Ok(())
}

#[tokio::test]
async fn two_holders_seating_the_same_reader_concurrently_seat_it_once() -> TestResult {
    let carol = make_simple_keyhive().await?;
    let Drawer {
        bob,
        dave,
        doc_id,
        dave_id,
        ..
    } = note_alice_never_saw(&[&carol]).await?;

    let bobs = bob.reconcile_doc_readers(doc_id).await?;
    let carols = carol.reconcile_doc_readers(doc_id).await?;
    assert_eq!(adds_of(&bobs, dave_id), 1);
    assert_eq!(adds_of(&carols, dave_id), 1);

    sync_to(&bob, &carol).await;
    sync_to(&carol, &bob).await;
    for holder in [&bob, &carol] {
        let seated = seated(holder, doc_id).await;
        assert_eq!(
            seated.iter().filter(|id| **id == dave_id).count(),
            1,
            "dave holds one leaf: {seated:?}"
        );
    }

    assert!(reads_next_write(&bob, &dave, doc_id, 4).await?);
    sync_to(&carol, &dave).await;
    assert!(reads_next_write(&carol, &dave, doc_id, 5).await?);
    Ok(())
}
