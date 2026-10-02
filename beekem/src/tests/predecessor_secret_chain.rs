//! The update predecessor secret chain.

use crate::{
    cgka::Cgka,
    collections::Set,
    encrypted::EncryptedContent,
    id::MemberId,
    keys::ShareKeyMap,
    operation::{CgkaOperation, PredecessorSecret},
    pcs_key::PcsKey,
    test_utils::{member, Group, Member},
};
use alloc::{sync::Arc, vec, vec::Vec};
use keyhive_crypto::{
    digest::Digest,
    share_key::ShareSecretKey,
    signed::Signed,
    signer::{
        async_signer::{self, AsyncSigner},
        memory::MemorySigner,
    },
    siv::Siv,
};
use rand::{rngs::StdRng, SeedableRng};

async fn rotate<S: AsyncSigner<future_form::Local>, R: rand::CryptoRng + rand::RngCore>(
    cgka: &mut Cgka,
    signer: &S,
    csprng: &mut R,
) -> (PcsKey, Signed<CgkaOperation>) {
    let sk = ShareSecretKey::generate(csprng);
    let (pcs_key, op, _) = cgka
        .update::<future_form::Local, _, _>(sk.share_key(), sk, signer, csprng)
        .await
        .unwrap();
    (pcs_key, op)
}

fn predecessor_secrets(op: &Signed<CgkaOperation>) -> &[PredecessorSecret] {
    let CgkaOperation::Update {
        predecessor_secrets,
        ..
    } = &op.payload
    else {
        panic!("an update should be an Update op")
    };
    predecessor_secrets
}

fn added_to_chain(op: &Signed<CgkaOperation>, hash: &Digest<Signed<CgkaOperation>>) -> bool {
    predecessor_secrets(op)
        .iter()
        .any(|s| s.update_op_hash == *hash)
}

/// A new member's [`Cgka`] built by applying every operation in `source`.
fn view_of(source: &Cgka, id: MemberId, sks: ShareKeyMap) -> Cgka {
    let mut view = Cgka::new(source.doc_id, id, sks);
    view.apply_batches(&source.ops().unwrap()).unwrap();
    view
}

/// Re-sign `op` with its predecessor secrets replaced by `entries`.
async fn with_entries(
    signer: &MemorySigner,
    op: &Signed<CgkaOperation>,
    entries: Vec<PredecessorSecret>,
) -> Signed<CgkaOperation> {
    let CgkaOperation::Update {
        id,
        ref new_path,
        ref predecessors,
        ..
    } = op.payload
    else {
        panic!("an update should be an Update op")
    };
    let rebuilt = CgkaOperation::Update {
        id,
        new_path: new_path.clone(),
        predecessor_secrets: entries,
        predecessors: predecessors.clone(),
        doc_id: *op.payload.doc_id(),
    };
    async_signer::try_sign_async::<future_form::Local, _, _>(signer, rebuilt)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_update_chains_an_ancestor_an_earlier_update_could_not() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0001);
    let mut group = Group::new(2, &mut rng).await;
    let alice_signer = group.members[0].signer.clone();

    // Concurrently, Alice rotates and adds Carol while Bob rotates.
    let alice_op1 = group.rotate(0, &mut rng).await;
    let alice_op1_hash = Digest::hash(alice_op1.as_ref());
    let carol = member(&mut rng);
    group.add(0, carol.id, carol.pk).await;
    let bob_op = group.rotate(1, &mut rng).await;
    let bob_op_hash = Digest::hash(bob_op.as_ref());
    group.deliver(&bob_op, &[0]);

    // Carol builds her view from the merged history and updates first.
    let mut carol_sks = ShareKeyMap::new();
    carol_sks.insert(carol.pk, carol.sk);
    let mut carol_cgka = view_of(&group.replicas[0], carol.id, carol_sks);
    let (_, carol_op) = rotate(&mut carol_cgka, &carol.signer, &mut rng).await;
    let carol_op_hash = Digest::hash(&carol_op);
    assert!(
        added_to_chain(&carol_op, &alice_op1_hash),
        "Carol should add the ancestor secret her invitation wraps to the chain"
    );
    assert!(
        !added_to_chain(&carol_op, &bob_op_hash),
        "Carol should not add a secret she cannot derive to the chain"
    );

    let alice = &mut group.replicas[0];
    alice
        .merge_concurrent_operation(Arc::new(carol_op))
        .unwrap();
    assert!(
        alice.ops_graph.chainable_updates.contains(&alice_op1_hash),
        "Carol's update was in a position to chain Alice's, so Alice's is chainable"
    );
    assert!(
        !alice.is_unchained(&alice_op1_hash),
        "an entry we did not author should be chained once it decrypts to the real secret"
    );
    assert!(
        alice.is_unchained(&bob_op_hash),
        "an update nothing added to the chain should still be reported as unchained"
    );
    assert_eq!(
        alice
            .ops_graph
            .nearest_update_ancestors(&alice.ops_graph.cgka_op_heads),
        Set::from_iter([carol_op_hash]),
        "Carol's update should cover Bob's, leaving the unchained record as the only route to it"
    );

    let (_, alice_op2) = rotate(alice, &alice_signer, &mut rng).await;
    assert!(
        added_to_chain(&alice_op2, &bob_op_hash),
        "a member that can derive an unchained ancestor secret should add it to the chain"
    );
    assert!(
        !alice.is_unchained(&bob_op_hash),
        "an update in the chain should no longer be reported as unchained"
    );
}

#[tokio::test]
async fn the_traversal_finds_a_secret_by_its_digest_whatever_its_label() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0002);
    let mut group = Group::new(2, &mut rng).await;
    let doc_id = group.replicas[0].doc_id;
    let alice_signer = group.members[0].signer.clone();
    let bob_id = group.members[1].id;
    let bob_pk = group.members[1].pk;
    let bob_sk = group.members[1].sk;
    let alice = &mut group.replicas[0];

    let (_, op1) = rotate(alice, &alice_signer, &mut rng).await;
    let op1_hash = Digest::hash(&op1);
    let (root2, _) = rotate(alice, &alice_signer, &mut rng).await;
    let (root3, op3) = rotate(alice, &alice_signer, &mut rng).await;

    // Rebuild the third update so its only entry wraps root2 labelled
    // with op1, an update that did not produce it.
    let entry = PredecessorSecret {
        update_op_hash: op1_hash,
        encrypted_root_secret: root3
            .derive_predecessor_secrets_key()
            .try_seal(root2.0.as_slice(), doc_id.as_bytes())
            .unwrap(),
    };
    let tampered_op = with_entries(&alice_signer, &op3, vec![entry]).await;

    let mut bob_sks = ShareKeyMap::new();
    bob_sks.insert(bob_pk, bob_sk);
    let mut bob = Cgka::new(doc_id, bob_id, bob_sks);
    for epoch in alice.ops().unwrap() {
        for op in epoch.iter() {
            if Digest::hash(&**op) == Digest::hash(&op3) {
                continue;
            }
            bob.apply_operation_and_record_root_secret(op.clone())
                .unwrap();
        }
    }
    bob.apply_operation_and_record_root_secret(Arc::new(tampered_op))
        .unwrap();

    assert_eq!(
        bob.pcs_key_from_predecessor_secrets(&Digest::hash(&root2)),
        Some(root2),
        "the traversal matches a secret by its digest, whatever update the entry refers to"
    );
}

#[tokio::test]
async fn a_secret_is_recorded_only_for_the_update_that_produced_it() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0003);
    let mut group = Group::new(2, &mut rng).await;
    let doc_id = group.replicas[0].doc_id;

    // Alice rotates once. Bob is in the tree for it, and receives it.
    let op1 = group.rotate(0, &mut rng).await;
    group.broadcast(&op1);
    let op1_hash = Digest::hash(op1.as_ref());
    let root1 = group.replicas[0]
        .root_secret_for(&op1_hash)
        .expect("the author records the secret its own update produced");
    let alice_signer = group.members[0].signer.clone();
    let bob_signer = group.members[1].signer.clone();
    let (alice, bob) = group.replicas.split_at_mut(1);
    let alice = &mut alice[0];
    let bob = &mut bob[0];

    let encrypt_pcs_key = |pcs_key: PcsKey, op_hash| -> EncryptedContent<Vec<u8>, [u8; 32]> {
        EncryptedContent::new(
            Siv::new(&pcs_key.into(), b"content", doc_id.as_bytes()),
            vec![0u8; 4],
            Digest::hash(&pcs_key),
            op_hash,
            [0u8; 32],
            Digest::hash(&Vec::<[u8; 32]>::new()),
        )
    };

    // Bob reads content written under the first rotation.
    bob.decryption_key_for(&encrypt_pcs_key(root1, op1_hash))
        .unwrap();

    // Alice rotates again. Bob applies it without deriving its root secret,
    // which is the ordinary state for an update authored by someone else.
    let sk2 = ShareSecretKey::generate(&mut rng);
    let (root2, op2, _) = alice
        .update::<future_form::Local, _, _>(sk2.share_key(), sk2, &alice_signer, &mut rng)
        .await
        .unwrap();
    let op2_hash = Digest::hash(&op2);
    bob.apply_batches(&alice.ops().unwrap()).unwrap();

    // A peer sends content pairing the first rotation's secret with the second
    // rotation's operation. Both values are ones any peer legitimately has. What
    // matters is what Bob records, not whether this content decrypts.
    let _ = bob.decryption_key_for(&encrypt_pcs_key(root1, op2_hash));

    assert_ne!(
        bob.root_secret_for(&op2_hash),
        Some(root1),
        "the incorrect pairing should not lead to an incorrect answer"
    );

    let sk3 = ShareSecretKey::generate(&mut rng);
    let (root3, op3, _) = bob
        .update::<future_form::Local, _, _>(sk3.share_key(), sk3, &bob_signer, &mut rng)
        .await
        .unwrap();
    let CgkaOperation::Update {
        ref predecessor_secrets,
        ..
    } = op3.payload
    else {
        panic!("an update should be an Update op")
    };
    let key = root3.derive_predecessor_secrets_key();
    assert!(
        predecessor_secrets
            .iter()
            .any(|chained| Cgka::decrypt_predecessor_secret(&key, chained) == Some(root2)),
        "Bob's update should encrypt the secret op2 really produced, or nothing \
         downstream will be able to reach it by the predecessor key chain again"
    );
}

#[tokio::test]
async fn a_forged_entry_does_not_chain_the_update_it_refers_to() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0004);
    let mut group = Group::new(3, &mut rng).await;

    // Everyone sees Bob's update, so Mallory's follows it and Alice can derive
    // Mallory's root secret when it arrives. Delivering it concurrently instead
    // would leave that secret unrecorded, and then nothing would read the
    // entries at all.
    let target = group.rotate(1, &mut rng).await;
    let target_hash = Digest::hash(target.as_ref());
    group.broadcast(&target);

    // Mallory has her own update's root secret, so she can encrypt anything at
    // all under the key its entries are read with. The entry is correctly
    // signed, and anyone could sign one like it about any update.
    let genuine = group.rotate(2, &mut rng).await;
    let mallory_secret = group.replicas[2]
        .root_secret_for(&Digest::hash(genuine.as_ref()))
        .expect("the author records the secret its own update produced");
    let doc_id = group.replicas[0].doc_id;
    let forged = with_entries(
        &group.members[2].signer,
        &genuine,
        vec![PredecessorSecret {
            update_op_hash: target_hash,
            encrypted_root_secret: mallory_secret
                .derive_predecessor_secrets_key()
                .try_seal(&[0u8; 32], doc_id.as_bytes())
                .expect("sealing 32 bytes should succeed"),
        }],
    )
    .await;
    group.replicas[0]
        .merge_concurrent_operation(Arc::new(forged))
        .unwrap();

    assert!(
        !group.replicas[0].chained_updates.contains(&target_hash),
        "an entry that does not contain the root secret of the update it refers to \
         should not chain it"
    );
}

#[tokio::test]
async fn an_invitation_leaves_out_an_update_already_in_the_chain() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0005);
    let mut group = Group::new(2, &mut rng).await;
    let op1 = group.rotate(0, &mut rng).await;
    let op1_hash = Digest::hash(op1.as_ref());
    group.rotate(0, &mut rng).await;

    let invitee = member(&mut rng);
    let add = group.add(0, invitee.id, invitee.pk).await;
    let CgkaOperation::Add { invitation, .. } = &add.payload else {
        panic!("an add should be an Add op")
    };
    assert!(
        !invitation
            .as_ref()
            .expect("the adder can derive the head secret")
            .head_secrets
            .iter()
            .any(|secret| secret.update_op_hash == op1_hash),
        "the second update put op1 in the chain, so the invitation should not wrap it again"
    );
}

/// Carol, added after three updates, reads back to the oldest through the chain.
/// Returns her, her [`Cgka`], and each update with the secret it produced.
async fn carol_after_reading_back(
    rng: &mut StdRng,
) -> (Member, Cgka, Vec<(Digest<Signed<CgkaOperation>>, PcsKey)>) {
    let mut group = Group::new(1, rng).await;
    let mut updates = Vec::new();
    for _ in 0..3 {
        let op_hash = Digest::hash(group.rotate(0, rng).await.as_ref());
        let secret = group.replicas[0]
            .root_secret_for(&op_hash)
            .expect("the author records the secret its own update produced");
        updates.push((op_hash, secret));
    }

    let carol = member(rng);
    group.add(0, carol.id, carol.pk).await;
    let mut carol_sks = ShareKeyMap::new();
    carol_sks.insert(carol.pk, carol.sk);
    let mut carol_cgka = view_of(&group.replicas[0], carol.id, carol_sks);
    let oldest = updates[0].1;
    assert_eq!(
        carol_cgka.pcs_key_from_predecessor_secrets(&Digest::hash(&oldest)),
        Some(oldest),
        "precondition: Carol reads back to the oldest update"
    );
    (carol, carol_cgka, updates)
}

#[tokio::test]
async fn history_read_through_the_chain_is_not_wrapped_again() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0006);
    let (carol, mut carol_cgka, updates) = carol_after_reading_back(&mut rng).await;

    let (_, op) = rotate(&mut carol_cgka, &carol.signer, &mut rng).await;
    let wrapped: Vec<_> = predecessor_secrets(&op)
        .iter()
        .map(|entry| entry.update_op_hash)
        .collect();
    assert_eq!(
        wrapped,
        vec![updates[2].0],
        "the earlier updates are already in the chain, so only the nearest one is wrapped"
    );
}

#[tokio::test]
async fn the_traversal_records_each_secret_it_derives() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0007);
    let (_, carol_cgka, updates) = carol_after_reading_back(&mut rng).await;

    for (op_hash, secret) in updates {
        assert_eq!(
            carol_cgka.root_secret_for(&op_hash),
            Some(secret),
            "every secret on the way back to the oldest update should be recorded for its update"
        );
    }
}
