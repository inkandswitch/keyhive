//! The update predecessor secret chain.

use crate::{
    cgka::Cgka,
    collections::Set,
    keys::ShareKeyMap,
    operation::{CgkaOperation, PredecessorSecret},
    pcs_key::PcsKey,
    test_utils::{assert_chain_bookkeeping, member, Group, Member},
    transact::{Fork, Merge},
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

/// `member`'s [`Cgka`] built by applying every operation in `source`.
fn view_of(source: &Cgka, member: &Member) -> Cgka {
    let mut sks = ShareKeyMap::new();
    sks.insert(member.pk, member.sk);
    let mut view = Cgka::new(source.doc_id, member.id, sks);
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

/// Alice rotates and adds Carol while Bob rotates, and Alice receives Bob's
/// update. Carol, who cannot derive Bob's secret, then updates from Alice's
/// history. Returns the group, Alice's and Bob's update hashes, and Carol's
/// update, which nobody has applied yet.
async fn carol_updates_without_bobs_secret(
    rng: &mut StdRng,
) -> (
    Group,
    Digest<Signed<CgkaOperation>>,
    Digest<Signed<CgkaOperation>>,
    Signed<CgkaOperation>,
) {
    let mut group = Group::new(2, rng).await;
    let alice_op1_hash = Digest::hash(group.rotate(0, rng).await.as_ref());
    let carol = member(rng);
    group.add(0, carol.id, carol.pk).await;
    let bob_op = group.rotate(1, rng).await;
    group.deliver(&bob_op, &[0]);

    let mut carol_cgka = view_of(&group.replicas[0], &carol);
    let (_, carol_op) = rotate(&mut carol_cgka, &carol.signer, rng).await;
    (
        group,
        alice_op1_hash,
        Digest::hash(bob_op.as_ref()),
        carol_op,
    )
}

#[tokio::test]
async fn an_update_chains_an_ancestor_an_earlier_update_could_not() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0001);
    let (mut group, alice_op1_hash, bob_op_hash, carol_op) =
        carol_updates_without_bobs_secret(&mut rng).await;
    let alice_signer = group.members[0].signer.clone();
    let carol_op_hash = Digest::hash(&carol_op);
    assert!(
        added_to_chain(&carol_op, &alice_op1_hash),
        "Carol should add the ancestor secret her invitation wraps to the chain"
    );

    let alice = &mut group.replicas[0];
    alice
        .merge_concurrent_operation(Arc::new(carol_op))
        .unwrap();
    assert!(
        !alice.unchained_updates.contains(&alice_op1_hash),
        "an entry we did not author should be chained once it decrypts to the real secret"
    );
    assert!(
        alice.unchained_updates.contains(&bob_op_hash),
        "an update nothing added to the chain should still be reported as unchained"
    );
    assert_eq!(
        alice
            .ops_graph
            .nearest_update_ancestors(&alice.ops_graph.cgka_op_heads),
        Set::from_iter([carol_op_hash]),
        "precondition: Carol's update should cover Bob's, leaving the unchained record as the \
         only route to it"
    );

    let (_, alice_op2) = rotate(alice, &alice_signer, &mut rng).await;
    assert!(
        added_to_chain(&alice_op2, &bob_op_hash),
        "a member that can derive an unchained ancestor secret should add it to the chain"
    );
    assert!(
        !alice.unchained_updates.contains(&bob_op_hash),
        "an update in the chain should no longer be reported as unchained"
    );
}

#[tokio::test]
async fn the_traversal_ignores_an_entry_whose_secret_is_not_its_updates() {
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
    let (root2, op2) = rotate(alice, &alice_signer, &mut rng).await;
    let op2_hash = Digest::hash(&op2);
    let (root3, op3) = rotate(alice, &alice_signer, &mut rng).await;
    let op3_hash = Digest::hash(&op3);

    // Rebuild the third update with only an entry that wraps root2 labelled
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
            if Digest::hash(&**op) == op3_hash {
                continue;
            }
            bob.apply_operation_and_record_root_secret(op.clone())
                .unwrap();
        }
    }
    bob.apply_operation_and_record_root_secret(Arc::new(tampered_op))
        .unwrap();

    // With only the third update's secret recorded, the forged entry is the
    // traversal's only route to op1.
    bob.root_secrets.remove(&op1_hash);
    bob.root_secrets.remove(&op2_hash);
    assert_eq!(
        bob.root_secret_from_chain(&op1_hash),
        None,
        "the traversal took a secret for op1 from an entry whose secret op1 did not produce"
    );
    assert!(
        bob.root_secrets.get(&op1_hash).is_none(),
        "the forged secret should not be recorded for op1"
    );
}

#[tokio::test]
async fn a_forged_entry_does_not_chain_the_update_it_refers_to() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0004);
    let mut group = Group::new(3, &mut rng).await;

    // Everyone sees Bob's update, so Mallory's follows it and Alice can derive
    // Mallory's root secret when it arrives.
    let target = group.rotate(1, &mut rng).await;
    let target_hash = Digest::hash(target.as_ref());
    group.broadcast(&target);

    // Mallory has her own update's root secret, so she can encrypt anything at
    // all under the key its entries are read with. The entry is correctly
    // signed, and anyone could sign one like it about any update.
    let genuine = group.rotate(2, &mut rng).await;
    let mallory_secret = group.replicas[2]
        .root_secrets
        .get(&Digest::hash(genuine.as_ref()))
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
    let forged_hash = Digest::hash(&forged);
    group.replicas[0]
        .merge_concurrent_operation(Arc::new(forged))
        .unwrap();
    assert!(
        group.replicas[0].root_secrets.get(&forged_hash).is_some(),
        "precondition: Alice records the forged update's secret, so she reads its entries"
    );

    assert!(
        group.replicas[0].unchained_updates.contains(&target_hash),
        "an entry that does not contain the root secret of the update it refers to \
         should not chain it"
    );
}

#[tokio::test]
async fn an_invitation_leaves_out_an_update_already_in_the_chain() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0005);
    let mut group = Group::new(2, &mut rng).await;
    group.rotate(0, &mut rng).await;
    let op2_hash = Digest::hash(group.rotate(0, &mut rng).await.as_ref());

    let invitee = member(&mut rng);
    let add = group.add(0, invitee.id, invitee.pk).await;
    let CgkaOperation::Add { invitation, .. } = &add.payload else {
        panic!("an add should be an Add op")
    };
    let wrapped: Vec<_> = invitation
        .as_ref()
        .expect("the adder can derive the head secret")
        .ancestor_secrets
        .iter()
        .map(|secret| secret.update_op_hash)
        .collect();
    assert_eq!(
        wrapped,
        vec![op2_hash],
        "the second update put the first in the chain, so the invitation wraps only the second"
    );
}

/// Carol, added after three updates by the only other member. Returns her, her
/// [`Cgka`], and each update with the secret it produced.
async fn carol_added_after_three_updates(
    rng: &mut StdRng,
) -> (Member, Cgka, Vec<(Digest<Signed<CgkaOperation>>, PcsKey)>) {
    let mut group = Group::new(1, rng).await;
    let mut updates = Vec::new();
    for _ in 0..3 {
        let op_hash = Digest::hash(group.rotate(0, rng).await.as_ref());
        let secret = group.replicas[0]
            .root_secrets
            .get(&op_hash)
            .expect("the author records the secret its own update produced");
        updates.push((op_hash, secret));
    }
    let carol = member(rng);
    group.add(0, carol.id, carol.pk).await;
    let carol_cgka = view_of(&group.replicas[0], &carol);
    (carol, carol_cgka, updates)
}

#[tokio::test]
async fn the_traversal_records_each_secret_it_derives() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0007);
    let (_, mut carol_cgka, updates) = carol_added_after_three_updates(&mut rng).await;
    assert_eq!(
        carol_cgka.root_secret_from_chain(&updates[0].0),
        Some(updates[0].1),
        "precondition: Carol reads back to the oldest update"
    );

    for (op_hash, secret) in updates {
        assert_eq!(
            carol_cgka.root_secrets.get(&op_hash),
            Some(secret),
            "every secret on the way back to the oldest update should be recorded for its update"
        );
    }
}

#[tokio::test]
async fn a_merge_reports_the_unchained_updates_of_the_merged_history() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0008);
    let (mut group, _, _, carol_op) = carol_updates_without_bobs_secret(&mut rng).await;
    group.replicas[0]
        .merge_concurrent_operation(Arc::new(carol_op))
        .unwrap();
    let alice = group.replicas[0].fork();

    // Only the merge tells Bob that Carol's update made his chainable.
    let bob = &mut group.replicas[1];
    bob.merge(alice);

    assert_chain_bookkeeping(bob, "after the merge");
}

#[tokio::test]
async fn a_merge_keeps_what_either_side_chained() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0009);
    let (mut group, _, bob_op_hash, carol_op) = carol_updates_without_bobs_secret(&mut rng).await;
    let alice_signer = group.members[0].signer.clone();
    let alice = &mut group.replicas[0];
    alice
        .merge_concurrent_operation(Arc::new(carol_op))
        .unwrap();
    let behind = alice.fork();

    // The second rotation keeps the update that chains Bob's from being the
    // head a replay records.
    rotate(alice, &alice_signer, &mut rng).await;
    rotate(alice, &alice_signer, &mut rng).await;
    assert!(
        behind.unchained_updates.contains(&bob_op_hash)
            && !alice.unchained_updates.contains(&bob_op_hash),
        "precondition: only Alice has chained Bob's update"
    );

    let mut caught_up = behind.fork();
    caught_up.merge(alice.fork());
    assert_chain_bookkeeping(&caught_up, "after merging in an update that chains ours");

    let mut alice_merged = alice.fork();
    alice_merged.merge(behind);
    assert_chain_bookkeeping(&alice_merged, "after merging in our own update unchained");
}

#[tokio::test]
async fn a_new_members_first_update_wraps_only_what_is_not_in_the_chain() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_000a);
    let (carol, mut carol_cgka, updates) = carol_added_after_three_updates(&mut rng).await;

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

/// A single member's replica after two updates, which has lost the second's
/// secret, so the first is unchained again. Returns the group and both updates'
/// hashes. The second update is the head.
async fn missing_the_second_secret(
    rng: &mut StdRng,
) -> (
    Group,
    Digest<Signed<CgkaOperation>>,
    Digest<Signed<CgkaOperation>>,
) {
    let mut group = Group::new(1, rng).await;
    let first = Digest::hash(group.rotate(0, rng).await.as_ref());
    let second = Digest::hash(group.rotate(0, rng).await.as_ref());
    let cgka = &mut group.replicas[0];
    cgka.root_secrets.remove(&second);
    cgka.unchained_updates.insert(first);
    assert_chain_bookkeeping(cgka, "precondition: only the second update wraps the first");
    (group, first, second)
}

#[tokio::test]
async fn a_rebuilt_secret_chains_the_updates_its_entries_contain() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_000b);
    let (mut group, _, second) = missing_the_second_secret(&mut rng).await;
    let cgka = &mut group.replicas[0];

    cgka.rebuild_root_secret(&second)
        .expect("the author's own update can be rebuilt");

    assert_chain_bookkeeping(cgka, "after rebuilding the second update's secret");
}

#[tokio::test]
async fn a_replayed_secret_chains_the_updates_its_entries_contain() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_000c);
    let (mut group, first, _) = missing_the_second_secret(&mut rng).await;
    let cgka = &mut group.replicas[0];
    let fork = cgka.fork();

    cgka.merge(fork);

    assert!(
        !cgka.unchained_updates.contains(&first),
        "the replay recorded the head, whose entries chain the first"
    );
    assert_chain_bookkeeping(cgka, "after the replay");
}
