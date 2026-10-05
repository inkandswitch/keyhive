use crate::{
    encrypted::encrypt_secret,
    id::MemberId,
    keys::ShareKeyMap,
    operation::{CgkaOperation, Invitation, InvitationSecret},
    pcs_key::PcsKey,
    test_utils::{member, Group, ADD_AUTH},
};
use alloc::{boxed::Box, vec, vec::Vec};
use keyhive_crypto::{digest::Digest, share_key::ShareSecretKey, signer::async_signer};
use rand::{rngs::StdRng, SeedableRng};

#[tokio::test]
async fn changing_owner_records_an_invitation_addressed_to_the_new_one() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0001);
    let mut group = Group::new(2, &mut rng).await;

    let op = group.rotate(0, &mut rng).await;
    let op_hash = Digest::hash(op.as_ref());
    let root = group.replicas[0]
        .root_secret_for(&op_hash)
        .expect("the author records the secret its own update produced");

    // Carol is added after the rotation, so her invitation wraps its secret.
    let carol = member(&mut rng);
    group.add(0, carol.id, carol.pk).await;

    // Drop what the inviter derived for itself so the invitation is the only
    // route left to that secret.
    let mut from_alice = group.replicas[0].clone();
    from_alice.pcs_keys_by_update.clear();
    let mut carol_sks = ShareKeyMap::new();
    carol_sks.insert(carol.pk, carol.sk);

    let carol_view = from_alice.with_new_owner(carol.id, carol_sks).unwrap();
    assert_eq!(
        carol_view.root_secret_for(&op_hash),
        Some(root),
        "changing ownership should record the invitation secret for the new owner"
    );
}

#[tokio::test]
async fn an_invitation_addressed_to_public_is_recorded_by_a_reader_that_is_not_public() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0002);
    let mut group = Group::new(2, &mut rng).await;

    let op = group.rotate(0, &mut rng).await;
    let op_hash = Digest::hash(op.as_ref());
    let root = group.replicas[0]
        .root_secret_for(&op_hash)
        .expect("the author records the secret its own update produced");

    // Public joins after the rotation, so its invitation is the only route to
    // that secret from outside the tree.
    let public = member(&mut rng);
    group.add(0, MemberId::public(), public.pk).await;

    // Drop what the inviter derived for itself so the invitation is the only
    // route left to that secret.
    let mut from_alice = group.replicas[0].clone();
    from_alice.pcs_keys_by_update.clear();
    let mut reader_sks = ShareKeyMap::new();
    reader_sks.insert(public.pk, public.sk);

    // The reader is neither Public nor in the tree, so the invitation is
    // recorded for it only because the add is addressed to Public.
    let reader = member(&mut rng);
    let reader_view = from_alice.with_new_owner(reader.id, reader_sks).unwrap();
    assert_eq!(
        reader_view.root_secret_for(&op_hash),
        Some(root),
        "an invitation addressed to Public should be recorded whoever reads it"
    );
}

#[tokio::test]
async fn an_invitation_cannot_pair_a_secret_with_an_update_that_did_not_produce_it() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0003);
    let mut group = Group::new(2, &mut rng).await;
    let doc_id = group.replicas[0].doc_id;
    let alice_signer = group.members[0].signer.clone();
    let bob_id = group.members[1].id;
    let bob_pk = group.members[1].pk;

    let op1 = group.rotate(0, &mut rng).await;
    group.broadcast(&op1);
    let root1 = group.replicas[0]
        .root_secret_for(&Digest::hash(op1.as_ref()))
        .expect("the author records the secret its own update produced");
    let op2 = group.rotate(0, &mut rng).await;
    group.broadcast(&op2);
    let op2_hash = Digest::hash(op2.as_ref());
    let root2 = group.replicas[0]
        .root_secret_for(&op2_hash)
        .expect("the author records the secret its own update produced");
    assert_ne!(root1, root2, "the two rotations produce different secrets");

    // An inviter chooses the op hash and the encrypted root secret, which
    // could be selected to be incorrect.
    let inviter_sk = ShareSecretKey::generate(&mut rng);
    let inviter_pk = inviter_sk.share_key();
    let create_add_with_invitation_wrapping = |secret: PcsKey| CgkaOperation::Add {
        added_id: bob_id,
        pk: bob_pk,
        leaf_index: 1,
        authorization: ADD_AUTH,
        invitation: Some(Box::new(Invitation {
            inviter_pk,
            head_secrets: vec![InvitationSecret {
                update_op_hash: op2_hash,
                encrypted_root_secret: encrypt_secret(
                    doc_id.as_bytes(),
                    secret.0,
                    &inviter_sk,
                    &bob_pk,
                )
                .unwrap(),
            }],
        })),
        predecessors: Vec::new(),
        doc_id,
    };
    let sign = |op| async {
        async_signer::try_sign_async::<future_form::Local, _, _>(&alice_signer, op)
            .await
            .unwrap()
    };

    // Bob recorded op2's secret from the tree when it arrived, so drop it to
    // leave the invitation as the only thing under test.
    let bob = &mut group.replicas[1];
    bob.pcs_keys_by_update.remove(&op2_hash);
    assert_eq!(
        bob.root_secret_for(&op2_hash),
        None,
        "precondition: nothing is recorded for op2"
    );

    bob.record_secrets_from_invitation(&sign(create_add_with_invitation_wrapping(root1)).await);
    assert_eq!(
        bob.root_secret_for(&op2_hash),
        None,
        "an invitation pairing op2 with a secret it did not produce should be ignored"
    );

    bob.record_secrets_from_invitation(&sign(create_add_with_invitation_wrapping(root2)).await);
    assert_eq!(
        bob.root_secret_for(&op2_hash),
        Some(root2),
        "an invitation pairing op2 with the secret it did produce should be used"
    );
}

#[tokio::test]
async fn an_invitation_wraps_every_concurrent_update_head() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0004);
    let mut group = Group::new(5, &mut rng).await;

    // Four members rotate without seeing each other, so Alice ends up with four
    // concurrent update heads and a conflicted root.
    let mut heads = Vec::new();
    for author in 1..=4 {
        let op = group.rotate(author, &mut rng).await;
        heads.push(Digest::hash(op.as_ref()));
        group.deliver(&op, &[0]);
    }

    // A conflicted root means `record_tree_root_secret` recorded nothing for
    // three of them, so an invitation built only from what is recorded would
    // reach one head out of four.
    let recorded = heads
        .iter()
        .filter(|h| group.replicas[0].root_secret_for(h).is_some())
        .count();
    assert!(
        recorded < heads.len(),
        "precondition: concurrency should leave some head secrets unrecorded, \
         otherwise this test is not exercising the rebuild"
    );

    let invitee = member(&mut rng);
    let add = group.add(0, invitee.id, invitee.pk).await;
    let CgkaOperation::Add { invitation, .. } = &add.payload else {
        panic!("an add should be an Add op")
    };
    let wrapped: Vec<_> = invitation
        .as_ref()
        .expect("the adder can reach at least one head secret")
        .head_secrets
        .iter()
        .map(|secret| secret.update_op_hash)
        .collect();

    for head in &heads {
        assert!(
            wrapped.contains(head),
            "an invitation should wrap every concurrent update head, since each \
             one may have content written under it"
        );
    }
}
