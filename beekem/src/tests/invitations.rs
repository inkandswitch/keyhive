use crate::{
    encrypted::encrypt_secret,
    keys::ShareKeyMap,
    operation::{CgkaChange, CgkaOperation, Invitation, InvitationSecret},
    pcs_key::PcsKey,
    test_utils::{member, Group},
};
use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};
use future_form::Local;
use keyhive_crypto::{share_key::ShareSecretKey, verified::Verified};
use rand::{rngs::StdRng, SeedableRng};

#[tokio::test]
async fn changing_owner_records_an_invitation_addressed_to_the_new_one() {
    let mut rng = StdRng::seed_from_u64(0x5ec0_0001);
    let mut group = Group::new(2, &mut rng).await;

    let op = group.rotate(0, &mut rng).await;
    let op_hash = op.digest();
    let root = group.replicas[0]
        .root_secrets
        .get(&op_hash)
        .expect("the author records the secret its own update produced");

    // Carol is added after the rotation, so her invitation wraps its secret.
    let carol = member(&mut rng);
    group.add(0, carol.id, carol.pk).await;

    // Drop what the inviter derived for itself so the invitation is the only
    // route left to that secret.
    let mut from_alice = group.replicas[0].clone();
    from_alice.root_secrets.clear();
    let mut carol_sks = ShareKeyMap::new();
    carol_sks.insert(carol.pk, carol.sk);

    let carol_view = from_alice.with_new_owner(carol.id, carol_sks).unwrap();
    assert_eq!(
        carol_view.root_secrets.get(&op_hash),
        Some(root),
        "changing ownership should record the invitation secret for the new owner"
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
        .root_secrets
        .get(&op1.digest())
        .expect("the author records the secret its own update produced");
    let op2 = group.rotate(0, &mut rng).await;
    group.broadcast(&op2);
    let op2_hash = op2.digest();
    let root2 = group.replicas[0]
        .root_secrets
        .get(&op2_hash)
        .expect("the author records the secret its own update produced");
    assert_ne!(root1, root2, "the two rotations produce different secrets");

    // An inviter chooses the op hash and the encrypted root secret, which
    // could be selected to be incorrect.
    let inviter_sk = ShareSecretKey::generate(&mut rng);
    let inviter_pk = inviter_sk.share_key();
    let create_add_with_invitation_wrapping = |secret: PcsKey| CgkaOperation {
        doc_id,
        predecessors: BTreeSet::new(),
        change: CgkaChange::Add {
            added_id: bob_id,
            pk: bob_pk,
            leaf_index: 1,
            invitation: Some(Box::new(Invitation {
                inviter_pk,
                ancestor_secrets: vec![InvitationSecret {
                    update_op_hash: op2_hash,
                    encrypted_root_secret: encrypt_secret(doc_id, secret, &inviter_sk, &bob_pk)
                        .unwrap(),
                }],
            })),
            key_proof: None,
            citations: BTreeSet::new(),
        },
    };
    let alice = &alice_signer;
    let sign = |op| async move { Verified::sign::<Local, _>(&op, alice).await.unwrap() };

    // Bob recorded op2's secret from the tree when it arrived, so drop it to
    // leave the invitation as the only thing under test.
    let bob = &mut group.replicas[1];
    bob.root_secrets.remove(&op2_hash);
    assert_eq!(
        bob.root_secrets.get(&op2_hash),
        None,
        "precondition: nothing is recorded for op2"
    );

    bob.record_secrets_from_invitation(&sign(create_add_with_invitation_wrapping(root1)).await);
    assert_eq!(
        bob.root_secrets.get(&op2_hash),
        None,
        "an invitation pairing op2 with a secret it did not produce should be ignored"
    );

    bob.record_secrets_from_invitation(&sign(create_add_with_invitation_wrapping(root2)).await);
    assert_eq!(
        bob.root_secrets.get(&op2_hash),
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
        heads.push(op.digest());
        group.deliver(&op, &[0]);
    }

    // A conflicted root means `record_tree_root_secret` recorded nothing for
    // three of them, so an invitation built only from what is recorded would
    // reach one head out of four.
    let recorded = heads
        .iter()
        .filter(|h| group.replicas[0].root_secrets.get(h).is_some())
        .count();
    assert!(
        recorded < heads.len(),
        "precondition: concurrency should leave some head secrets unrecorded, \
         otherwise the invitation only wraps secrets already recorded"
    );

    let invitee = member(&mut rng);
    let add = group.add(0, invitee.id, invitee.pk).await;
    let CgkaChange::Add { invitation, .. } = &add.payload().change else {
        panic!("an add should be an Add op")
    };
    let wrapped: Vec<_> = invitation
        .as_ref()
        .expect("the adder can reach at least one head secret")
        .ancestor_secrets
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
