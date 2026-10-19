//! Path secrets contained in an update operation.

use crate::{
    encrypted::encrypt_secret, error::CgkaError, keys::ShareKeyMap, operation::CgkaOperation,
    test_utils::Group,
};
use alloc::{sync::Arc, vec};
use future_form::Local;
use keyhive_crypto::{share_key::ShareSecretKey, signed::Signed, signer::async_signer};
use rand::{rngs::StdRng, SeedableRng};

/// An update by `author` whose every path node is encrypted to its
/// recipients as a random secret that is not that node's correct
/// secret for this rotation, signed by `author`.
async fn forged_update(
    group: &mut Group,
    author: usize,
    rng: &mut StdRng,
) -> Arc<Signed<CgkaOperation>> {
    // Made on a copy, so the author's own replica receives it like everyone
    // else's.
    let mut copy = group.replicas[author].clone();
    let sk = ShareSecretKey::generate(rng);
    let signer = &group.members[author].signer;
    let (_, op, _) = copy
        .update::<Local, _, _>(sk.share_key(), sk, signer, rng)
        .await
        .expect("the author can update");
    group.replicas[author].owner_sks.extend(&copy.owner_sks);
    let mut payload = op.payload;
    let CgkaOperation::Update {
        new_path, doc_id, ..
    } = &mut payload
    else {
        unreachable!("an update")
    };
    for (_, node) in new_path.path.iter_mut() {
        let version = node.head_mut();
        let encrypter_sk = *copy
            .owner_sks
            .get(&version.encrypter_pk)
            .expect("the author has its path secrets");
        let incorrect_secret = ShareSecretKey::generate(rng);
        for encrypted in version.sk.values_mut() {
            *encrypted = encrypt_secret(
                doc_id.as_bytes(),
                incorrect_secret,
                &encrypter_sk,
                &encrypted.paired_pk,
            )
            .expect("encryption succeeds");
        }
    }
    Arc::new(
        async_signer::try_sign_async::<Local, _, _>(signer, payload)
            .await
            .expect("signing succeeds"),
    )
}

#[tokio::test]
async fn a_member_who_receives_forged_path_secrets_still_agrees_on_later_keys() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0001);
    let mut group = Group::new(4, &mut rng).await;
    group.settle(0, &mut rng).await;

    let forged = forged_update(&mut group, 0, &mut rng).await;
    group.broadcast(&forged);
    // Each other member finds that the forged update's path does not match
    // its keys, rather than keeping what it decrypted.
    for replica in &mut group.replicas[1..] {
        let root = replica.decrypt_tree_root_secret();
        assert!(
            matches!(root, Err(CgkaError::PathSecretMismatch)),
            "{root:?}"
        );
    }
    // An honest update from the other half of the tree is encrypted to the
    // node the forgery wrote on its author's side, which it does not replace.
    group.settle(2, &mut rng).await;

    // The member on the forged node's side can still write by rotating.
    let signer = group.members[1].signer.clone();
    let (_, rotation) = group.replicas[1]
        .new_app_secret_for::<Local, _, [u8; 32], _>(&[0; 32], b"bob", &vec![], &signer, &mut rng)
        .await
        .expect("a member who cannot derive the root secret still writes");
    let (op, _) = rotation.expect("writing rotated");
    group.broadcast(&Arc::new(op));

    group.assert_key_agreement("after a forged update, an honest update and write");
}

#[tokio::test]
async fn a_member_who_lacks_its_leaf_secret_rotates_its_leaf_to_write() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0002);
    let mut group = Group::new(3, &mut rng).await;
    group.settle(0, &mut rng).await;

    // As if another instance of this identity rotated the leaf and has not
    // shared the new secret yet.
    let mut stranded = group.replicas[1].clone();
    stranded.owner_sks = ShareKeyMap::new();
    stranded.root_secrets = Default::default();
    let signer = group.members[1].signer.clone();
    let leaf = stranded.owner_leaf_key();
    let (_, rotation) = stranded
        .new_app_secret_for::<Local, _, [u8; 32], _>(&[0; 32], b"b", &vec![], &signer, &mut rng)
        .await
        .expect("a member who lacks its leaf secret still writes");

    assert!(rotation.is_some(), "writing rotated");
    assert_ne!(stranded.owner_leaf_key(), leaf, "the leaf was replaced");
}
