//! Path secrets contained in an update operation.

use crate::{
    cgka::NoImplicitRemoves,
    collections::Set,
    encrypted::encrypt_secret,
    error::CgkaError,
    operation::{CgkaChange, CgkaOperation},
    secret_store::SecretStore,
    test_utils::Group,
    tree::PathChange,
    treemath::{InnerNodeIndex, TreeNodeIndex},
};
use alloc::{collections::BTreeMap, sync::Arc};
use future_form::Local;
use keyhive_crypto::{share_key::ShareSecretKey, verified::Verified};
use rand::{rngs::StdRng, SeedableRng};

/// An update by `author` whose every path node is encrypted to its
/// recipients as a random secret that is not that node's correct
/// secret for this rotation, signed by `author`.
async fn forged_update(
    group: &mut Group<NoImplicitRemoves>,
    author: usize,
    rng: &mut StdRng,
) -> Arc<Verified<CgkaOperation>> {
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
    let mut payload = op.payload().clone();
    let doc_id = payload.doc_id;
    let CgkaChange::Update { new_path, .. } = &mut payload.change else {
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
                doc_id,
                incorrect_secret,
                &encrypter_sk,
                &encrypted.paired_pk,
            )
            .expect("encryption succeeds");
        }
    }
    Arc::new(
        Verified::sign::<Local, _>(&payload, signer)
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
        let root = replica.decrypt_current_group_secret();
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
    let (_, _, rotation) = group.replicas[1]
        .group_secret_for_write::<Local, _, _>(&signer, &mut rng)
        .await
        .expect("a member who cannot derive the root secret still writes");
    let (op, _) = rotation.expect("writing rotated");
    group.broadcast(&Arc::new(op));

    group.assert_key_agreement("after a forged update, an honest update and write");
}

/// The path of an honest rotation in a group of four, which has two nodes.
async fn honest_path(rng: &mut StdRng) -> PathChange {
    let mut group = Group::<NoImplicitRemoves>::new(4, rng).await;
    group.settle(0, rng).await;
    let op = group.rotate(0, rng).await;
    let CgkaChange::Update { new_path, .. } = &op.payload().change else {
        unreachable!("a rotation is an update")
    };
    (**new_path).clone()
}

#[tokio::test]
async fn a_path_node_without_an_entry_for_its_encrypting_child_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0003);
    let mut path = honest_path(&mut rng).await;
    let first = TreeNodeIndex::from(InnerNodeIndex::new(path.path[0].0));
    path.path[1]
        .1
        .head_mut()
        .sk
        .remove(&first)
        .expect("a node has an entry for the child that encrypted it");

    assert!(!path.is_well_formed());
}

#[tokio::test]
async fn a_path_node_with_two_versions_is_malformed() {
    let mut rng = StdRng::seed_from_u64(0x9a7b_0004);
    let mut path = honest_path(&mut rng).await;
    let stranger = ShareSecretKey::generate(&mut rng).share_key();
    path.path[0].1.merge(
        &SecretStore::new(stranger, stranger, BTreeMap::new()),
        &Set::new(),
    );

    assert!(!path.is_well_formed());
}
