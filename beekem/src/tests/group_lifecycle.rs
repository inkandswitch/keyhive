use crate::{
    cgka::Cgka,
    error::CgkaError,
    test_utils::{member, Group},
};
use core::hash::{Hash, Hasher};
use future_form::Local;
use keyhive_crypto::share_key::ShareSecretKey;
use rand::{rngs::StdRng, SeedableRng};
use std::hash::DefaultHasher;

#[tokio::test]
async fn a_group_can_be_emptied_and_refilled() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0001);
    let mut group = Group::new(1, &mut rng).await;
    let owner = group.id(0);
    let signer = group.members[0].signer.clone();
    let cgka = &mut group.replicas[0];

    cgka.remove::<Local, _>(owner, &signer)
        .await
        .expect("removing the last member is allowed");
    assert_eq!(
        cgka.group_size(),
        0,
        "removing the last member left members"
    );
    assert!(!cgka.has_pcs_key(), "an empty group reported a PCS key");

    let sk = ShareSecretKey::generate(&mut rng);
    assert!(
        matches!(
            cgka.update::<Local, _, _>(sk.share_key(), sk, &signer, &mut rng)
                .await,
            Err(CgkaError::NoMembers)
        ),
        "an empty group has no leaf to encrypt a path from"
    );

    let rejoin_pk = ShareSecretKey::generate(&mut rng).share_key();
    cgka.add::<Local, _>(owner, rejoin_pk, &signer)
        .await
        .expect("the owner can rejoin an empty group");
    let rotate = ShareSecretKey::generate(&mut rng);
    cgka.update::<Local, _, _>(rotate.share_key(), rotate, &signer, &mut rng)
        .await
        .expect("a member of a refilled group can encrypt a path");
    assert!(
        cgka.has_pcs_key(),
        "a refilled group did not recover a PCS key"
    );
}

fn hash_of(cgka: &Cgka) -> u64 {
    let mut hasher = DefaultHasher::new();
    cgka.hash(&mut hasher);
    hasher.finish()
}

#[tokio::test]
async fn adding_a_member_changes_the_hash() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0002);
    let mut group = Group::new(2, &mut rng).await;
    let before = hash_of(&group.replicas[0]);

    let joiner = member(&mut rng);
    group.add(0, joiner.id, joiner.pk).await;

    assert_ne!(
        hash_of(&group.replicas[0]),
        before,
        "a replica hashes the same before and after a membership change"
    );
}
