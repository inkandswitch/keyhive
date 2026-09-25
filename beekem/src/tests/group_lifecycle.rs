use crate::{error::CgkaError, test_utils::Group};
use future_form::Local;
use keyhive_crypto::share_key::ShareSecretKey;
use rand::{rngs::StdRng, SeedableRng};

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

#[tokio::test]
async fn shrinking_into_a_subtree_makes_its_secret_the_root_secret() {
    let mut rng = StdRng::seed_from_u64(0x11fe_0002);
    let mut group = Group::new(4, &mut rng).await;
    for i in 0..4 {
        let op = group.rotate(i, &mut rng).await;
        group.broadcast(&op);
    }
    assert!(
        group.replicas[0].has_pcs_key(),
        "there should be a root secret after everyone rotated"
    );

    // The upper half leaves. The two who remain are in a subtree that the removals
    // did not blank.
    for target in [3, 2] {
        let id = group.id(target);
        let op = group.remove(0, id).await;
        group.broadcast(&op);
    }

    assert_eq!(
        group.replicas[0].group_size(),
        2,
        "the wrong members were removed"
    );
    assert!(
        group.replicas[0].has_pcs_key(),
        "shrinking into a subtree should makes its secret the root secret"
    );
    group.replicas[0]
        .pcs_key_from_tree_root()
        .expect("a member who remains can still derive the key");
}
