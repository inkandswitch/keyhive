//! The codec laws for every Beekem type that is sent inside an operation, and
//! the rejections that keep each value to one encoding.

use crate::{
    encrypted::{encrypt_secret, EncryptedSecret},
    id::TreeId,
    operation::{
        CgkaChange, CgkaOperation, CitationId, Invitation, InvitationSecret, PredecessorSecret,
        RemovedMember,
    },
    secret_store::{SecretStore, SecretStoreVersion},
    tree::PathChange,
    treemath::TreeNodeIndex,
};
use alloc::{collections::BTreeMap, vec::Vec};
use ed25519_dalek::SigningKey;
use keyhive_codec::{
    error::DecodeError,
    laws::{canonical_near, round_trip, stream},
    prefixed::encode_bytes,
    traits::{Decode, Encode, StreamDecode},
};
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use rand::{rngs::StdRng, SeedableRng};

/// The share key from seed `n`.
fn key(n: u8) -> ShareKey {
    ShareSecretKey::generate(&mut StdRng::seed_from_u64(n.into())).share_key()
}

/// A secret from seed `n`, sealed to [`key`]`(n)`.
fn sealed(n: u8) -> EncryptedSecret<ShareSecretKey> {
    let mut rng = StdRng::seed_from_u64(u64::from(n) + 1000);
    encrypt_secret(
        TreeId::from(&SigningKey::from_bytes(&[n; 32])),
        ShareSecretKey::generate(&mut rng),
        &ShareSecretKey::generate(&mut rng),
        &key(n),
    )
    .expect("a fresh secret seals")
}

fn laws<T>()
where
    T: for<'a> arbitrary::Arbitrary<'a>
        + core::fmt::Debug
        + Encode
        + PartialEq
        + StreamDecode
        + 'static,
{
    round_trip::<T>();
    canonical_near::<T>();
    stream::<T>();
}

#[test]
fn citation_laws() {
    laws::<CitationId>();
}

#[test]
fn removed_member_laws() {
    laws::<RemovedMember>();
}

#[test]
fn encrypted_secret_laws() {
    laws::<EncryptedSecret<ShareSecretKey>>();
}

#[test]
fn secret_store_version_laws() {
    laws::<SecretStoreVersion>();
}

#[test]
fn secret_store_laws() {
    laws::<SecretStore>();
}

#[test]
fn invitation_laws() {
    laws::<InvitationSecret>();
    laws::<Invitation>();
}

#[test]
fn predecessor_secret_laws() {
    laws::<PredecessorSecret>();
}

#[test]
fn path_change_laws() {
    laws::<PathChange>();
}

#[test]
fn cgka_operation_laws() {
    laws::<CgkaChange>();
    laws::<CgkaOperation>();
}

fn version(seed: u8) -> SecretStoreVersion {
    SecretStoreVersion {
        pk: key(seed),
        sk: BTreeMap::from([(
            TreeNodeIndex::decode(&[seed]).expect("one byte"),
            sealed(seed),
        )]),
        encrypter_pk: key(seed.wrapping_add(1)),
    }
}

/// A count followed by `versions`, encoded as given.
fn store_bytes(versions: &[SecretStoreVersion]) -> Vec<u8> {
    let mut bytes = Vec::new();
    keyhive_codec::prefixed::encode_list(versions, &mut bytes);
    bytes
}

#[test]
fn a_secret_store_must_have_a_version() {
    assert_eq!(
        SecretStore::decode(&store_bytes(&[])),
        Err(DecodeError::InvalidField("secret store versions"))
    );
}

#[test]
fn secret_store_versions_must_ascend_without_repeats() {
    let (low, high) = {
        let (a, b) = (version(1), version(2));
        if a < b {
            (a, b)
        } else {
            (b, a)
        }
    };
    assert!(SecretStore::decode(&store_bytes(&[low.clone(), high.clone()])).is_ok());
    assert_eq!(
        SecretStore::decode(&store_bytes(&[high, low.clone()])),
        Err(DecodeError::UnsortedKeys)
    );
    assert_eq!(
        SecretStore::decode(&store_bytes(&[low.clone(), low])),
        Err(DecodeError::UnsortedKeys)
    );
}

#[test]
fn a_secret_map_must_ascend_by_tree_index() {
    let v = version(3);
    let entry = v.sk.values().next().expect("one entry").clone();
    let mut bytes = Vec::new();
    v.pk.encode_into(&mut bytes);
    // Count 2: index 5, then index 4.
    bytes.push(2);
    for index in [5, 4] {
        bytes.push(index);
        entry.encode_into(&mut bytes);
    }
    v.encrypter_pk.encode_into(&mut bytes);
    assert_eq!(
        SecretStoreVersion::decode(&bytes),
        Err(DecodeError::UnsortedKeys)
    );
}

/// Every sealed secret holds at least its 24-byte nonce and 16-byte tag.
#[test]
fn a_sealed_secret_holds_at_least_a_nonce_and_tag() {
    let decode = |len| {
        let mut bytes = Vec::new();
        encode_bytes(&alloc::vec![0; len], &mut bytes);
        key(1).encode_into(&mut bytes);
        EncryptedSecret::<ShareSecretKey>::decode(&bytes)
    };
    assert_eq!(decode(0), Err(DecodeError::InvalidField("sealed")));
    assert_eq!(decode(39), Err(DecodeError::InvalidField("sealed")));
    assert!(decode(40).is_ok());
}

#[test]
fn a_small_order_paired_key_is_rejected() {
    let mut bytes = sealed(9).encode().into_bytes();
    let at = bytes.len() - 32;
    bytes[at..].copy_from_slice(&[0; 32]);
    assert!(matches!(
        EncryptedSecret::<ShareSecretKey>::decode(&bytes),
        Err(DecodeError::InvalidField(_))
    ));
}

/// Fixed values for the operation layouts below.
mod layout {
    use super::*;
    use crate::id::MemberId;
    use keyhive_crypto::digest::Digest;

    pub(super) fn doc() -> TreeId {
        TreeId::from(&SigningKey::from_bytes(&[1; 32]))
    }

    pub(super) fn member() -> MemberId {
        MemberId::from(&SigningKey::from_bytes(&[2; 32]))
    }

    pub(super) fn share_key(n: u8) -> ShareKey {
        ShareSecretKey::force_from_bytes([n; 32]).share_key()
    }

    pub(super) fn digest<T>() -> Digest<T> {
        Digest::from([4; 32])
    }

    /// `parts` in order, as one byte string.
    pub(super) fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }
}

/// `doc ‖ predecessors ‖ 0 ‖ added_id ‖ pk ‖ leaf_index ‖ invitation? ‖
/// key_proof? ‖ citations`, an absent invitation as tag `0` and a present
/// key proof as tag `1` and its length-prefixed bytes.
#[test]
fn an_add_encodes_in_its_documented_layout() {
    use layout::*;
    let op = CgkaOperation {
        doc_id: doc(),
        predecessors: Default::default(),
        change: CgkaChange::Add {
            added_id: member(),
            pk: share_key(3),
            leaf_index: 3,
            invitation: None,
            key_proof: Some(alloc::vec![9, 9]),
            citations: [CitationId([5; 32])].into(),
        },
    };
    let expected = concat(&[
        doc().as_bytes(),
        &[0, 0],
        member().as_bytes(),
        share_key(3).as_bytes(),
        &[3, 0, 1, 2, 9, 9, 1],
        &[5; 32],
    ]);
    assert_eq!(op.encode().as_bytes(), expected);
    assert_eq!(CgkaOperation::decode(&expected), Ok(op));
}

/// `doc ‖ predecessors ‖ 1 ‖ citations ‖ removed`, each set a count and then
/// its elements ascending.
#[test]
fn a_remove_encodes_in_its_documented_layout() {
    use layout::*;
    let op = CgkaOperation {
        doc_id: doc(),
        predecessors: [digest()].into(),
        change: CgkaChange::Remove {
            citations: [CitationId([5; 32])].into(),
            removed: [RemovedMember {
                id: member(),
                leaf_idx: 7,
            }]
            .into(),
        },
    };
    let expected = concat(&[
        doc().as_bytes(),
        &[1],
        &[4; 32],
        &[1, 1],
        &[5; 32],
        &[1],
        member().as_bytes(),
        &[7],
    ]);
    assert_eq!(op.encode().as_bytes(), expected);
    assert_eq!(CgkaOperation::decode(&expected), Ok(op));
}

/// `doc ‖ predecessors ‖ 2 ‖ leaf_idx ‖ leaf_pk ‖ path ‖ removed_keys ‖
/// predecessor_secrets`, the path a count and then `( index ‖ node )*`.
#[test]
fn an_update_encodes_in_its_documented_layout() {
    use layout::*;
    let node = SecretStore::new(share_key(6), share_key(3), BTreeMap::new());
    let op = CgkaOperation {
        doc_id: doc(),
        predecessors: Default::default(),
        change: CgkaChange::Update {
            new_path: alloc::boxed::Box::new(PathChange {
                leaf_idx: 2,
                leaf_pk: share_key(3),
                path: alloc::vec![(1, node.clone())],
                removed_keys: [share_key(8)].into(),
            }),
            predecessor_secrets: alloc::vec![PredecessorSecret {
                update_op_hash: digest(),
                encrypted_root_secret: alloc::vec![6, 6, 6],
            }],
        },
    };
    let expected = concat(&[
        doc().as_bytes(),
        &[0, 2, 2],
        share_key(3).as_bytes(),
        &[1, 1],
        node.encode().as_bytes(),
        &[1],
        share_key(8).as_bytes(),
        &[1],
        &[4; 32],
        &[3, 6, 6, 6],
    ]);
    assert_eq!(op.encode().as_bytes(), expected);
    assert_eq!(CgkaOperation::decode(&expected), Ok(op));
}

/// Each set refuses elements out of order or repeated, so an operation has
/// one encoding.
#[test]
fn an_operation_with_unsorted_predecessors_is_refused() {
    use layout::*;
    let mut bytes = concat(&[doc().as_bytes(), &[2], &[9; 32], &[4; 32]]);
    bytes.extend(
        CgkaChange::Remove {
            citations: Default::default(),
            removed: Default::default(),
        }
        .encode()
        .as_bytes(),
    );
    assert_eq!(
        CgkaOperation::decode(&bytes),
        Err(DecodeError::UnsortedKeys)
    );
}
