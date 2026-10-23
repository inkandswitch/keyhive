//! The codec laws for every Beekem type that is sent inside an operation, and
//! the rejections that keep each value to one encoding.

use crate::{
    encrypted::EncryptedSecret,
    operation::{CitationId, Invitation, InvitationSecret, PredecessorSecret, RemovedMember},
    secret_store::{SecretStore, SecretStoreVersion},
    treemath::TreeNodeIndex,
};
use alloc::{collections::BTreeMap, vec::Vec};
use keyhive_codec::{
    error::DecodeError,
    laws::{canonical_near, round_trip, stream},
    traits::{Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    siv::Siv,
};
use rand::{rngs::StdRng, SeedableRng};

/// The share key from seed `n`.
fn key(n: u8) -> ShareKey {
    ShareSecretKey::generate(&mut StdRng::seed_from_u64(n.into())).share_key()
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

fn version(seed: u8) -> SecretStoreVersion {
    let secret = EncryptedSecret::new(Siv::from([seed; 24]), Vec::from([seed; 40]), key(seed));
    SecretStoreVersion {
        pk: key(seed),
        sk: BTreeMap::from([(TreeNodeIndex::decode(&[seed]).expect("one byte"), secret)]),
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

#[test]
fn a_small_order_paired_key_is_rejected() {
    let secret: EncryptedSecret<ShareSecretKey> =
        EncryptedSecret::new(Siv::from([0; 24]), Vec::from([1, 2, 3]), key(9));
    let mut bytes = secret.encode().into_bytes();
    let at = bytes.len() - 32;
    bytes[at..].copy_from_slice(&[0; 32]);
    assert!(matches!(
        EncryptedSecret::<ShareSecretKey>::decode(&bytes),
        Err(DecodeError::InvalidField(_))
    ));
}
