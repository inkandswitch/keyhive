//! The codec laws for every Beekem type that is sent inside an operation, and
//! the rejections that keep each value to one encoding.

use crate::{
    encrypted::{encrypt_secret, EncryptedSecret},
    id::TreeId,
    operation::{CitationId, Invitation, InvitationSecret, PredecessorSecret, RemovedMember},
    secret_store::{SecretStore, SecretStoreVersion},
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
