//! The codec laws for every Beekem type that is sent inside an operation, and
//! the rejections that keep each value to one encoding.

use crate::{
    encrypted::EncryptedSecret,
    operation::{CgkaAuthorization, Invitation, InvitationSecret, PredecessorSecret},
    secret_store::{SecretStore, SecretStoreVersion},
    tree::PathChange,
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
fn authorization_laws() {
    laws::<CgkaAuthorization>();
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
fn an_authorization_tag_past_one_is_rejected() {
    let mut bytes = CgkaAuthorization::Revocation([7; 32]).encode().into_bytes();
    bytes[0] = 2;
    assert_eq!(
        CgkaAuthorization::decode(&bytes),
        Err(DecodeError::InvalidTag(2))
    );
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

mod operation {
    use super::*;
    use crate::{
        id::{MemberId, TreeId},
        operation::{CgkaChange, CgkaOperation},
    };
    use alloc::{collections::BTreeSet, string::String};
    use ed25519_dalek::SigningKey;
    use keyhive_crypto::{digest::Digest, verified::Verified};

    #[test]
    fn operation_laws() {
        laws::<CgkaChange>();
        laws::<CgkaOperation>();
    }

    /// A share key from fixed bytes, not from an RNG: `rand` does not promise
    /// that a seeded `StdRng` gives the same keys across versions.
    fn fixed_key(n: u8) -> ShareKey {
        ShareSecretKey::from(x25519_dalek::StaticSecret::from([n; 32])).share_key()
    }

    fn signing_key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn secret(n: u8, paired: u8) -> EncryptedSecret<ShareSecretKey> {
        EncryptedSecret::new(Siv::from([n; 24]), Vec::from([n; 40]), fixed_key(paired))
    }

    /// One operation of each variant, every field set.
    fn fixtures() -> [CgkaOperation; 3] {
        let doc_id = TreeId::from(&signing_key(1));
        let root = Digest::from([7; 32]);
        let add = CgkaOperation {
            doc_id,
            predecessors: BTreeSet::new(),
            change: CgkaChange::Add {
                added_id: MemberId::from(&signing_key(2)),
                pk: fixed_key(3),
                leaf_index: 1,
                invitation: Some(Invitation {
                    inviter_pk: fixed_key(4),
                    ancestor_secrets: Vec::from([InvitationSecret {
                        update_op_hash: root,
                        encrypted_root_secret: secret(5, 6),
                    }]),
                }),
                authorization: CgkaAuthorization::Delegation([8; 32]),
            },
        };
        let remove = CgkaOperation {
            doc_id,
            predecessors: BTreeSet::from([root]),
            change: CgkaChange::Remove {
                id: MemberId::from(&signing_key(2)),
                leaf_idx: 1,
                removed_keys: BTreeSet::from([fixed_key(3)]),
                authorization: CgkaAuthorization::Revocation([9; 32]),
            },
        };
        let update = CgkaOperation {
            doc_id,
            predecessors: BTreeSet::from([root, Digest::from([10; 32])]),
            change: CgkaChange::Update {
                new_path: PathChange {
                    leaf_idx: 0,
                    leaf_pk: fixed_key(11),
                    path: Vec::from([(
                        0,
                        SecretStore::new(
                            fixed_key(12),
                            fixed_key(11),
                            BTreeMap::from([(
                                TreeNodeIndex::decode(&[2]).expect("one byte"),
                                secret(13, 14),
                            )]),
                        ),
                    )]),
                    removed_keys: BTreeSet::from([fixed_key(15)]),
                },
                predecessor_secrets: Vec::from([PredecessorSecret {
                    update_op_hash: root,
                    encrypted_root_secret: Vec::from([16; 48]),
                }]),
            },
        };
        [add, remove, update]
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }

    /// The digest of each fixture, signed by one key. A change here is a
    /// change to the operation format: every operation's identity changes.
    #[test]
    fn known_answers() {
        let issuer = signing_key(20);
        let digests = fixtures().map(|op| {
            let verified = Verified::sign_sync(&op, &issuer).expect("a valid key signs");
            let frame = verified.signed().encode();
            let decoded =
                keyhive_crypto::verified::Signed::<CgkaOperation>::decode(frame.as_bytes())
                    .expect("the frame decodes")
                    .verify()
                    .expect("the frame verifies");
            assert_eq!(decoded.payload(), &op);
            hex(verified.digest().as_slice())
        });
        assert_eq!(
            digests,
            [
                "46f178fef6ad092daa9b05748859217cb0bb746467597f46a5c44c4833806383",
                "a6c43fd4307123d0dda7493b8c523495f0504e73dc2a598547462d9af874eb9b",
                "69f286b38ffd4599a46c75c3a78b9d094aca90bd7bcf20a19cc567b95f1d93c1",
            ]
        );
    }

    #[test]
    fn predecessors_must_ascend() {
        let [_, _, update] = fixtures();
        let mut descending: Vec<_> = update.predecessors.iter().collect();
        descending.reverse();

        let mut bytes = Vec::new();
        update.doc_id.encode_into(&mut bytes);
        keyhive_codec::prefixed::encode_list(descending, &mut bytes);
        update.change.encode_into(&mut bytes);
        assert_eq!(
            CgkaOperation::decode(&bytes),
            Err(DecodeError::UnsortedKeys)
        );
    }

    #[test]
    fn a_change_tag_past_two_is_rejected() {
        let [add, ..] = fixtures();
        let mut bytes = add.change.encode().into_bytes();
        bytes[0] = 3;
        assert_eq!(CgkaChange::decode(&bytes), Err(DecodeError::InvalidTag(3)));
    }
}
