//! Secrets sealed to a share key, with their public metadata: BeeKEM node
//! secrets and the root secrets wrapped by an invitation.

use crate::{error::CgkaError, id::TreeId, pcs_key::PcsKey};
use alloc::vec::Vec;
use core::marker::PhantomData;
use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_bytes, encode_bytes},
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    context::Context,
    share_key::{ShareKey, ShareSecretKey},
    symmetric_key::SymmetricKey,
};
use tracing::instrument;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;

/// Bytes [`SymmetricKey::try_seal`] adds to its plaintext: its nonce and its
/// AEAD tag.
const SEAL_OVERHEAD: usize = NONCE_LEN + AEAD_TAG_LEN;

/// A secret that is sealed to a share key. Its type picks the key derivation,
/// so a sealed node secret never opens as an invitation's root secret, or the
/// reverse.
pub trait Sealable {
    /// The context its key is derived under, from the X25519 exchange.
    const CONTEXT: Context;

    /// The secret's bytes, as sealed. Borrowed: a copy would not be wiped.
    fn secret_bytes(&self) -> &[u8];
}

/// A BeeKEM node's secret, sealed to a node of its sibling's resolution.
impl Sealable for ShareSecretKey {
    const CONTEXT: Context = Context::CGKA_NODE_SECRET_KEY;

    fn secret_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A root secret, sealed to an invitee so they can read what came before
/// their add.
impl Sealable for PcsKey {
    const CONTEXT: Context = Context::CGKA_INVITATION_KEY;

    fn secret_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A `T` sealed for the holder of `paired_pk`'s secret, under the key a
/// Diffie-Hellman exchange between that holder and the encrypter gives for
/// `T` ([`Sealable::CONTEXT`]).
///
/// The seal's associated data is the tree and both public keys of the
/// exchange (`tree_id ‖ encrypter_pk ‖ paired_pk`), and opening checks the
/// synthetic nonce ([`SymmetricKey::try_open`]). A ciphertext therefore opens
/// only as a `T`, only in the tree, and between the two keys, it was sealed
/// for, and under only one key.
pub struct EncryptedSecret<T> {
    /// `nonce ‖ ciphertext ‖ tag`, from [`SymmetricKey::try_seal`].
    sealed: Vec<u8>,

    /// The [`ShareKey`] used as a Diffie Hellman partner when encrypting.
    pub paired_pk: ShareKey,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

// By hand: `#[derive]` would also require `T: Ord + Hash`, but `T` only names
// the secret type sealed inside, and secret keys implement neither.
impl<T> Clone for EncryptedSecret<T> {
    fn clone(&self) -> Self {
        EncryptedSecret {
            sealed: self.sealed.clone(),
            paired_pk: self.paired_pk,
            _plaintext_tag: PhantomData,
        }
    }
}

impl<T> PartialEq for EncryptedSecret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.sealed == other.sealed && self.paired_pk == other.paired_pk
    }
}

impl<T> Eq for EncryptedSecret<T> {}

impl<T> PartialOrd for EncryptedSecret<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for EncryptedSecret<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (&self.sealed, &self.paired_pk).cmp(&(&other.sealed, &other.paired_pk))
    }
}

impl<T> core::hash::Hash for EncryptedSecret<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.sealed.hash(state);
        self.paired_pk.hash(state);
    }
}

impl<T> core::fmt::Debug for EncryptedSecret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("sealed", &self.sealed)
            .field("paired_pk", &self.paired_pk)
            .finish()
    }
}

impl<T: Sealable> EncryptedSecret<T> {
    /// Open with the encrypter's secret key.
    #[instrument(skip_all)]
    pub fn try_encrypter_decrypt(
        &self,
        doc_id: TreeId,
        encrypter_sk: &ShareSecretKey,
    ) -> Result<Zeroizing<Vec<u8>>, chacha20poly1305::Error> {
        encrypter_sk
            .derive_symmetric_key(&self.paired_pk, T::CONTEXT)
            .try_open(
                &self.sealed,
                &node_secret_aad(doc_id, &encrypter_sk.share_key(), &self.paired_pk),
            )
    }

    /// Open with `paired_sk`, the secret of [`Self::paired_pk`], given the
    /// encrypter's public key.
    #[instrument(skip_all)]
    pub fn try_paired_decrypt(
        &self,
        doc_id: TreeId,
        paired_sk: &ShareSecretKey,
        encrypter_pk: &ShareKey,
    ) -> Result<Zeroizing<Vec<u8>>, chacha20poly1305::Error> {
        paired_sk
            .derive_symmetric_key(encrypter_pk, T::CONTEXT)
            .try_open(
                &self.sealed,
                &node_secret_aad(doc_id, encrypter_pk, &self.paired_pk),
            )
    }
}

/// The key a Diffie-Hellman exchange gives for sealing a `T`, with the
/// public keys of both sides.
pub struct PairedKey<T> {
    key: SymmetricKey,
    encrypter_pk: ShareKey,
    paired_pk: ShareKey,
    _plaintext_tag: PhantomData<T>,
}

impl<T: Sealable> PairedKey<T> {
    /// Derive the key `paired_pk`'s holder needs to open the `T`s `sk` seals.
    pub fn new(sk: &ShareSecretKey, paired_pk: &ShareKey) -> Self {
        PairedKey {
            key: sk.derive_symmetric_key(paired_pk, T::CONTEXT),
            encrypter_pk: sk.share_key(),
            paired_pk: *paired_pk,
            _plaintext_tag: PhantomData,
        }
    }
}

/// `tree_id ‖ encrypter_pk ‖ paired_pk`, the associated data a node secret is
/// sealed under.
fn node_secret_aad(doc_id: TreeId, encrypter_pk: &ShareKey, paired_pk: &ShareKey) -> [u8; 96] {
    let mut aad = [0; 96];
    aad[..32].copy_from_slice(doc_id.as_bytes());
    aad[32..64].copy_from_slice(encrypter_pk.as_bytes());
    aad[64..].copy_from_slice(paired_pk.as_bytes());
    aad
}

/// Up to a few blocks of arbitrary sealed bytes, never shorter than a nonce
/// and a tag, so that every value has an encoding that decodes.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T> arbitrary::Arbitrary<'a> for EncryptedSecret<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut sealed = <[u8; SEAL_OVERHEAD]>::arbitrary(u)?.to_vec();
        sealed.extend(Vec::<u8>::arbitrary(u)?);
        Ok(EncryptedSecret {
            sealed,
            paired_pk: ShareKey::arbitrary(u)?,
            _plaintext_tag: PhantomData,
        })
    }
}

/// `sealed_len:bijou32 ‖ sealed ‖ paired_pk`.
impl<T> Encode for EncryptedSecret<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_bytes(&self.sealed, out);
        self.paired_pk.encode_into(out);
    }
}

impl<T> Decode for EncryptedSecret<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T> StreamDecode for EncryptedSecret<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (sealed, rest) = decode_bytes(bytes)?;
        if sealed.len() < SEAL_OVERHEAD {
            return Err(DecodeError::InvalidField("sealed"));
        }
        let (paired_pk, rest) = ShareKey::decode_next(rest)?;
        Ok((
            EncryptedSecret {
                sealed: sealed.to_vec(),
                paired_pk,
                _plaintext_tag: PhantomData,
            },
            rest,
        ))
    }
}

/// Seal `secret` for the holder of `paired_pk`'s secret.
pub fn encrypt_secret<T: Sealable>(
    doc_id: TreeId,
    secret: &T,
    sk: &ShareSecretKey,
    paired_pk: &ShareKey,
) -> Result<EncryptedSecret<T>, CgkaError> {
    encrypt_secret_with(&PairedKey::new(sk, paired_pk), doc_id, secret)
}

/// Seal `secret` under an already derived [`PairedKey`].
pub fn encrypt_secret_with<T: Sealable>(
    paired: &PairedKey<T>,
    doc_id: TreeId,
    secret: &T,
) -> Result<EncryptedSecret<T>, CgkaError> {
    let PairedKey {
        key,
        encrypter_pk,
        paired_pk,
        ..
    } = paired;
    let sealed = key
        .try_seal(
            secret.secret_bytes(),
            &node_secret_aad(doc_id, encrypter_pk, paired_pk),
        )
        .map_err(CgkaError::Encryption)?;
    Ok(EncryptedSecret {
        sealed,
        paired_pk: *paired_pk,
        _plaintext_tag: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use core::hash::{Hash, Hasher};
    use ed25519_dalek::SigningKey;
    #[cfg(feature = "std")]
    use std::collections::hash_map::DefaultHasher;

    fn doc(n: u8) -> TreeId {
        TreeId::from(&SigningKey::from_bytes(&[n; 32]))
    }

    fn share_sk(n: u8) -> ShareSecretKey {
        ShareSecretKey::force_from_bytes([n; 32])
    }

    fn sealed_to(sealed: &[u8], pk_seed: u8) -> EncryptedSecret<ShareSecretKey> {
        EncryptedSecret {
            sealed: sealed.to_vec(),
            paired_pk: share_sk(pk_seed).share_key(),
            _plaintext_tag: PhantomData,
        }
    }

    #[cfg(feature = "std")]
    fn hash_of(secret: &EncryptedSecret<ShareSecretKey>) -> u64 {
        let mut hasher = DefaultHasher::new();
        secret.hash(&mut hasher);
        hasher.finish()
    }

    /// The hand-written `PartialEq`, `Ord` and `Hash` (`T` has no `Ord` or
    /// `Hash` to derive them from) agree with the fields: equal exactly when
    /// both fields are, ordered by `sealed` then `paired_pk`, and hashed from
    /// both, so equal values hash alike and values differing in either field
    /// hash apart.
    #[cfg(feature = "std")]
    #[test]
    fn equality_order_and_hash_follow_both_fields() {
        bolero::check!()
            .with_type::<(Vec<u8>, u8, Vec<u8>, u8)>()
            .for_each(|(sealed_a, pk_a, sealed_b, pk_b)| {
                let (a, b) = (sealed_to(sealed_a, *pk_a), sealed_to(sealed_b, *pk_b));
                let same_fields = sealed_a == sealed_b && pk_a == pk_b;
                assert_eq!(a == b, same_fields);

                // Differing in one field alone is enough to differ.
                let other_pk = sealed_to(sealed_a, pk_a.wrapping_add(1));
                let other_sealed = sealed_to(&[sealed_a.as_slice(), &[0]].concat(), *pk_a);
                assert_ne!(a, other_pk);
                assert_ne!(a, other_sealed);
                assert_ne!(hash_of(&a), hash_of(&other_pk));
                assert_ne!(hash_of(&a), hash_of(&other_sealed));
                assert_eq!(
                    a.cmp(&b),
                    (sealed_a, a.paired_pk).cmp(&(sealed_b, b.paired_pk))
                );
                assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
                assert_eq!(hash_of(&a) == hash_of(&b), same_fields);
            });
    }

    /// Node secrets and invitations' root secrets are sealed under keys from
    /// different contexts, so one exchange's node secret does not open as an
    /// invitation secret, nor the reverse, though their bytes decode as either.
    #[test]
    fn a_node_secret_and_an_invitation_secret_do_not_open_as_each_other() {
        let (encrypter, paired) = (share_sk(2), share_sk(3));
        let as_other = |bytes: &[u8]| -> EncryptedSecret<PcsKey> {
            EncryptedSecret::decode(bytes).expect("the layouts are the same")
        };

        let node_secret =
            encrypt_secret(doc(1), &share_sk(1), &encrypter, &paired.share_key()).expect("seals");
        assert!(node_secret
            .try_paired_decrypt(doc(1), &paired, &encrypter.share_key())
            .is_ok());
        assert_eq!(
            as_other(node_secret.encode().as_bytes()).try_paired_decrypt(
                doc(1),
                &paired,
                &encrypter.share_key()
            ),
            Err(chacha20poly1305::Error)
        );

        let invitation = encrypt_secret(
            doc(1),
            &PcsKey::new(share_sk(1)),
            &encrypter,
            &paired.share_key(),
        )
        .expect("seals");
        assert!(invitation
            .try_paired_decrypt(doc(1), &paired, &encrypter.share_key())
            .is_ok());
        let as_node_secret: EncryptedSecret<ShareSecretKey> =
            EncryptedSecret::decode(invitation.encode().as_bytes()).expect("same layout");
        assert_eq!(
            as_node_secret.try_paired_decrypt(doc(1), &paired, &encrypter.share_key()),
            Err(chacha20poly1305::Error)
        );
    }

    /// The encrypter and the paired key's holder both open a node secret in
    /// the tree it was sealed in, and neither opens it in another.
    #[test]
    fn a_node_secret_opens_only_in_its_tree() {
        let (secret, encrypter, paired) = (share_sk(1), share_sk(2), share_sk(3));
        let sealed =
            encrypt_secret(doc(1), &secret, &encrypter, &paired.share_key()).expect("seals");
        let plaintext = Zeroizing::new(secret.as_slice().to_vec());
        for (tree, expected) in [
            (doc(1), Ok(plaintext)),
            (doc(2), Err(chacha20poly1305::Error)),
        ] {
            assert_eq!(sealed.try_encrypter_decrypt(tree, &encrypter), expected);
            assert_eq!(
                sealed.try_paired_decrypt(tree, &paired, &encrypter.share_key()),
                expected
            );
        }
    }
}
