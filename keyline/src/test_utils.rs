//! Test support: deterministic fixtures, and the cross-backend conformance
//! suite in [`conformance`].
//!
//! Not part of the public API; gated on `cfg(test)` and the `test_utils` feature.

pub mod conformance;

use crate::{
    certificate::Certificate,
    id::Id,
    signed::{Signed, Verified},
};
use ed25519_dalek::{Signature, SigningKey};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::domain_separator::Domain;

/// A deterministic signing key derived from a small integer.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// The [`Id`] of [`signing_key`]`(n)`.
pub fn id(n: u8) -> Id {
    Id::from(&signing_key(n))
}

/// Wrap a certificate as [`Verified`] without signing it.
///
/// The signature is all zeros and is never checked: [`Verified::assume`] exists
/// so that graph tests do not pay for Ed25519. Use [`signed`] where the
/// production path matters.
pub fn cert<W: Encode + Decode, X: Into<Certificate<W>>>(cert: X) -> Verified<Certificate<W>> {
    let cert = cert.into();
    Verified::assume(Signed::from_parts(
        cert.encode(),
        Signature::from_bytes(&[0u8; 64]),
    ))
}

/// Sign a certificate with the deterministic key of its issuer and verify it:
/// the production path, for the few tests that should exercise it.
///
/// The issuer must be one of the fixture identities (`id(n)`), so its signing
/// key is `signing_key(n)`.
pub fn signed<W: Encode + Decode, X: Into<Certificate<W>>>(cert: X) -> Verified<Certificate<W>> {
    let cert = cert.into();
    Signed::try_sign(&cert, &issuer_key(&cert))
        .expect("key is the issuer")
        .verify()
        .expect("freshly signed certificate verifies")
}

/// [`signed`], but with another valid signature over the same bytes.
///
/// The nonce is derived from `salt` instead of the RFC 8032 derivation, as a
/// hedged or randomised signer would choose it. The result has the same digest
/// as [`signed`]'s, and a different signature.
pub fn resigned<W: Encode + Decode, X: Into<Certificate<W>>>(
    cert: X,
    salt: u8,
) -> Verified<Certificate<W>> {
    use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};

    let cert = cert.into();
    let key = issuer_key(&cert);
    let mut expanded = ExpandedSecretKey::from(key.as_bytes());
    expanded.hash_prefix = [salt; 32];
    let encoded = cert.encode();
    let message = Certificate::<W>::message(encoded.as_bytes());
    let signature = raw_sign::<sha2::Sha512>(&expanded, &message, &key.verifying_key());
    Signed::from_parts(encoded, signature)
        .verify()
        .expect("a signature with any nonce verifies")
}

/// The fixture signing key whose `Id` is the certificate's issuer.
fn issuer_key<W>(cert: &Certificate<W>) -> SigningKey {
    (0..=u8::MAX)
        .map(signing_key)
        .find(|k| Id::from(k) == cert.issuer())
        .expect("issuer is a fixture identity")
}

/// One edit to a byte string. Positions wrap modulo the current length, so
/// every mutation applies to any input.
#[cfg(feature = "arbitrary")]
#[derive(Debug, Clone, arbitrary::Arbitrary)]
pub enum Mutation {
    Flip { at: usize, mask: u8 },
    Insert { at: usize, byte: u8 },
    Remove { at: usize },
    Truncate { len: usize },
}

#[cfg(feature = "arbitrary")]
impl Mutation {
    pub fn apply(&self, bytes: &mut alloc::vec::Vec<u8>) {
        match *self {
            Mutation::Flip { at, mask } if !bytes.is_empty() => {
                let i = at % bytes.len();
                bytes[i] ^= mask;
            }
            Mutation::Insert { at, byte } => bytes.insert(at % (bytes.len() + 1), byte),
            Mutation::Remove { at } if !bytes.is_empty() => {
                bytes.remove(at % bytes.len());
            }
            Mutation::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
            Mutation::Flip { .. } | Mutation::Remove { .. } => {}
        }
    }
}

/// Canonicality near valid encodings: mutate the encoding of an arbitrary
/// `T`, and whatever still decodes must re-encode to exactly those bytes.
///
/// Random byte strings almost never decode (bolero's default length is at
/// most 64 bytes, below every certificate's minimum), so a raw-bytes harness
/// would never reach its assertion. Starting from a valid encoding keeps the
/// mutated input near the inputs that matter: tags, counts, lengths, and
/// trailing bytes.
#[cfg(feature = "arbitrary")]
pub fn decode_is_canonical_near<T>()
where
    T: for<'a> arbitrary::Arbitrary<'a> + Encode + Decode + core::fmt::Debug + 'static,
{
    bolero::check!()
        .with_arbitrary::<(T, alloc::vec::Vec<Mutation>)>()
        .for_each(|(value, mutations)| {
            let mut bytes = value.encode().into_bytes();
            for m in mutations {
                m.apply(&mut bytes);
            }
            if let Ok(decoded) = T::decode(&bytes) {
                assert_eq!(decoded.encode().as_bytes(), bytes.as_slice());
            }
        });
}
