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
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use keyhive_codec::traits::{Decode, Encode};

/// A deterministic signing key derived from a small integer.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// The [`Id`] of [`signing_key`]`(n)`.
pub fn id(n: u8) -> Id {
    Id::new(VerifyingKey::from(&signing_key(n)))
}

/// Wrap a certificate as [`Verified`] without signing it.
///
/// The signature is all zeros and is never checked: [`Verified::assume`] exists
/// so that graph tests do not pay for Ed25519. Use [`signed`] where the
/// production path matters.
pub fn cert<C: Encode + Decode, X: Into<Certificate<C>>>(cert: X) -> Verified<Certificate<C>> {
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
pub fn signed<C: Encode + Decode, X: Into<Certificate<C>>>(cert: X) -> Verified<Certificate<C>> {
    let cert = cert.into();
    let key = (0..=u8::MAX)
        .map(signing_key)
        .find(|k| Id::new(k.verifying_key()) == cert.issuer())
        .expect("issuer is a fixture identity");
    Signed::try_sign(&cert, &key)
        .expect("key is the issuer")
        .verify()
        .expect("freshly signed certificate verifies")
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
    T: for<'a> arbitrary::Arbitrary<'a> + Encode + Decode + core::fmt::Debug,
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
