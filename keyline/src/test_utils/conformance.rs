//! Conformance suite shared by every [`Keyline`] implementation.
//!
//! A backend is correct iff it agrees with the reference implementation on
//! every set. This module makes that checkable: [`scenarios`] are the named
//! cases from the design documents, [`laws`] are `bolero` properties over
//! generated sets, and [`gen`] produces the sets. Every scenario and law is a
//! plain function generic over `K: Keyline + Default`; a backend runs the suite
//! by writing one `#[test]` per function that calls it with the backend's type.
//! The test module in `memory.rs` is the reference list.

// The generator and the `bolero` laws need `Arbitrary`, which needs `std`;
// the scenarios need nothing beyond the crate, so `cargo test` runs them.
#[cfg(feature = "arbitrary")]
pub mod gen;
#[cfg(feature = "arbitrary")]
pub mod laws;
pub mod scenarios;

use crate::{
    certificate::Certificate,
    delegation::Delegation,
    keyline::Keyline,
    power::Power,
    revocation::Revocation,
    test_utils::{cert, id},
};
use keyhive_codec::traits::{Decode, Encode};

// The cast, as small integers for `test_utils::id`. Roles first, then people
// in the usual order (Alice, Bob, Carol, Dan, Eve, Frank).
pub const DOC: u8 = 1;
pub const OWNERS: u8 = 2;
pub const MEMBERS: u8 = 3;
pub const MODS: u8 = 4;
pub const ALICE: u8 = 5;
pub const BOB: u8 = 6;
pub const CAROL: u8 = 7;
pub const DAN: u8 = 8;
pub const EVE: u8 = 9;
pub const FRANK: u8 = 10;
/// A second document, for scenarios that need a subject outside the cast.
pub const OTHER_DOC: u8 = 11;

pub fn d(issuer: u8, audience: u8, subject: u8, power: Power) -> Delegation {
    Delegation::new(id(issuer), id(audience), id(subject), power)
}

pub fn r<C>(issuer: u8, target: &Delegation) -> Revocation<C> {
    Revocation::new(id(issuer), target.digest())
}

/// What a backend's content type must satisfy to run the generated laws.
///
/// The scenarios need none of this — they never look at [`crate::revocation::Revocation::retains`]
/// — but the laws generate whole certificate sets, so the content type has to
/// be generatable and comparable as well as encodable.
pub trait TestContent:
    'static + for<'a> arbitrary::Arbitrary<'a> + Clone + core::fmt::Debug + Eq + Ord + Encode + Decode
{
}

impl<
        T: 'static
            + for<'a> arbitrary::Arbitrary<'a>
            + Clone
            + core::fmt::Debug
            + Eq
            + Ord
            + Encode
            + Decode,
    > TestContent for T
{
}

/// A backend holding exactly these certificates.
pub fn build<K: Keyline + Default, I: IntoIterator<Item = Certificate<K::Content>>>(certs: I) -> K {
    let mut k = K::default();
    for c in certs {
        k.insert(cert(c));
    }
    k
}

pub fn power<K: Keyline>(k: &K, subject: u8, audience: u8) -> Option<Power> {
    k.effective_power(id(subject), id(audience))
}
