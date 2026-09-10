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
    access::Access,
    certificate::Certificate,
    delegation::Delegation,
    keyline::Keyline,
    revocation::Revocation,
    test_utils::{cert, id},
};

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

pub fn d(iss: u8, aud: u8, sub: u8, can: Access) -> Delegation {
    Delegation::new(id(iss), id(aud), id(sub), can)
}

pub fn r(iss: u8, target: &Delegation) -> Revocation {
    Revocation::new(id(iss), target.digest())
}

/// A backend holding exactly these certificates.
pub fn build<K: Keyline + Default, I: IntoIterator<Item = Certificate>>(certs: I) -> K {
    let mut k = K::default();
    for c in certs {
        k.insert(cert(c));
    }
    k
}

pub fn access<K: Keyline>(k: &K, sub: u8, aud: u8) -> Option<Access> {
    k.effective_access(id(sub), id(aud))
}
