//! The [`Keyline`] trait: the backend contract.
//!
//! Every method is defined purely in terms of the certificate set, so an
//! implementation over any store (in memory, DBSP, a database) is correct if and
//! only if it agrees with the reference [`crate::memory::MemoryKeyline`] on every
//! set. The conformance suite behind the `test_utils` feature is how a backend
//! proves that.

use crate::{
    access::Access, certificate::Certificate, delegation::Delegation, id::Id,
    revocation::Revocation, signed::Verified,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::digest::Digest;

/// A set of certificates and the authority they imply.
///
/// Queries are `&self` and inserts are `&mut self`; the trait is synchronous.
/// Concurrency is the wrapper's job: `keyhive_core` holds an implementation
/// behind a `RwLock`, and readers call `&self` methods in parallel.
pub trait Keyline {
    /// Add a certificate to the set. Returns `true` if it was not already
    /// present, as [`alloc::collections::BTreeSet::insert`] does. Idempotent;
    /// insertion order never matters.
    ///
    /// A revocation whose target is not (yet) in the set is stored like any
    /// other certificate; it contributes nothing until the target arrives.
    ///
    /// The return value is a dedupe signal for gossip, not a membership-change
    /// signal: a new certificate may change no query result (it may be dead on
    /// arrival), so callers driving key rotation must diff [`Keyline::members`].
    fn insert(&mut self, cert: Verified<Certificate>) -> bool;

    /// Whether a certificate with this digest is in the set.
    ///
    /// Cheap. Ingest paths should call this before paying for signature
    /// verification: `Digest::of(signed.encoded())` costs nanoseconds,
    /// `verify` costs tens of microseconds.
    fn contains(&self, cert: &Digest<Certificate>) -> bool;

    /// Revocations in the set that name this delegation, covering or not.
    ///
    /// Whether a revocation actually covers the delegation depends on the
    /// issuer's admin reach; this reports the syntactic fact. Its main use
    /// is explaining a silent collision: an issuer who re-mints a grant
    /// byte-identical to a revoked one gets `insert == false`, and this tells
    /// them why and that a re-issue with `seen` is needed.
    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<Revocation>>;

    /// `aud`'s effective level over `sub`: the maximum over live routes of the
    /// minimum along each. `None` if no live route exists.
    ///
    /// Every subject stands at `Admin` over itself by axiom, so
    /// `effective_access(x, x)` is `Some(Admin)` for every `x`.
    fn effective_access(&self, sub: Id, aud: Id) -> Option<Access>;

    /// Every `Id` other than `sub` itself with a live route to `sub`, with its
    /// effective level. The materialized view.
    fn members(&self, sub: Id) -> BTreeMap<Id, Access>;

    /// Whether the named delegation participates in any live derivation.
    /// `false` for digests not in the set.
    fn is_live(&self, cert: &Digest<Delegation>) -> bool;

    /// A digest of the whole set. Same set (in any order), same digest; usable
    /// as a cache key for every other query. Backends compute it with
    /// [`set_digest`].
    fn digest(&self) -> Digest<BTreeSet<Certificate>>;
}

/// Digest a certificate set from its members' certificate digests, in any order.
///
/// BLAKE3 over the sorted digests, so the result is independent of insertion
/// order. Typed as `Digest<BTreeSet<Certificate>>` so it cannot be confused
/// with the digest of a single certificate.
pub fn set_digest<I: IntoIterator<Item = Digest<Certificate>>>(
    digests: I,
) -> Digest<BTreeSet<Certificate>> {
    let mut sorted: Vec<[u8; 32]> = digests
        .into_iter()
        .map(|d| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(d.as_slice());
            bytes
        })
        .collect();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for d in &sorted {
        hasher.update(d);
    }
    Digest::from(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_digest_is_order_independent() {
        let a: Digest<Certificate> = Digest::from([1u8; 32]);
        let b: Digest<Certificate> = Digest::from([2u8; 32]);
        let c: Digest<Certificate> = Digest::from([3u8; 32]);
        assert_eq!(set_digest([a, b, c]), set_digest([c, a, b]));
        assert_ne!(set_digest([a, b]), set_digest([a, b, c]));
    }
}
