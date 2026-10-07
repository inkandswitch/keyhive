//! The [`Keyline`] trait: the backend contract.
//!
//! Every method is defined purely in terms of the certificate set, so an
//! implementation over any store (in memory, DBSP, a database) is correct if and
//! only if it agrees with the reference backend, `keyline_memory::MemoryKeyline`,
//! on every set. The conformance suite behind the `conformance` and
//! `test_utils` features is how a backend checks that.

use crate::{
    certificate::{CertificateId, VerifiedCertificate},
    delegation::Delegation,
    id::Id,
    power::Power,
    revocation::RevocationId,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{digest::Digest, domain_separator::Domain};

/// A set of certificates and the authority they imply.
///
/// Queries are `&self` and inserts are `&mut self`; the trait is synchronous.
/// Concurrency is the wrapper's job: hold an implementation behind a
/// `RwLock`, and readers call `&self` methods in parallel.
pub trait Keyline {
    /// The per-subject bound a revocation may carry in
    /// [`crate::revocation::Revocation::retain`]: which of the removed key's
    /// content to keep, such as a set of content heads.
    ///
    /// Evaluation never reads it; the bound exists only so certificates
    /// round-trip canonically. A backend that does not care picks `()`.
    type RetentionWatermark: Encode + Decode;

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
    fn insert(&mut self, cert: VerifiedCertificate<Self::RetentionWatermark>) -> bool;

    /// Whether a certificate with this identity is in the set.
    ///
    /// Call this before `Certificate::verify`: `Certificate::id` is far
    /// cheaper than a signature check.
    fn contains(&self, cert: &CertificateId) -> bool;

    /// Revocations in the set that name this delegation, covering or not.
    ///
    /// Whether a revocation actually covers the delegation depends on the
    /// issuer's admin reach; this reports the syntactic fact. Its main use
    /// is explaining a silent collision: an issuer who re-mints a delegation
    /// byte-identical to a revoked one gets `insert == false`, and this tells
    /// them why and that a re-issue with `citation` is needed.
    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<RevocationId>>;

    /// `audience`'s effective power over `subject`: the maximum over live routes of the
    /// minimum along each. `None` if no live route exists.
    ///
    /// Every subject stands at `Admin` over itself by axiom, so
    /// `effective_power(x, x)` is `Some(Admin)` for every `x`.
    fn effective_power(&self, subject: Id, audience: Id) -> Option<Power>;

    /// Every `Id` other than `subject` itself with a live route to `subject`, with its
    /// effective power. The materialized view.
    fn members(&self, subject: Id) -> BTreeMap<Id, Power>;

    /// Whether the named delegation participates in any live derivation.
    /// `false` for digests not in the set.
    fn is_live(&self, cert: &Digest<Delegation>) -> bool;

    /// A digest of the whole set. Same set (in any order), same digest; usable
    /// as a cache key for every other query. Backends compute it with
    /// [`set_digest`].
    fn digest(&self) -> Digest<CertificateSet<Self::RetentionWatermark>>;
}

/// What a [`Keyline::digest`] is the digest of: a set of certificates, by
/// their identities.
///
/// Only ever a phantom parameter of [`Digest`]; it has no values. A distinct
/// type keeps a set digest from being mistaken for a certificate's.
pub struct CertificateSet<W> {
    _never: core::convert::Infallible,
    _watermark: core::marker::PhantomData<fn() -> W>,
}

impl<W> Domain for CertificateSet<W> {
    const CONTEXT: &'static str = "keyline/v0/set";
}

/// Digest a certificate set from its members' identities, in any order and
/// with any repetition.
///
/// BLAKE3, under [`CertificateSet`]'s domain context, over the sorted and
/// deduplicated digests, so the result depends only on the set. Delegation
/// and revocation digests are domain-separated, so they never collide and
/// need no kind tag here.
pub fn set_digest<W, I: IntoIterator<Item = CertificateId>>(ids: I) -> Digest<CertificateSet<W>> {
    let mut sorted: Vec<[u8; Digest::<Delegation>::LEN]> = ids
        .into_iter()
        .map(|id| {
            id.as_slice()
                .try_into()
                .expect("every digest is Digest::LEN bytes")
        })
        .collect();
    sorted.sort_unstable();
    sorted.dedup();
    Digest::of_bytes(sorted.as_flattened())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> [CertificateId; 3] {
        [
            CertificateId::Delegation(Digest::from([1u8; 32])),
            CertificateId::Revocation(Digest::from([2u8; 32])),
            CertificateId::Delegation(Digest::from([3u8; 32])),
        ]
    }

    #[test]
    fn set_digest_is_order_independent() {
        let [a, b, c] = ids();
        assert_eq!(
            set_digest::<(), _>([a, b, c]),
            set_digest::<(), _>([c, a, b])
        );
        assert_ne!(set_digest::<(), _>([a, b]), set_digest::<(), _>([a, b, c]));
    }

    #[test]
    fn set_digest_ignores_repetition() {
        let [a, b, _] = ids();
        assert_eq!(
            set_digest::<(), _>([a, b, a, a]),
            set_digest::<(), _>([b, a])
        );
    }
}
