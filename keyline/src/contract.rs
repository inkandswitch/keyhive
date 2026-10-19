//! The [`Keyline`] trait: the backend contract.
//!
//! Every query is defined purely in terms of the certificate set, so an
//! implementation over any store (in memory, DBSP, a database) is correct if and
//! only if it agrees with the reference backend, `keyline_memory::MemoryKeyline`,
//! on every set. The conformance suite behind the `conformance` and
//! `test_utils` features is how a backend checks that.
//!
//! # Why async, fallible, and versioned
//!
//! The trait is shaped for backends that are not in memory. A database answers
//! with I/O, so every method returns a future. Connections drop and
//! transactions abort, so every method returns a `Result`. Sync and archive
//! loading arrive in batches, and an incremental engine wants them whole, so
//! [`Keyline::insert`] takes a batch and applies it atomically.
//!
//! Each query is atomic on its own and returns the [`Version`] of the set it
//! read, in a [`Versioned`]. There are no views: no lock or transaction ever
//! leaves the store, so callers have no rules to follow to avoid deadlocks.
//! Combining answers from adjacent versions is safe wherever the questions
//! are monotone (the positive queries) or the set only grows (closures).
//! The version comes back with the answer, rather than from a separate call,
//! so that a cache can never stamp an old answer as fresh.

use crate::{
    certificate::{Certificate, CertificateId, VerifiedCertificate},
    delegation::Delegation,
    power::Power,
    revocation::RevocationId,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use future_form::FutureForm;
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{
    digest::Digest,
    id::Id,
    signable::{Kind, Kinded},
};

/// A set of certificates and the authority they imply, behind whatever
/// concurrency control its backend uses.
///
/// Every method takes `&self`: a backend owns its concurrency control, as a
/// database has transactions and the in-memory backend has a lock.
pub trait Keyline<F: FutureForm> {
    /// The per-subject bound a revocation may carry in
    /// [`crate::revocation::Revocation::retain`]: which of the removed key's
    /// content to keep, such as a set of content heads.
    ///
    /// Evaluation never reads it; the bound exists only so certificates
    /// round-trip canonically. A backend that does not care picks `()`.
    ///
    /// Its `decode` runs on unauthenticated bytes: [`Certificate::verify`]
    /// decodes before it checks the signature. It must reject non-canonical
    /// input, never panic, and allocate no more than its input length
    /// warrants.
    type RetentionWatermark: Encode + Decode;

    /// What a backend's storage can fail with. `Infallible` in memory.
    type Error: core::error::Error;

    /// The current version of the set.
    ///
    /// For cheap staleness checks. To pair a version with an answer, use the
    /// version the query returned instead.
    fn version(&self) -> F::Future<'_, Result<Version, Self::Error>>;

    /// Add a batch of certificates to the set, atomically: no query observes
    /// part of a batch. Returns the version after the insert.
    ///
    /// Idempotent, and insertion order never matters. If the batch added a
    /// certificate, the returned version is greater than every version read
    /// before the call; if it added none, the version may stay the same.
    ///
    /// A revocation whose target is not (yet) in the set is stored like any
    /// other certificate; it contributes nothing until the target arrives.
    ///
    /// The set growing does not mean an answer changed: a new certificate may
    /// be dead on arrival. Callers driving key rotation must diff
    /// [`Keyline::members`].
    fn insert(
        &self,
        batch: Vec<VerifiedCertificate<Self::RetentionWatermark>>,
    ) -> F::Future<'_, Result<Version, Self::Error>>;

    /// Whether a certificate with this identity is in the set.
    ///
    /// Call this before `Certificate::verify`: `Certificate::id` is far
    /// cheaper than a signature check.
    fn contains(&self, cert: CertificateId) -> Query<'_, F, bool, Self::Error>;

    /// The certificate with this identity, as received.
    fn get(
        &self,
        cert: CertificateId,
    ) -> Query<'_, F, Option<Certificate<Self::RetentionWatermark>>, Self::Error>;

    /// Every certificate in the set, in [`CertificateId`] order.
    fn certificates(&self)
        -> Query<'_, F, Vec<Certificate<Self::RetentionWatermark>>, Self::Error>;

    /// Revocations in the set that name this delegation, covering or not.
    ///
    /// Whether a revocation actually covers the delegation depends on the
    /// issuer's admin reach; this reports the syntactic fact. Its main use
    /// is explaining a silent collision: an issuer who re-mints a delegation
    /// byte-identical to a revoked one finds it already present, and this
    /// tells them why and that a re-issue with `citation` is needed.
    fn revocations_of(
        &self,
        delegation: Digest<Delegation>,
    ) -> Query<'_, F, BTreeSet<Digest<RevocationId>>, Self::Error>;

    /// Every delegation in the set from `subject` to `audience`, live or not,
    /// each with its issuer: what revoking `audience`'s access must name.
    #[allow(clippy::type_complexity)]
    fn delegations_to(
        &self,
        subject: Id,
        audience: Id,
    ) -> Query<'_, F, BTreeMap<Digest<Delegation>, (Id, Delegation)>, Self::Error>;

    /// `audience`'s effective power over `subject`: the maximum over live
    /// routes of the minimum along each. `None` if no live route exists.
    ///
    /// Every subject stands at `Admin` over itself by axiom, so
    /// `effective_power(x, x)` is `Some(Admin)` for every `x`.
    fn effective_power(
        &self,
        subject: Id,
        audience: Id,
    ) -> Query<'_, F, Option<Power>, Self::Error>;

    /// Every `Id` other than `subject` itself with a live route to `subject`,
    /// with its effective power.
    fn members(&self, subject: Id) -> Query<'_, F, BTreeMap<Id, Power>, Self::Error>;

    /// [`Keyline::members`] over only the certificates of `subset` that the
    /// background set contains. Identities the background set does not contain
    /// are ignored.
    fn members_for_subset(
        &self,
        subset: BTreeSet<CertificateId>,
        subject: Id,
    ) -> Query<'_, F, BTreeMap<Id, Power>, Self::Error>;

    /// The subject of every delegation in the set, live or not: everything
    /// the set says something about. Monotone in the set.
    fn subjects(&self) -> Query<'_, F, BTreeSet<Id>, Self::Error>;

    /// Whether `delegation` is live: its issuer has standing over its subject
    /// on a derivation that avoids every node its revocations cover, and its
    /// audience has not revoked it. `false` for digests not in the set.
    fn is_live(&self, delegation: Digest<Delegation>) -> Query<'_, F, bool, Self::Error>;

    /// `audience`'s power over `subject` in the positive graph: as
    /// [`Keyline::effective_power`], but with every revocation ignored.
    ///
    /// Monotone in the set: adding certificates never lowers it, so a `Some`
    /// read at one version holds at every later one. That makes it usable in
    /// decisions that must not be undone, such as authorizing an operation in
    /// another protocol, but not sufficient for one on its own: it ignores
    /// every revocation, so a revoked principal keeps its positive power
    /// forever. Such a check needs something more to stand for "still
    /// authorized".
    fn positive_power(&self, subject: Id, audience: Id)
        -> Query<'_, F, Option<Power>, Self::Error>;

    /// The closure of `subject`: every node with standing over `subject` in
    /// the positive graph (including `subject`), every delegation about those
    /// nodes, and every revocation naming one of those delegations, in
    /// [`CertificateId`] order.
    ///
    /// No certificate outside it can change any answer about `subject`, so it
    /// is what a replica interested in `subject` must hold, and what sync
    /// sends. It only grows as the set does.
    fn closure(
        &self,
        subject: Id,
    ) -> Query<'_, F, Vec<Certificate<Self::RetentionWatermark>>, Self::Error>;

    /// A digest of the whole set. Same set (in any order), same digest.
    /// Backends compute it with [`set_digest`]. It identifies the set across
    /// replicas; a [`Version`] identifies it only within one store.
    fn digest(&self) -> Query<'_, F, Digest<CertificateSet>, Self::Error>;
}

/// What every [`Keyline`] query returns: a future of the answer and the
/// version it was read at.
pub type Query<'a, F, T, E> = <F as FutureForm>::Future<'a, Result<Versioned<T>, E>>;

/// A version of one store's set: local to that store, opaque, and monotone.
///
/// Two answers from one store with the same version were read from the same
/// set. Versions from different stores are not comparable; use
/// [`Keyline::digest`] to compare sets across replicas.
///
/// A newtype over `u64`, because every backend has one at hand: a write
/// counter in memory, a log position in a database, a step in an incremental
/// engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u64);

impl Version {
    /// The version of a store that has never been written.
    pub const INITIAL: Version = Version(0);

    /// A version from a backend's own counter.
    pub const fn new(counter: u64) -> Self {
        Version(counter)
    }

    /// The version after this one.
    ///
    /// # Panics
    ///
    /// After `u64::MAX` writes, which no store reaches.
    #[must_use]
    pub fn next(self) -> Self {
        Version(
            self.0
                .checked_add(1)
                .expect("a store makes fewer than 2^64 writes"),
        )
    }
}

/// An answer and the version of the set it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Versioned<T> {
    pub version: Version,
    pub value: T,
}

impl<T> Versioned<T> {
    /// Apply `f` to the value, keeping the version.
    pub fn map<U, G: FnOnce(T) -> U>(self, f: G) -> Versioned<U> {
        Versioned {
            version: self.version,
            value: f(self.value),
        }
    }
}

/// What a [`Keyline::digest`] is the digest of: a set of certificates, by
/// their identities.
///
/// Only ever a phantom parameter of [`Digest`]; it has no values. A distinct
/// type keeps a set digest from being mistaken for a certificate's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateSet {}

impl Kinded for CertificateSet {
    const KIND: Kind = Kind::CERTIFICATE_SET;
    const VERSION: u8 = 0;
}

/// Digest a certificate set from its members' identities, in any order and
/// with any repetition.
///
/// BLAKE3, under [`CertificateSet`]'s kind, over the sorted and deduplicated
/// digests, so the result depends only on the set. Delegation and revocation
/// digests cover their kinds, so they never collide and need no tag here.
pub fn set_digest<I: IntoIterator<Item = CertificateId>>(ids: I) -> Digest<CertificateSet> {
    let mut sorted: Vec<[u8; Digest::<Delegation>::LEN]> =
        ids.into_iter().map(|id| id.to_bytes()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    Digest::of_bytes(sorted.as_flattened())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

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
        assert_eq!(set_digest([a, b, c]), set_digest([c, a, b]));
        assert_ne!(set_digest([a, b]), set_digest([a, b, c]));
    }

    /// Pins the set digest of fixed ids: the tag, kind and version, the sort,
    /// and the concatenation. Changing any of them must change this test on purpose.
    #[test]
    fn set_digest_known_answer() {
        let hex: String = set_digest(ids())
            .as_slice()
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(hex, SET_KNOWN_DIGEST);
    }

    const SET_KNOWN_DIGEST: &str =
        "bc00e6b141f8c293210bca3b8fd96d5994389b59f9bf6bf8e7859f229a370916";

    #[test]
    fn set_digest_ignores_repetition() {
        let [a, b, _] = ids();
        assert_eq!(set_digest([a, b, a, a]), set_digest([a, b]));
    }

    #[test]
    fn versions_are_ordered_by_counter() {
        assert!(Version::INITIAL < Version::INITIAL.next());
        assert_eq!(Version::new(3).next(), Version::new(4));
    }
}
