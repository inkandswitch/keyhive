//! [`MemoryKeyline`]: the in-memory reference implementation of [`Keyline`].
//!
//! Two layers. [`State`] is the certificate set and a synchronous evaluator:
//! inserts take `&mut self`, queries take `&self`, and there is no async and
//! no lock. [`MemoryKeyline`] puts it behind one `async_lock::RwLock` and
//! implements the async [`Keyline`] trait: queries hold the read lock for
//! their whole evaluation, so they run concurrently, and inserts mutate in
//! place under the write lock.
//!
//! The lock is a leaf: it is taken and released inside each method, held
//! only for straight-line work, and never handed to a caller, so it cannot
//! deadlock. `async-lock`'s `RwLock` is write-preferring, so a stream of
//! queries cannot starve an insert. Every future resolves on its first poll
//! unless another task holds the lock.
//!
//! The evaluation is cached in [`State`] and shared by every query until the
//! next insert that changes the set; see the [`state`] module for the
//! evaluation program.
//!
//! # `no_std` support
//!
//! `no_std` with `alloc`. The `std` feature (default) switches the evaluator's
//! maps to `HashMap`/`HashSet`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod collections;
pub mod state;

use crate::state::State;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use async_lock::RwLock;
use core::convert::Infallible;
use future_form::{future_form, FutureForm, Local, Sendable};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{digest::Digest, id::Id};
use keyline::{
    certificate::{Certificate, CertificateId, VerifiedCertificate},
    contract::{CertificateSet, Keyline, Query, Version, Versioned},
    delegation::Delegation,
    power::Power,
    revocation::RevocationId,
};

/// The in-memory reference [`Keyline`]: a [`State`] behind an `RwLock`.
#[derive(Debug)]
pub struct MemoryKeyline<W> {
    state: RwLock<State<W>>,
}

impl<W> MemoryKeyline<W> {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The set and evaluator inside.
    pub fn into_state(self) -> State<W> {
        self.state.into_inner()
    }

    /// Read the state and answer with the version it was read at.
    async fn read<T, G: FnOnce(&State<W>) -> T>(
        &self,
        query: G,
    ) -> Result<Versioned<T>, Infallible> {
        let state = self.state.read().await;
        Ok(Versioned {
            version: state.version(),
            value: query(&state),
        })
    }
}

// Manual: the derive would add a spurious `W: Default` bound.
impl<W> Default for MemoryKeyline<W> {
    fn default() -> Self {
        State::default().into()
    }
}

impl<W> From<State<W>> for MemoryKeyline<W> {
    fn from(state: State<W>) -> Self {
        MemoryKeyline {
            state: RwLock::new(state),
        }
    }
}

#[future_form(Sendable where W: Send + Sync, Local)]
impl<F: FutureForm, W: Encode + Decode> Keyline<F> for MemoryKeyline<W> {
    type RetentionWatermark = W;
    type Error = Infallible;

    fn version(&self) -> F::Future<'_, Result<Version, Infallible>> {
        F::from_future(async move { Ok(self.state.read().await.version()) })
    }

    fn insert(
        &self,
        batch: Vec<VerifiedCertificate<W>>,
    ) -> F::Future<'_, Result<Version, Infallible>> {
        F::from_future(async move { Ok(self.state.write().await.insert_all(batch)) })
    }

    fn contains(&self, cert: CertificateId) -> Query<'_, F, bool, Infallible> {
        F::from_future(self.read(move |s| s.contains(&cert)))
    }

    fn get(&self, cert: CertificateId) -> Query<'_, F, Option<Certificate<W>>, Infallible> {
        F::from_future(self.read(move |s| s.get(&cert)))
    }

    fn certificates(&self) -> Query<'_, F, Vec<Certificate<W>>, Infallible> {
        F::from_future(self.read(State::certificates))
    }

    fn revocations_of(
        &self,
        delegation: Digest<Delegation>,
    ) -> Query<'_, F, BTreeSet<Digest<RevocationId>>, Infallible> {
        F::from_future(self.read(move |s| s.revocations_of(&delegation)))
    }

    fn delegations_to(
        &self,
        subject: Id,
        audience: Id,
    ) -> Query<'_, F, BTreeMap<Digest<Delegation>, Delegation>, Infallible> {
        F::from_future(self.read(move |s| s.delegations_to(subject, audience)))
    }

    fn effective_power(
        &self,
        subject: Id,
        audience: Id,
    ) -> Query<'_, F, Option<Power>, Infallible> {
        F::from_future(self.read(move |s| s.effective_power(subject, audience)))
    }

    fn members(&self, subject: Id) -> Query<'_, F, BTreeMap<Id, Power>, Infallible> {
        F::from_future(self.read(move |s| s.members(subject)))
    }

    fn subjects(&self) -> Query<'_, F, BTreeSet<Id>, Infallible> {
        F::from_future(self.read(State::subjects))
    }

    fn is_live(&self, delegation: Digest<Delegation>) -> Query<'_, F, bool, Infallible> {
        F::from_future(self.read(move |s| s.is_live(&delegation)))
    }

    fn positive_power(&self, subject: Id, audience: Id) -> Query<'_, F, Option<Power>, Infallible> {
        F::from_future(self.read(move |s| s.positive_power(subject, audience)))
    }

    fn closure(&self, subject: Id) -> Query<'_, F, Vec<Certificate<W>>, Infallible> {
        F::from_future(self.read(move |s| s.closure(subject)))
    }

    fn digest(&self) -> Query<'_, F, Digest<CertificateSet>, Infallible> {
        F::from_future(self.read(State::digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyline::{
        revocation::Revocation,
        test_utils::{
            assume_verified,
            conformance::{d, Polled, ALICE, CAROL, DOC, MEMBERS, OWNERS},
        },
    };

    #[cfg(feature = "test_utils")]
    use keyline::test_utils::conformance::laws;

    mod local {
        use super::*;
        keyline::keyline_conformance!(Polled<MemoryKeyline<()>, Local>);
    }

    mod sendable {
        use super::*;
        keyline::keyline_conformance!(Polled<MemoryKeyline<()>, Sendable>);
    }

    /// A watermark type with a variable-length encoding.
    ///
    /// At `W = ()` a `retain` entry carries a subject and an empty watermark,
    /// so the laws above never see watermark bytes. The tests below re-run
    /// the laws about `retain` with watermarks that carry bytes.
    #[cfg(feature = "test_utils")]
    type Watermark = Vec<u8>;

    #[cfg(feature = "test_utils")]
    type WithBytes = Polled<MemoryKeyline<Watermark>, Local>;

    /// Both oracles keep only `(issuer, revoke)`, so neither can read a
    /// watermark; agreement with watermark bytes present checks that
    /// `MemoryKeyline` ignores them too.
    #[cfg(feature = "test_utils")]
    #[test]
    fn matches_naive_oracle_with_watermark_bytes() {
        laws::matches_naive_oracle_with_revocations::<WithBytes>();
    }

    #[cfg(feature = "test_utils")]
    #[test]
    fn matches_threshold_oracle_with_watermark_bytes() {
        laws::matches_threshold_oracle::<WithBytes>();
    }

    #[cfg(feature = "test_utils")]
    #[test]
    fn retain_with_bytes_is_inert() {
        laws::retain_is_inert::<WithBytes>();
    }

    #[test]
    fn state_accessors() {
        assert!(State::<()>::new().is_empty());

        let root = d(DOC, OWNERS, DOC, Power::Admin);
        let alice_member = d(CAROL, ALICE, MEMBERS, Power::Admin);
        let mut state = State::<()>::new();
        assert_eq!(state.version(), Version::INITIAL);
        let v = state.insert_all([root, alice_member].map(assume_verified));
        assert_eq!(state.len(), 2);
        assert!(!state.is_empty());
        assert_eq!(
            state.delegation(&root.digest()).map(|v| v.payload()),
            Some(&root)
        );
        assert!(state.get(&root.digest().into()).is_some());
        assert!(state.revocation(&Digest::from([0u8; 32])).is_none());

        // A batch of duplicates leaves the version, and so the cache, alone.
        assert_eq!(state.insert_all([assume_verified(root)]), v);
        assert!(!state.insert(assume_verified(root)));

        let revocation: Revocation<()> =
            Revocation::new(alice_member.issuer, alice_member.digest());
        assert!(state.insert(assume_verified(revocation.clone())));
        assert!(state.version() > v);
        assert_eq!(
            state.revocation(&revocation.digest()).map(|v| v.payload()),
            Some(&revocation)
        );

        let keyline: MemoryKeyline<()> = state.clone().into();
        assert_eq!(keyline.into_state().digest(), state.digest());
    }
}
