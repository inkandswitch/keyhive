//! Conformance suite shared by every [`Keyline`] implementation.
//!
//! A backend is correct iff it agrees with the reference implementation on
//! every set. This module makes that checkable: [`scenarios`] are the named
//! cases from the design documents, [`laws`] are `bolero` properties over
//! generated sets, and [`gen`] produces the sets. Every scenario and law is a
//! plain function generic over a [`Backend`], which says how to build the
//! store and drive its futures, and talks to the store through a synchronous
//! [`Harness`]. A backend runs the whole suite with
//! [`keyline_conformance!`](crate::keyline_conformance), which writes one
//! `#[test]` per scenario and law:
//!
//! ```ignore
//! mod conformance {
//!     use future_form::Local;
//!     use keyline::test_utils::conformance::Polled;
//!
//!     keyline::keyline_conformance!(Polled<my_crate::MyKeyline<()>, Local>);
//! }
//! ```
//!
//! [`Polled`] suits a backend whose futures are ready on their first poll. A
//! backend that does real I/O implements [`Backend`] itself, with its own
//! executor in [`Backend::block_on`].

// The generator, oracles and `bolero` laws need `Arbitrary` and `bolero`
// (the `test_utils` feature, which implies `std`). The scenarios need only the
// `conformance` feature, so a backend can run them without `std`.
#[cfg(all(feature = "arbitrary", any(test, feature = "test_utils")))]
pub mod gen;
#[cfg(all(feature = "arbitrary", any(test, feature = "test_utils")))]
pub mod laws;
#[cfg(all(feature = "arbitrary", any(test, feature = "test_utils")))]
pub mod oracle;
pub mod scenarios;

use crate::{
    certificate::{Certificate, CertificateId, VerifiedCertificate},
    contract::{CertificateSet, Keyline, Query, Version},
    delegation::Delegation,
    power::Power,
    revocation::{Revocation, RevocationId},
    test_utils::{assume_verified, delegation, id, revocation, Issued, Statement},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{
    future::Future,
    marker::PhantomData,
    pin::pin,
    task::{Context, Poll, Waker},
};
use future_form::FutureForm;
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{digest::Digest, identifier::Identifier};

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

pub fn d(issuer: u8, audience: u8, subject: u8, power: Power) -> Issued<Delegation> {
    delegation(id(issuer), id(audience), id(subject), power)
}

pub fn r<W>(issuer: u8, target: &Issued<Delegation>) -> Issued<Revocation<W>> {
    revocation(id(issuer), target.digest())
}

/// What a backend's watermark type must satisfy to run the generated laws.
///
/// The scenarios need none of this, because they never look at
/// [`crate::revocation::Revocation::retain`]. The laws generate whole
/// certificate sets, so the watermark type has to be generatable and
/// comparable as well as encodable.
#[cfg(all(feature = "arbitrary", any(test, feature = "test_utils")))]
pub trait TestWatermark:
    'static + for<'a> arbitrary::Arbitrary<'a> + Clone + core::fmt::Debug + Eq + Ord + Encode + Decode
{
}

#[cfg(all(feature = "arbitrary", any(test, feature = "test_utils")))]
impl<
        T: 'static
            + for<'a> arbitrary::Arbitrary<'a>
            + Clone
            + core::fmt::Debug
            + Eq
            + Ord
            + Encode
            + Decode,
    > TestWatermark for T
{
}

/// How the suite builds a backend and drives its futures.
pub trait Backend {
    /// The future form the store is used at.
    type Form: FutureForm;

    /// The store's [`Keyline::RetentionWatermark`].
    type Watermark: Encode + Decode;

    /// The store under test.
    type Store: Keyline<Self::Form, RetentionWatermark = Self::Watermark> + Default;

    /// Run a future to completion.
    fn block_on<T, Fut: Future<Output = T>>(future: Fut) -> T;
}

/// A [`Backend`] for a store whose futures are ready on their first poll, as
/// an in-memory store's are when nothing else holds its lock. Needs no
/// executor, so it also runs without `std`.
pub struct Polled<K, F>(PhantomData<(K, F)>);

impl<K: Keyline<F> + Default, F: FutureForm> Backend for Polled<K, F> {
    type Form = F;
    type Watermark = K::RetentionWatermark;
    type Store = K;

    fn block_on<T, Fut: Future<Output = T>>(future: Fut) -> T {
        match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("a `Polled` backend's futures are ready on their first poll"),
        }
    }
}

/// A store driven synchronously, with every call checked against the
/// interface's version contract.
///
/// Each query must report the version the last insert returned (the suite
/// runs nothing concurrently), and an insert that adds a certificate must
/// return a greater version. Errors are failures: the suite's backends must
/// not fail.
pub struct Harness<C: Backend> {
    store: C::Store,
    version: Version,
}

impl<C: Backend> Default for Harness<C> {
    fn default() -> Self {
        let store = C::Store::default();
        let version = C::block_on(store.version()).expect("a conformance backend does not fail");
        Harness { store, version }
    }
}

impl<C: Backend> Harness<C> {
    /// The store under test.
    pub fn store(&self) -> &C::Store {
        &self.store
    }

    /// The version the last insert returned.
    pub fn version(&self) -> Version {
        self.version
    }

    fn answer<T>(&self, query: Query<'_, C::Form, T, <C::Store as Keyline<C::Form>>::Error>) -> T {
        let answer = C::block_on(query).expect("a conformance backend does not fail");
        assert_eq!(
            answer.version, self.version,
            "an answer reports the version of the set it read"
        );
        answer.value
    }

    /// Insert one certificate. Returns whether it was new.
    pub fn insert(&mut self, cert: VerifiedCertificate<C::Watermark>) -> bool {
        let new = !self.contains(&cert.id());
        self.insert_batch(&[cert]);
        new
    }

    /// Insert a batch, checking the version it returns.
    pub fn insert_batch(&mut self, batch: &[VerifiedCertificate<C::Watermark>]) -> Version {
        let grows = batch.iter().any(|c| !self.contains(&c.id()));
        let version = C::block_on(self.store.insert(batch.to_vec()))
            .expect("a conformance backend does not fail");
        if grows {
            assert!(
                version > self.version,
                "an insert that adds a certificate returns a greater version"
            );
        } else {
            assert!(version >= self.version, "versions never go back");
        }
        assert_eq!(
            C::block_on(self.store.version()).expect("a conformance backend does not fail"),
            version,
            "`version` reports what the last insert returned"
        );
        self.version = version;
        version
    }

    pub fn contains(&self, cert: &CertificateId) -> bool {
        self.answer(self.store.contains(*cert))
    }

    pub fn get(&self, cert: &CertificateId) -> Option<Certificate<C::Watermark>> {
        self.answer(self.store.get(*cert))
    }

    pub fn certificates(&self) -> Vec<Certificate<C::Watermark>> {
        self.answer(self.store.certificates())
    }

    pub fn revocations_of(
        &self,
        delegation: &Digest<Delegation>,
    ) -> BTreeSet<Digest<RevocationId>> {
        self.answer(self.store.revocations_of(*delegation))
    }

    pub fn delegations_to(
        &self,
        subject: Identifier,
        audience: Identifier,
    ) -> BTreeMap<Digest<Delegation>, (Identifier, Delegation)> {
        self.answer(self.store.delegations_to(subject, audience))
    }

    pub fn effective_power(&self, subject: Identifier, audience: Identifier) -> Option<Power> {
        self.answer(self.store.effective_power(subject, audience))
    }

    pub fn members(&self, subject: Identifier) -> BTreeMap<Identifier, Power> {
        self.answer(self.store.members(subject))
    }

    pub fn members_for_subset(
        &self,
        subset: BTreeSet<CertificateId>,
        subject: Identifier,
    ) -> BTreeMap<Identifier, Power> {
        self.answer(self.store.members_for_subset(subset, subject))
    }

    pub fn subjects(&self) -> BTreeSet<Identifier> {
        self.answer(self.store.subjects())
    }

    pub fn is_live(&self, delegation: &Digest<Delegation>) -> bool {
        self.answer(self.store.is_live(*delegation))
    }

    pub fn conveyed_power(&self, delegation: &Digest<Delegation>) -> Option<Power> {
        self.answer(self.store.conveyed_power(*delegation))
    }

    pub fn positive_power(&self, subject: Identifier, audience: Identifier) -> Option<Power> {
        self.answer(self.store.positive_power(subject, audience))
    }

    pub fn closure(&self, subject: Identifier) -> Vec<Certificate<C::Watermark>> {
        self.answer(self.store.closure(subject))
    }

    pub fn digest(&self) -> Digest<CertificateSet> {
        self.answer(self.store.digest())
    }
}

/// A backend holding exactly these certificates, inserted one at a time.
/// Checks that each insert reports whether its certificate was new.
pub fn build<C: Backend, I: IntoIterator<Item = Statement<C::Watermark>>>(certs: I) -> Harness<C> {
    let mut k = Harness::<C>::default();
    let mut seen = BTreeSet::new();
    for c in certs {
        let c = assume_verified(c);
        let new = seen.insert(c.id());
        assert_eq!(
            k.insert(c),
            new,
            "insert reports whether the certificate is new"
        );
    }
    k
}

pub fn power<C: Backend>(k: &Harness<C>, subject: u8, audience: u8) -> Option<Power> {
    k.effective_power(id(subject), id(audience))
}

/// One `#[test]` per conformance scenario and law, for the given backend.
///
/// Invoke it inside its own module, since the tests take the scenarios'
/// names. The argument is a [`Backend`]. The scenario
/// `retain_distinguishes_certificates_not_authority` also needs
/// `Watermark: Clone + Default`, and the laws need [`TestWatermark`].
#[macro_export]
macro_rules! keyline_conformance {
    ($backend:ty) => {
        $crate::keyline_conformance!(@each $backend, scenarios:
            empty_graph,
            attenuation_and_widest_path,
            ungrounded_edges_are_dead,
            membership_composes,
            late_binding_grants_new_documents_to_members,
            issuer_revocation_is_total,
            audience_revocation_without_admin_reach_is_total,
            admin_reach_covers_a_transited_node,
            non_admin_revocation_is_confined_to_own_node,
            ex_admin_reach_is_frozen,
            mutual_revocations_both_take_effect,
            root_role_admin_can_revoke_the_root_edge,
            edit_rooted_root_edge_is_irrevocable,
            root_role_duel_kills_creation_memberships_even_when_edit_rooted,
            senior_role_admin_revokes_inside_junior_role,
            supply_is_daisy_chained,
            covered_edges_are_clamped_not_just_gated,
            mutually_covered_edges_cannot_lift_each_other,
            second_signature_is_the_same_certificate,
            retain_distinguishes_certificates_not_authority,
            revocation_may_arrive_before_its_target,
            insert_is_idempotent_and_reports_duplicates,
            reissue_with_citation_heals,
            rotation_escapes_frozen_reach,
            unknown_revocation_is_inert,
            gift_cert_attack_follows_liveness,
            steward_rotation_leaves_former_officers_nothing,
            role_admin_cannot_revoke_the_supply_into_the_role,
            revocations_of_one_delegation_cover_jointly,
            pinned_delegation_answers_to_the_role,
            caretaker_admin_severs_downstream_but_not_the_supply,
            signed_certificates_agree_with_fixtures,
            closure_holds_what_a_document_needs,
            delegations_to_lists_dead_delegations_too,
        );
        $crate::__keyline_conformance_laws!($backend);
    };
    (@each $backend:ty, $module:ident: $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                $crate::test_utils::conformance::$module::$name::<$backend>();
            }
        )*
    };
}

/// The law half of [`keyline_conformance!`](crate::keyline_conformance).
/// The laws need `test_utils`; with only `conformance`, the scenarios run alone.
#[cfg(all(feature = "arbitrary", any(test, feature = "test_utils")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __keyline_conformance_laws {
    ($backend:ty) => {
        $crate::keyline_conformance!(@each $backend, laws:
            matches_naive_oracle_without_revocations,
            matches_naive_oracle_with_revocations,
            matches_threshold_oracle,
            order_independent,
            idempotent,
            revocations_only_deny,
            party_revocation_is_total,
            retain_is_inert,
            digest_identifies_the_set,
            queries_are_consistent,
            conveyed_power_is_what_a_delegation_contributes,
            positive_power_matches_stratum_one,
            positive_power_is_monotone,
            listings_match_the_set,
            closure_is_sufficient,
            members_for_subset_answers_as_the_subset,
            batches_equal_singles,
            interleaving_is_invisible,
        );
    };
}

#[cfg(not(all(feature = "arbitrary", any(test, feature = "test_utils"))))]
#[doc(hidden)]
#[macro_export]
macro_rules! __keyline_conformance_laws {
    ($backend:ty) => {};
}

#[cfg(test)]
mod tests {
    /// Every public scenario and law is listed in [`keyline_conformance!`].
    /// One that is not still compiles, and then never runs for any backend.
    #[test]
    fn macro_lists_every_scenario_and_law() {
        let listed = include_str!("conformance.rs");
        let sources = [
            (include_str!("conformance/scenarios.rs"), "standard"),
            (include_str!("conformance/laws.rs"), "observe"),
        ];
        for (source, helper) in sources {
            let names = source
                .lines()
                .filter_map(|line| line.trim_start().strip_prefix("pub fn "))
                .filter_map(|rest| rest.split(['<', '(']).next())
                .filter(|name| *name != helper);
            for name in names {
                assert!(
                    listed.contains(&alloc::format!("            {name},\n")),
                    "{name} is missing from keyline_conformance!"
                );
            }
        }
    }
}
