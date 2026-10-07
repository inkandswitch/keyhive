//! Conformance suite shared by every [`Keyline`] implementation.
//!
//! A backend is correct iff it agrees with the reference implementation on
//! every set. This module makes that checkable: [`scenarios`] are the named
//! cases from the design documents, [`laws`] are `bolero` properties over
//! generated sets, and [`gen`] produces the sets. Every scenario and law is a
//! plain function generic over `K: Keyline + Default`. A backend runs the whole
//! suite with [`keyline_conformance!`](crate::keyline_conformance), which
//! writes one `#[test]` per scenario and law:
//!
//! ```ignore
//! mod conformance {
//!     keyline::keyline_conformance!(my_crate::MyKeyline);
//! }
//! ```

// The generator and the `bolero` laws need `Arbitrary`, which needs `std`;
// the scenarios need nothing beyond the crate, so `cargo test` runs them.
#[cfg(feature = "arbitrary")]
pub mod gen;
#[cfg(feature = "arbitrary")]
pub mod laws;
#[cfg(feature = "arbitrary")]
pub mod oracle;
pub mod scenarios;

use crate::{
    certificate::Certificate,
    contract::Keyline,
    delegation::Delegation,
    power::Power,
    revocation::Revocation,
    test_utils::{cert, id},
};
use alloc::collections::BTreeSet;
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

pub fn r<W>(issuer: u8, target: &Delegation) -> Revocation<W> {
    Revocation::new(id(issuer), target.digest())
}

/// What a backend's watermark type must satisfy to run the generated laws.
///
/// The scenarios need none of this, because they never look at
/// [`crate::revocation::Revocation::retain`]. The laws generate whole
/// certificate sets, so the watermark type has to be generatable and
/// comparable as well as encodable.
pub trait TestWatermark:
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
    > TestWatermark for T
{
}

/// A backend holding exactly these certificates. Checks that each `insert`
/// reports whether its certificate was new.
pub fn build<K: Keyline + Default, I: IntoIterator<Item = Certificate<K::RetentionWatermark>>>(
    certs: I,
) -> K {
    let mut k = K::default();
    let mut seen = BTreeSet::new();
    for c in certs {
        let c = cert(c);
        let new = seen.insert(c.digest());
        assert_eq!(
            k.insert(c),
            new,
            "insert reports whether the certificate is new"
        );
    }
    k
}

pub fn power<K: Keyline>(k: &K, subject: u8, audience: u8) -> Option<Power> {
    k.effective_power(id(subject), id(audience))
}

/// One `#[test]` per conformance scenario and law, for the given backend.
///
/// Invoke it inside its own module, since the tests take the scenarios'
/// names. The backend must be `Keyline + Default`. The scenario
/// `retain_distinguishes_certificates_not_authority` also needs
/// `RetentionWatermark: Clone + Default`, and the laws need
/// [`TestWatermark`].
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
            audience_revocation_is_total,
            audience_revocation_without_admin_reach_is_total,
            admin_reach_covers_a_transited_node,
            non_admin_revocation_is_confined_to_own_node,
            ex_admin_reach_is_frozen,
            mutual_revocations_both_stand,
            apex_admin_can_revoke_the_root_edge,
            edit_rooted_root_edge_is_irrevocable,
            apex_duel_kills_creation_memberships_even_when_edit_rooted,
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
            signed_certificates_agree_with_fixtures,
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
/// The laws need `arbitrary`, which `test_utils` enables; this crate's own
/// `cfg(test)` build may lack it.
#[cfg(feature = "arbitrary")]
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
        );
    };
}

#[cfg(not(feature = "arbitrary"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __keyline_conformance_laws {
    ($backend:ty) => {};
}
