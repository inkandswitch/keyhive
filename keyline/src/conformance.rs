//! Conformance suite shared by every [`Keyline`] implementation.
//!
//! A backend is correct iff it agrees with the reference implementation on
//! every set. This module makes that checkable: [`scenarios`] are the named
//! cases from the design documents, [`laws`] are `bolero` properties over
//! generated sets, and [`gen`] produces the sets. Run the whole suite against
//! a backend with one line:
//!
//! ```ignore
//! keyline::keyline_conformance!(MyBackend);
//! ```
//!
//! which expands to one `#[test]` per scenario and per law.

pub mod gen;
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

/// Instantiate every scenario and law as a `#[test]` for a backend.
///
/// Internal rule: `@tests` takes the backend and the module paths, so the list
/// of test names lives in one place.
#[macro_export]
macro_rules! keyline_conformance {
    ($backend:ty) => {
        mod keyline_conformance {
            #[allow(unused_imports)]
            use super::*;

            $crate::keyline_conformance!(@scenarios $backend;
                empty_graph,
                attenuation_and_widest_path,
                ungrounded_edges_are_dead,
                membership_composes,
                late_binding_grants_new_documents_to_members,
                retraction_is_total,
                renunciation_is_total,
                admin_over_a_transited_node_cuts_deep,
                non_admin_cut_is_confined_to_own_node,
                ex_admin_reach_is_frozen,
                mutual_revocation_leaves_both_cuts_standing,
                apex_admin_can_deny_the_root_edge,
                edit_rooted_root_edge_is_undeniable,
                senior_role_admin_cuts_inside_junior_role,
                supply_is_daisy_chained,
                covered_edges_are_clamped_not_just_gated,
                revocation_may_arrive_before_its_target,
                insert_is_idempotent_and_reports_duplicates,
                reissue_with_seen_heals,
                unknown_revocation_is_inert,
            );

            $crate::keyline_conformance!(@laws $backend;
                matches_naive_oracle_without_revocations,
                order_independent,
                idempotent,
                revocations_only_deny,
                digest_identifies_the_set,
                queries_are_consistent,
            );
        }
    };

    (@scenarios $backend:ty; $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                $crate::conformance::scenarios::$name::<$backend>();
            }
        )*
    };

    (@laws $backend:ty; $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                $crate::conformance::laws::$name::<$backend>();
            }
        )*
    };
}
