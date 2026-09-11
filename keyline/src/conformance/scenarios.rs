//! Named scenarios from `design/keyline/{README,edge-cases}.md`, each a
//! function generic over the backend. Every one MUST pass on every `Keyline`.
//!
//! The cast: `DOC` is a document; `OWNERS` and `MEMBERS` are roles; `MODS` is a
//! role in the clamping example; the rest are people.

use super::{
    access, build, d, r, ALICE, BOB, CAROL, DAN, DOC, EVE, FRANK, MEMBERS, MODS, OTHER_DOC, OWNERS,
};
use crate::{
    access::Access,
    delegation::Delegation,
    keyline::Keyline,
    test_utils::{cert, id, signed},
};
use alloc::vec::Vec;

/// Doc -> Owners (root); Owners administers Members; Bob and Carol are
/// Owners; Members has Edit over Doc; Alice is a Member, added by Carol.
///
/// Returns the graph, Carol's Owners membership, and Alice's Members membership.
pub fn standard<K: Keyline + Default>() -> (K, Delegation, Delegation) {
    let carol_owner = d(OWNERS, CAROL, OWNERS, Access::Admin);
    let alice_member = d(CAROL, ALICE, MEMBERS, Access::Admin);
    let g = build([
        d(DOC, OWNERS, DOC, Access::Admin).into(),
        d(OWNERS, BOB, OWNERS, Access::Admin).into(),
        carol_owner.into(),
        d(MEMBERS, OWNERS, MEMBERS, Access::Admin).into(),
        d(BOB, MEMBERS, DOC, Access::Edit).into(),
        alice_member.into(),
    ]);
    (g, carol_owner, alice_member)
}

pub fn empty_graph<K: Keyline + Default>() {
    let g = K::default();
    assert_eq!(access(&g, DOC, DOC), Some(Access::Admin));
    assert_eq!(access(&g, DOC, ALICE), None);
    assert!(g.members(id(DOC)).is_empty());
}

pub fn attenuation_and_widest_path<K: Keyline + Default>() {
    let g: K = build([
        d(DOC, ALICE, DOC, Access::Admin).into(),
        d(ALICE, BOB, DOC, Access::Read).into(),
        d(BOB, CAROL, DOC, Access::Admin).into(),
        d(DOC, CAROL, DOC, Access::Relay).into(),
    ]);
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Admin));
    assert_eq!(access(&g, DOC, BOB), Some(Access::Read));
    // min along the chain is Read; the direct Relay route loses to it.
    assert_eq!(access(&g, DOC, CAROL), Some(Access::Read));
}

pub fn ungrounded_edges_are_dead<K: Keyline + Default>() {
    let stray = d(ALICE, BOB, DOC, Access::Admin);
    let g: K = build([stray.into(), d(BOB, CAROL, DOC, Access::Admin).into()]);
    assert!(!g.is_live(&stray.digest()));
    assert!(g.members(id(DOC)).is_empty());

    // An ungrounded cycle does not certify itself.
    let g: K = build([
        d(ALICE, BOB, DOC, Access::Admin).into(),
        d(BOB, ALICE, DOC, Access::Admin).into(),
    ]);
    assert!(g.members(id(DOC)).is_empty());
}

pub fn membership_composes<K: Keyline + Default>() {
    let (g, _, _) = standard::<K>();
    assert_eq!(access(&g, DOC, OWNERS), Some(Access::Admin));
    assert_eq!(access(&g, DOC, BOB), Some(Access::Admin));
    assert_eq!(access(&g, DOC, MEMBERS), Some(Access::Edit));
    // Alice: Admin over Members, clamped to Members' Edit over Doc.
    assert_eq!(access(&g, MEMBERS, ALICE), Some(Access::Admin));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    // Owners administer Members through Members' root edge.
    assert_eq!(access(&g, MEMBERS, CAROL), Some(Access::Admin));

    let members: Vec<_> = g.members(id(DOC)).into_keys().collect();
    assert_eq!(members.len(), 5);
    assert!(!members.contains(&id(DOC)));
}

pub fn late_binding_grants_new_documents_to_members<K: Keyline + Default>() {
    let (mut g, _, _) = standard::<K>();
    assert_eq!(access(&g, OTHER_DOC, ALICE), None);
    g.insert(cert(d(OTHER_DOC, MEMBERS, OTHER_DOC, Access::Read)));
    assert_eq!(access(&g, OTHER_DOC, ALICE), Some(Access::Read));
}

pub fn retraction_is_total<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    g.insert(cert(r(CAROL, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), None);
    assert_eq!(access(&g, MEMBERS, ALICE), None);
}

pub fn renunciation_is_total<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    g.insert(cert(r(ALICE, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), None);
}

/// Bob never signed Alice's membership, but Owners is in Bob's admin
/// reach and Members' only route to Carol grounds through Owners.
pub fn admin_over_a_transited_node_cuts_deep<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    g.insert(cert(r(BOB, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), None);
    // Carol herself is untouched.
    assert_eq!(access(&g, DOC, CAROL), Some(Access::Admin));
}

/// Dan holds only Read, so Dan's admin reach is {Dan}. Alice's membership
/// never transits Dan, so Dan's cut of it is inert; Dan's own hop is Dan's to cut.
pub fn non_admin_cut_is_confined_to_own_node<K: Keyline + Default>() {
    let dan_grant = d(DAN, ALICE, DOC, Access::Read);
    let (mut g, _, alice_member) = standard::<K>();
    g.insert(cert(d(DOC, DAN, DOC, Access::Read)));
    g.insert(cert(dan_grant));
    g.insert(cert(r(DAN, &alice_member)));
    assert!(g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    g.insert(cert(r(DAN, &dan_grant)));
    assert!(!g.is_live(&dan_grant.digest()));
}

/// Bob boots Carol; Carol was Alice's sponsor, so Alice dies implicitly.
/// Carol's admin reach still holds Owners, so she can cut Bob's re-sponsor.
pub fn ex_admin_reach_is_frozen<K: Keyline + Default>() {
    let (mut g, carol_owner, alice_member) = standard::<K>();
    g.insert(cert(r(BOB, &carol_owner)));
    assert_eq!(access(&g, DOC, CAROL), None);
    assert_eq!(access(&g, DOC, ALICE), None);

    let bob_sponsors = d(BOB, ALICE, MEMBERS, Access::Admin);
    g.insert(cert(bob_sponsors));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    g.insert(cert(r(CAROL, &bob_sponsors)));
    assert_eq!(access(&g, DOC, ALICE), None);
    assert!(!g.is_live(&alice_member.digest()));
}

pub fn mutual_revocation_leaves_both_cuts_standing<K: Keyline + Default>() {
    let (mut g, carol_owner, _) = standard::<K>();
    let bob_owner = d(OWNERS, BOB, OWNERS, Access::Admin);
    g.insert(cert(r(BOB, &carol_owner)));
    g.insert(cert(r(CAROL, &bob_owner)));
    assert_eq!(access(&g, DOC, BOB), None);
    assert_eq!(access(&g, DOC, CAROL), None);
    // The apex is bricked: nothing below survives.
    assert!(g.members(id(DOC)).into_keys().eq([id(OWNERS)]));
}

/// `standard()` roots Doc at Admin, so Doc is in every Owners admin's reach
/// and any of them can revoke the root edge. One certificate bricks the
/// document; nothing below survives.
pub fn apex_admin_can_deny_the_root_edge<K: Keyline + Default>() {
    let (mut g, _, _) = standard::<K>();
    let root = d(DOC, OWNERS, DOC, Access::Admin);
    assert_eq!(access(&g, DOC, BOB), Some(Access::Admin));
    g.insert(cert(r(BOB, &root)));
    assert!(!g.is_live(&root.digest()));
    assert!(g.members(id(DOC)).is_empty());
    // Owners itself is untouched: Bob is still an Owner, of a role that no
    // longer reaches anything.
    assert_eq!(access(&g, OWNERS, BOB), Some(Access::Admin));
}

/// Root Doc at Edit instead and nobody ever holds Admin over Doc, so Doc is in
/// nobody's reach: the root edge is undeniable, and Owners' admins keep every
/// power they had over the roles below.
pub fn edit_rooted_root_edge_is_undeniable<K: Keyline + Default>() {
    let root = d(DOC, OWNERS, DOC, Access::Edit);
    let alice_member = d(CAROL, ALICE, MEMBERS, Access::Admin);
    let mut g: K = build([
        root.into(),
        d(OWNERS, BOB, OWNERS, Access::Admin).into(),
        d(OWNERS, CAROL, OWNERS, Access::Admin).into(),
        d(MEMBERS, OWNERS, MEMBERS, Access::Admin).into(),
        d(BOB, MEMBERS, DOC, Access::Edit).into(),
        alice_member.into(),
    ]);
    assert_eq!(access(&g, DOC, BOB), Some(Access::Edit));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));

    g.insert(cert(r(BOB, &root)));
    assert!(g.is_live(&root.digest()));
    assert_eq!(access(&g, DOC, BOB), Some(Access::Edit));

    // Governance is Admin over the roles, which Edit-rooting leaves intact.
    g.insert(cert(r(BOB, &alice_member)));
    assert_eq!(access(&g, DOC, ALICE), None);
}

/// Bob is an Owner and Owners is Admin over Members, but Bob holds no
/// `sub: Members` grant of his own. Composed reach still puts Members in his
/// reach, so he can cut inside it.
pub fn senior_role_admin_cuts_inside_junior_role<K: Keyline + Default>() {
    // Members is rooted at Dan, who then makes Owners an admin of Members via
    // an ordinary (non-root) edge. Bob's only path to Members is through Owners.
    let alice_member = d(DAN, ALICE, MEMBERS, Access::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Access::Admin).into(),
        d(OWNERS, BOB, OWNERS, Access::Admin).into(),
        d(MEMBERS, DAN, MEMBERS, Access::Admin).into(),
        d(DAN, OWNERS, MEMBERS, Access::Admin).into(),
        d(BOB, MEMBERS, DOC, Access::Edit).into(),
        alice_member.into(),
    ]);
    assert_eq!(access(&g, MEMBERS, BOB), Some(Access::Admin));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));

    g.insert(cert(r(BOB, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), None);
    assert_eq!(access(&g, MEMBERS, ALICE), None);
}

/// Dan supplies Members into Doc. That gives him power over his own plug —
/// retract the supply and every Member loses Doc at once — and none over
/// Members' roster, which never routes through him. Even though Dan reaches
/// Doc at Admin (through Mods), Members is not in his reach.
pub fn supply_is_daisy_chained<K: Keyline + Default>() {
    let supply = d(DAN, MEMBERS, DOC, Access::Edit);
    let alice_member = d(CAROL, ALICE, MEMBERS, Access::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Access::Admin).into(),
        d(OWNERS, BOB, OWNERS, Access::Admin).into(),
        d(BOB, MODS, DOC, Access::Admin).into(),
        d(MODS, DAN, MODS, Access::Admin).into(),
        supply.into(),
        d(MEMBERS, CAROL, MEMBERS, Access::Admin).into(),
        alice_member.into(),
    ]);
    assert_eq!(access(&g, DOC, DAN), Some(Access::Admin));
    assert_eq!(access(&g, DOC, MEMBERS), Some(Access::Edit));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    assert_eq!(access(&g, MEMBERS, DAN), None);

    // Inert: Members is not in Dan's reach.
    g.insert(cert(r(DAN, &alice_member)));
    assert!(g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));

    // Total, for the whole strip: Dan retracts his own supply edge.
    g.insert(cert(r(DAN, &supply)));
    assert_eq!(access(&g, DOC, MEMBERS), None);
    assert_eq!(access(&g, DOC, ALICE), None);
    assert_eq!(access(&g, MEMBERS, ALICE), Some(Access::Admin));
}

/// Dan administers Mods, which is supplied into Doc at Edit (so Doc is not in
/// Dan's reach). Eve is a Mod (Edit over Doc through Mods) and separately holds
/// Read over Doc from Owners. Eve grants Frank Admin; Dan revokes it. The edge
/// stays live via Eve's independent route, but conveys only what Eve holds
/// independently of Mods: Read, not Edit.
pub fn covered_edges_are_clamped_not_just_gated<K: Keyline + Default>() {
    let h = d(EVE, FRANK, DOC, Access::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Access::Admin).into(),
        d(OWNERS, MODS, DOC, Access::Edit).into(),
        d(MODS, DAN, MODS, Access::Admin).into(),
        d(DAN, EVE, MODS, Access::Admin).into(),
        d(OWNERS, EVE, DOC, Access::Read).into(),
        h.into(),
    ]);
    assert_eq!(access(&g, DOC, EVE), Some(Access::Edit));
    assert_eq!(access(&g, DOC, FRANK), Some(Access::Edit));

    g.insert(cert(r(DAN, &h)));
    assert!(g.is_live(&h.digest()));
    assert_eq!(access(&g, DOC, EVE), Some(Access::Edit));
    assert_eq!(access(&g, DOC, FRANK), Some(Access::Read));
}

pub fn revocation_may_arrive_before_its_target<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    let mut early = K::default();
    assert!(early.insert(cert(r(CAROL, &alice_member))));
    assert!(early.members(id(DOC)).is_empty());
    for c in [
        d(DOC, OWNERS, DOC, Access::Admin),
        d(OWNERS, CAROL, OWNERS, Access::Admin),
        d(MEMBERS, OWNERS, MEMBERS, Access::Admin),
        d(BOB, MEMBERS, DOC, Access::Edit),
        d(OWNERS, BOB, OWNERS, Access::Admin),
        alice_member,
    ] {
        early.insert(cert(c));
    }
    g.insert(cert(r(CAROL, &alice_member)));
    assert_eq!(early.members(id(DOC)), g.members(id(DOC)));
    assert_eq!(early.digest(), g.digest());
    assert_eq!(access(&early, DOC, ALICE), None);
}

pub fn insert_is_idempotent_and_reports_duplicates<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    let before = g.digest();
    assert!(!g.insert(cert(alice_member)));
    assert_eq!(g.digest(), before);

    let rev = r(CAROL, &alice_member);
    g.insert(cert(rev));
    assert!(!g.insert(cert(alice_member)));
    assert!(g
        .revocations_naming(&alice_member.digest())
        .into_iter()
        .eq([rev.digest()]));
}

pub fn reissue_with_seen_heals<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    // Alice sponsors Eve, so the heal has something downstream to revive.
    let eve_member = d(ALICE, EVE, MEMBERS, Access::Edit);
    g.insert(cert(eve_member));
    assert_eq!(access(&g, DOC, EVE), Some(Access::Edit));

    let rev = r(CAROL, &alice_member);
    g.insert(cert(rev));
    assert_eq!(access(&g, DOC, ALICE), None);
    // Eve dies implicitly: nothing named her certificate.
    assert!(!g.is_live(&eve_member.digest()));
    assert_eq!(access(&g, DOC, EVE), None);

    let healed = alice_member.reissue(rev.digest());
    assert_ne!(healed.digest(), alice_member.digest());
    assert!(g.insert(cert(healed)));
    assert!(g.is_live(&healed.digest()));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    // Everything below revives as the same certificate: same hash, no re-issue.
    assert!(g.is_live(&eve_member.digest()));
    assert_eq!(access(&g, DOC, EVE), Some(Access::Edit));
}

/// Rotation is escape. Dan administers `Members`, so `Members` is in his admin
/// reach forever and his cuts inside it stand. Minting a successor role,
/// supplying it and re-rostering into it puts the survivors somewhere his
/// frozen reach does not name: his cuts there are inert.
pub fn rotation_escapes_frozen_reach<K: Keyline + Default>() {
    let supply = d(BOB, MEMBERS, DOC, Access::Edit);
    let alice_member = d(DAN, ALICE, MEMBERS, Access::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Access::Admin).into(),
        d(OWNERS, BOB, OWNERS, Access::Admin).into(),
        supply.into(),
        d(MEMBERS, DAN, MEMBERS, Access::Admin).into(),
        alice_member.into(),
    ]);
    assert_eq!(access(&g, MEMBERS, DAN), Some(Access::Admin));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));

    // Members is in Dan's reach, so his cut lands.
    g.insert(cert(r(DAN, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(access(&g, DOC, ALICE), None);

    // Rotate: mint the successor, supply it, re-roster Alice, retract the old
    // supply. `MODS` here is `Members'`.
    let alice_successor = d(BOB, ALICE, MODS, Access::Admin);
    let new_supply = d(BOB, MODS, DOC, Access::Edit);
    for c in [
        d(MODS, BOB, MODS, Access::Admin),
        new_supply,
        alice_successor,
    ] {
        g.insert(cert(c));
    }
    g.insert(cert(r(BOB, &supply)));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    assert_eq!(access(&g, DOC, DAN), None);

    // Dan's reach froze at `{Dan, Members}`: nothing in the successor names it.
    g.insert(cert(r(DAN, &alice_successor)));
    g.insert(cert(r(DAN, &new_supply)));
    assert!(g.is_live(&alice_successor.digest()));
    assert!(g.is_live(&new_supply.digest()));
    assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));

    // Permanence: the cut he made while in office is still applied.
    assert!(!g.is_live(&alice_member.digest()));
}

/// A revocation naming a hash nobody holds is stored and changes no answer.
pub fn unknown_revocation_is_inert<K: Keyline + Default>() {
    let (mut g, _, _) = standard::<K>();
    let before = g.members(id(DOC));
    let phantom = d(DAN, EVE, FRANK, Access::Relay);
    assert!(g.insert(cert(r(BOB, &phantom))));
    assert_eq!(g.members(id(DOC)), before);
    assert!(!g.is_live(&phantom.digest()));
}

/// The fixtures skip signing (`Verified::assume`). This is the one scenario
/// that goes through `Signed::try_sign` and `Signed::verify` for every
/// certificate, so a backend cannot depend on anything the shortcut leaves out.
pub fn signed_certificates_agree_with_fixtures<K: Keyline + Default>() {
    let (fixtures, carol_owner, alice_member) = standard::<K>();
    let mut real = K::default();
    for c in [
        d(DOC, OWNERS, DOC, Access::Admin),
        d(OWNERS, BOB, OWNERS, Access::Admin),
        carol_owner,
        d(MEMBERS, OWNERS, MEMBERS, Access::Admin),
        d(BOB, MEMBERS, DOC, Access::Edit),
        alice_member,
    ] {
        assert!(real.insert(signed(c)));
    }
    assert!(real.insert(signed(r(CAROL, &alice_member))));
    assert!(!real.insert(signed(r(CAROL, &alice_member))));

    assert_eq!(real.members(id(DOC)), {
        let mut g = fixtures;
        g.insert(cert(r(CAROL, &alice_member)));
        g.members(id(DOC))
    });
    assert_eq!(access(&real, DOC, ALICE), None);
}
