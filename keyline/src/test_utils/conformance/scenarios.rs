//! Named scenarios from `design/keyline/{README,edge-cases}.md`, each a
//! function generic over the backend. Every backend must pass every one.
//!
//! The cast: `DOC` is a document; `OWNERS` and `MEMBERS` are roles; `MODS` is a
//! role in the clamping example; the rest are people.

use super::{
    build, d, power, r, ALICE, BOB, CAROL, DAN, DOC, EVE, FRANK, MEMBERS, MODS, OTHER_DOC, OWNERS,
};
use crate::{
    contract::Keyline,
    delegation::Delegation,
    power::Power,
    revocation::{Revocation, RevocationId},
    test_utils::{assume_verified, id, resigned, signed},
};
use alloc::vec::Vec;
use keyhive_crypto::digest::Digest;

/// Doc -> Owners (root); Owners administers Members; Bob and Carol are
/// Owners; Members has Edit over Doc; Alice is a Member, added by Carol.
///
/// Returns the graph, Carol's Owners membership, and Alice's Members membership.
pub fn standard<K: Keyline + Default>() -> (K, Delegation, Delegation) {
    let carol_owner = d(OWNERS, CAROL, OWNERS, Power::Admin);
    let alice_member = d(CAROL, ALICE, MEMBERS, Power::Admin);
    let g = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        carol_owner.into(),
        d(MEMBERS, OWNERS, MEMBERS, Power::Admin).into(),
        d(BOB, MEMBERS, DOC, Power::Edit).into(),
        alice_member.into(),
    ]);
    (g, carol_owner, alice_member)
}

pub fn empty_graph<K: Keyline + Default>() {
    let g = K::default();
    assert_eq!(power(&g, DOC, DOC), Some(Power::Admin));
    assert_eq!(power(&g, DOC, ALICE), None);
    assert!(g.members(id(DOC)).is_empty());
}

pub fn attenuation_and_widest_path<K: Keyline + Default>() {
    let g: K = build([
        d(DOC, ALICE, DOC, Power::Admin).into(),
        d(ALICE, BOB, DOC, Power::Read).into(),
        d(BOB, CAROL, DOC, Power::Admin).into(),
        d(DOC, CAROL, DOC, Power::Relay).into(),
    ]);
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Admin));
    assert_eq!(power(&g, DOC, BOB), Some(Power::Read));
    // min along the chain is Read; the direct Relay route loses to it.
    assert_eq!(power(&g, DOC, CAROL), Some(Power::Read));
}

pub fn ungrounded_edges_are_dead<K: Keyline + Default>() {
    let stray = d(ALICE, BOB, DOC, Power::Admin);
    let g: K = build([stray.into(), d(BOB, CAROL, DOC, Power::Admin).into()]);
    assert!(!g.is_live(&stray.digest()));
    assert!(g.members(id(DOC)).is_empty());

    // An ungrounded cycle does not certify itself.
    let g: K = build([
        d(ALICE, BOB, DOC, Power::Admin).into(),
        d(BOB, ALICE, DOC, Power::Admin).into(),
    ]);
    assert!(g.members(id(DOC)).is_empty());
}

pub fn membership_composes<K: Keyline + Default>() {
    let (g, _, _) = standard::<K>();
    assert_eq!(power(&g, DOC, OWNERS), Some(Power::Admin));
    assert_eq!(power(&g, DOC, BOB), Some(Power::Admin));
    assert_eq!(power(&g, DOC, MEMBERS), Some(Power::Edit));
    // Alice: Admin over Members, clamped to Members' Edit over Doc.
    assert_eq!(power(&g, MEMBERS, ALICE), Some(Power::Admin));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    // Owners administer Members through Members' root edge.
    assert_eq!(power(&g, MEMBERS, CAROL), Some(Power::Admin));

    let members: Vec<_> = g.members(id(DOC)).into_keys().collect();
    assert_eq!(members.len(), 5);
    assert!(!members.contains(&id(DOC)));
}

pub fn late_binding_grants_new_documents_to_members<K: Keyline + Default>() {
    let (mut g, _, _) = standard::<K>();
    assert_eq!(power(&g, OTHER_DOC, ALICE), None);
    g.insert(assume_verified(d(
        OTHER_DOC,
        MEMBERS,
        OTHER_DOC,
        Power::Read,
    )));
    assert_eq!(power(&g, OTHER_DOC, ALICE), Some(Power::Read));
}

/// Revocation by the issuer needs no admin reach: Dan holds only Read over
/// Doc, so his reach is his own node, yet his revocation of what he issued
/// kills it.
pub fn issuer_revocation_is_total<K: Keyline + Default>() {
    let dan_delegation = d(DAN, ALICE, DOC, Power::Read);
    let (mut g, _, _) = standard::<K>();
    g.insert(assume_verified(d(DOC, DAN, DOC, Power::Read)));
    g.insert(assume_verified(dan_delegation));
    assert!(g.is_live(&dan_delegation.digest()));

    g.insert(assume_verified(r(DAN, &dan_delegation)));
    assert!(!g.is_live(&dan_delegation.digest()));
}

/// The audience clause on its own. Alice holds only Read in Members, so her
/// admin reach is {Alice}, and no route of her membership transits it. Her
/// revocation of it is still total. (Were she an Admin member, her admin
/// reach would cover Members and kill the membership even without the
/// audience clause.)
pub fn audience_revocation_without_admin_reach_is_total<K: Keyline + Default>() {
    let alice_reader = d(CAROL, ALICE, MEMBERS, Power::Read);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, CAROL, OWNERS, Power::Admin).into(),
        d(MEMBERS, OWNERS, MEMBERS, Power::Admin).into(),
        d(CAROL, MEMBERS, DOC, Power::Edit).into(),
        alice_reader.into(),
    ]);
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));

    g.insert(assume_verified(r(ALICE, &alice_reader)));
    assert!(!g.is_live(&alice_reader.digest()));
    assert_eq!(power(&g, DOC, ALICE), None);
    assert_eq!(power(&g, MEMBERS, ALICE), None);
    assert_eq!(power(&g, DOC, CAROL), Some(Power::Admin));
}

/// Bob never signed Alice's membership, and Members is not in his reach:
/// Owners is only an Edit member of Members. But Owners is in his reach, and
/// the membership's only route, from Members to its issuer Carol, transits
/// Owners. So his revocation covers it.
pub fn admin_reach_covers_a_transited_node<K: Keyline + Default>() {
    let alice_member = d(CAROL, ALICE, MEMBERS, Power::Edit);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        d(OWNERS, CAROL, OWNERS, Power::Admin).into(),
        d(MEMBERS, OWNERS, MEMBERS, Power::Edit).into(),
        d(BOB, MEMBERS, DOC, Power::Edit).into(),
        alice_member.into(),
    ]);
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    assert_eq!(power(&g, MEMBERS, BOB), Some(Power::Edit));

    g.insert(assume_verified(r(BOB, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(power(&g, DOC, ALICE), None);
    // Carol herself is untouched.
    assert_eq!(power(&g, DOC, CAROL), Some(Power::Admin));
}

/// A non-admin's revocation covers routes through their own node and nothing
/// else. Dan is an Edit member of Mods, so his reach is {Dan}. Eve holds Edit
/// in Mods through a seat Dan issued, and Read through Mods itself. Dan
/// revokes Eve's delegation to Frank: the derivation through Dan is excluded,
/// even though Dan sits inside Mods' row rather than on the path from Doc, so
/// Frank keeps only what Eve's own Read seat conveys. Eve is untouched.
pub fn non_admin_revocation_is_confined_to_own_node<K: Keyline + Default>() {
    let h = d(EVE, FRANK, DOC, Power::Admin);
    let mut g: K = build([
        d(DOC, MODS, DOC, Power::Edit).into(),
        d(MODS, DAN, MODS, Power::Edit).into(),
        d(DAN, EVE, MODS, Power::Edit).into(),
        d(MODS, EVE, MODS, Power::Read).into(),
        h.into(),
    ]);
    assert_eq!(power(&g, DOC, FRANK), Some(Power::Edit));

    g.insert(assume_verified(r(DAN, &h)));
    assert!(g.is_live(&h.digest()));
    assert_eq!(power(&g, DOC, FRANK), Some(Power::Read));
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
}

/// Bob removes Carol; Carol was Alice's sponsor, so Alice dies implicitly.
/// Carol's admin reach still holds Owners, so she can revoke Bob's re-sponsor.
pub fn ex_admin_reach_is_frozen<K: Keyline + Default>() {
    let (mut g, carol_owner, alice_member) = standard::<K>();
    g.insert(assume_verified(r(BOB, &carol_owner)));
    assert_eq!(power(&g, DOC, CAROL), None);
    assert_eq!(power(&g, DOC, ALICE), None);

    let bob_sponsors = d(BOB, ALICE, MEMBERS, Power::Admin);
    g.insert(assume_verified(bob_sponsors));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    g.insert(assume_verified(r(CAROL, &bob_sponsors)));
    assert_eq!(power(&g, DOC, ALICE), None);
    assert!(!g.is_live(&alice_member.digest()));
}

pub fn mutual_revocations_both_take_effect<K: Keyline + Default>() {
    let (mut g, carol_owner, _) = standard::<K>();
    let bob_owner = d(OWNERS, BOB, OWNERS, Power::Admin);
    g.insert(assume_verified(r(BOB, &carol_owner)));
    g.insert(assume_verified(r(CAROL, &bob_owner)));
    assert_eq!(power(&g, DOC, BOB), None);
    assert_eq!(power(&g, DOC, CAROL), None);
    // The apex is bricked: nothing below survives.
    assert!(g.members(id(DOC)).into_keys().eq([id(OWNERS)]));
}

/// `standard()` roots Doc at Admin, so Doc is in every Owners admin's reach
/// and any of them can revoke the root edge. One certificate bricks the
/// document; nothing below survives.
pub fn apex_admin_can_revoke_the_root_edge<K: Keyline + Default>() {
    let (mut g, _, _) = standard::<K>();
    let root = d(DOC, OWNERS, DOC, Power::Admin);
    assert_eq!(power(&g, DOC, BOB), Some(Power::Admin));
    g.insert(assume_verified(r(BOB, &root)));
    assert!(!g.is_live(&root.digest()));
    assert!(g.members(id(DOC)).is_empty());
    // Owners itself is untouched: Bob is still an Owner, of a role that no
    // longer reaches anything.
    assert_eq!(power(&g, OWNERS, BOB), Some(Power::Admin));
}

/// Root Doc at Edit instead and nobody ever holds Admin over Doc, so Doc is in
/// nobody's reach: the root edge is irrevocable, and Owners' admins keep every
/// power they had over the roles below.
pub fn edit_rooted_root_edge_is_irrevocable<K: Keyline + Default>() {
    let root = d(DOC, OWNERS, DOC, Power::Edit);
    let alice_member = d(CAROL, ALICE, MEMBERS, Power::Admin);
    let mut g: K = build([
        root.into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        d(OWNERS, CAROL, OWNERS, Power::Admin).into(),
        d(MEMBERS, OWNERS, MEMBERS, Power::Admin).into(),
        d(BOB, MEMBERS, DOC, Power::Edit).into(),
        alice_member.into(),
    ]);
    assert_eq!(power(&g, DOC, BOB), Some(Power::Edit));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    g.insert(assume_verified(r(BOB, &root)));
    assert!(g.is_live(&root.digest()));
    assert_eq!(power(&g, DOC, BOB), Some(Power::Edit));

    // Governance is Admin over the roles, which Edit-rooting leaves intact.
    g.insert(assume_verified(r(BOB, &alice_member)));
    assert_eq!(power(&g, DOC, ALICE), None);
}

/// Bob is an Owner and Owners is Admin over Members, but Bob holds no
/// `subject: Members` grant of his own. Composed reach still puts Members in his
/// reach, so his revocations cover delegations inside it.
pub fn senior_role_admin_revokes_inside_junior_role<K: Keyline + Default>() {
    // Members is rooted at Dan, who then makes Owners an admin of Members via
    // an ordinary (non-root) edge. Bob's only path to Members is through Owners.
    let alice_member = d(DAN, ALICE, MEMBERS, Power::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        d(MEMBERS, DAN, MEMBERS, Power::Admin).into(),
        d(DAN, OWNERS, MEMBERS, Power::Admin).into(),
        d(BOB, MEMBERS, DOC, Power::Edit).into(),
        alice_member.into(),
    ]);
    assert_eq!(power(&g, MEMBERS, BOB), Some(Power::Admin));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    g.insert(assume_verified(r(BOB, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(power(&g, DOC, ALICE), None);
    assert_eq!(power(&g, MEMBERS, ALICE), None);
}

/// Dan supplies Members into Doc. He controls his own supply (revoking it cuts
/// every Member off from Doc) but not Members' roster, which never routes
/// through him. Dan reaches Doc at Admin through Mods, but Members is not in
/// his reach.
pub fn supply_is_daisy_chained<K: Keyline + Default>() {
    let supply = d(DAN, MEMBERS, DOC, Power::Edit);
    let alice_member = d(CAROL, ALICE, MEMBERS, Power::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        d(BOB, MODS, DOC, Power::Admin).into(),
        d(MODS, DAN, MODS, Power::Admin).into(),
        supply.into(),
        d(MEMBERS, CAROL, MEMBERS, Power::Admin).into(),
        alice_member.into(),
    ]);
    assert_eq!(power(&g, DOC, DAN), Some(Power::Admin));
    assert_eq!(power(&g, DOC, MEMBERS), Some(Power::Edit));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    assert_eq!(power(&g, MEMBERS, DAN), None);

    // Inert: Members is not in Dan's reach.
    g.insert(assume_verified(r(DAN, &alice_member)));
    assert!(g.is_live(&alice_member.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    // Total, for the whole strip: Dan revokes his own supply edge.
    g.insert(assume_verified(r(DAN, &supply)));
    assert_eq!(power(&g, DOC, MEMBERS), None);
    assert_eq!(power(&g, DOC, ALICE), None);
    assert_eq!(power(&g, MEMBERS, ALICE), Some(Power::Admin));
}

/// Dan administers Mods, which is supplied into Doc at Edit (so Doc is not in
/// Dan's reach). Eve is a Mod (Edit over Doc through Mods) and separately holds
/// Read over Doc from Owners. Eve grants Frank Admin; Dan revokes it. The edge
/// stays live via Eve's independent route, but conveys only what Eve holds
/// independently of Mods: Read, not Edit.
pub fn covered_edges_are_clamped_not_just_gated<K: Keyline + Default>() {
    let h = d(EVE, FRANK, DOC, Power::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, MODS, DOC, Power::Edit).into(),
        d(MODS, DAN, MODS, Power::Admin).into(),
        d(DAN, EVE, MODS, Power::Admin).into(),
        d(OWNERS, EVE, DOC, Power::Read).into(),
        h.into(),
    ]);
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
    assert_eq!(power(&g, DOC, FRANK), Some(Power::Edit));

    g.insert(assume_verified(r(DAN, &h)));
    assert!(g.is_live(&h.digest()));
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
    assert_eq!(power(&g, DOC, FRANK), Some(Power::Read));
}

/// Second key standing in for a role, and a third person, for
/// `mutually_covered_edges_cannot_lift_each_other`.
const MODS_B: u8 = 12;
const GUS: u8 = 13;

/// Two covered edges on each other's avoiding derivation cannot raise each
/// other's level above what a derivation outside the cycle supports.
///
/// Eve holds Read over Doc directly and Edit through Mods; Frank holds Edit
/// through Mods′. Eve grants Frank Admin (h1), revoked by Mods. Frank grants
/// Eve Admin (h2) and Gus Admin (h3), both revoked by Mods′. Avoiding Mods,
/// Eve's only grounded standing is Read, so h1 conveys Read; avoiding Mods′,
/// Frank's only standing comes through h1, so h3 conveys Read too. Gus gets
/// Read. Edit would require h1 and h2 to certify each other.
pub fn mutually_covered_edges_cannot_lift_each_other<K: Keyline + Default>() {
    let h1 = d(EVE, FRANK, DOC, Power::Admin);
    let h2 = d(FRANK, EVE, DOC, Power::Admin);
    let h3 = d(FRANK, GUS, DOC, Power::Admin);
    let g: K = build([
        d(DOC, EVE, DOC, Power::Read).into(),
        d(DOC, MODS, DOC, Power::Edit).into(),
        d(MODS, EVE, MODS, Power::Admin).into(),
        d(DOC, MODS_B, DOC, Power::Edit).into(),
        d(MODS_B, FRANK, MODS_B, Power::Admin).into(),
        h1.into(),
        h2.into(),
        h3.into(),
        r(MODS, &h1).into(),
        r(MODS_B, &h2).into(),
        r(MODS_B, &h3).into(),
    ]);
    assert!(g.is_live(&h1.digest()) && g.is_live(&h2.digest()) && g.is_live(&h3.digest()));
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
    assert_eq!(power(&g, DOC, FRANK), Some(Power::Edit));
    assert_eq!(power(&g, DOC, GUS), Some(Power::Read));
}

pub fn revocation_may_arrive_before_its_target<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    let mut early = K::default();
    assert!(early.insert(assume_verified(r(CAROL, &alice_member))));
    assert!(early.members(id(DOC)).is_empty());
    for c in [
        d(DOC, OWNERS, DOC, Power::Admin),
        d(OWNERS, CAROL, OWNERS, Power::Admin),
        d(MEMBERS, OWNERS, MEMBERS, Power::Admin),
        d(BOB, MEMBERS, DOC, Power::Edit),
        d(OWNERS, BOB, OWNERS, Power::Admin),
        alice_member,
    ] {
        early.insert(assume_verified(c));
    }
    g.insert(assume_verified(r(CAROL, &alice_member)));
    assert_eq!(early.members(id(DOC)), g.members(id(DOC)));
    assert_eq!(early.digest(), g.digest());
    assert_eq!(power(&early, DOC, ALICE), None);
}

pub fn insert_is_idempotent_and_reports_duplicates<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    let before = g.digest();
    assert!(!g.insert(assume_verified(alice_member)));
    assert_eq!(g.digest(), before);

    let revocation: Revocation<K::RetentionWatermark> = r(CAROL, &alice_member);
    let revocation_digest = revocation.digest();
    g.insert(assume_verified(revocation));
    assert!(!g.insert(assume_verified(alice_member)));
    assert!(g
        .revocations_naming(&alice_member.digest())
        .into_iter()
        .eq([revocation_digest]));
}

pub fn reissue_with_citation_heals<K: Keyline + Default>() {
    let (mut g, _, alice_member) = standard::<K>();
    // Alice sponsors Eve, so the heal has something downstream to revive.
    let eve_member = d(ALICE, EVE, MEMBERS, Power::Edit);
    g.insert(assume_verified(eve_member));
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));

    let revocation: Revocation<K::RetentionWatermark> = r(CAROL, &alice_member);
    let healed = alice_member.reissue(revocation.digest());
    g.insert(assume_verified(revocation));
    assert_eq!(power(&g, DOC, ALICE), None);
    // Eve dies implicitly: nothing named her certificate.
    assert!(!g.is_live(&eve_member.digest()));
    assert_eq!(power(&g, DOC, EVE), None);

    assert_ne!(healed.digest(), alice_member.digest());
    assert!(g.insert(assume_verified(healed)));
    assert!(g.is_live(&healed.digest()));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    // Everything below revives as the same certificate: same hash, no re-issue.
    assert!(g.is_live(&eve_member.digest()));
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
}

/// Rotating a role escapes an ex-admin's frozen reach. Dan administers
/// `Members`, so `Members` is in his admin
/// reach forever and his revocations inside it stand. Minting a successor role,
/// supplying it and re-rostering into it puts the survivors somewhere his
/// frozen reach does not name: his revocations there are inert.
pub fn rotation_escapes_frozen_reach<K: Keyline + Default>() {
    let supply = d(BOB, MEMBERS, DOC, Power::Edit);
    let alice_member = d(MEMBERS, ALICE, MEMBERS, Power::Admin);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        supply.into(),
        d(MEMBERS, DAN, MEMBERS, Power::Admin).into(),
        alice_member.into(),
    ]);
    assert_eq!(power(&g, MEMBERS, DAN), Some(Power::Admin));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    // Dan did not issue Alice's membership, but Members is in his reach, so
    // his revocation covers it.
    g.insert(assume_verified(r(DAN, &alice_member)));
    assert!(!g.is_live(&alice_member.digest()));
    assert_eq!(power(&g, DOC, ALICE), None);

    // Rotate: mint the successor, supply it, re-roster Alice, revoke the old
    // supply. `MODS` here is `Members'`.
    let alice_successor = d(BOB, ALICE, MODS, Power::Admin);
    let new_supply = d(BOB, MODS, DOC, Power::Edit);
    for c in [
        d(MODS, BOB, MODS, Power::Admin),
        new_supply,
        alice_successor,
    ] {
        g.insert(assume_verified(c));
    }
    g.insert(assume_verified(r(BOB, &supply)));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    assert_eq!(power(&g, DOC, DAN), None);

    // Dan's reach froze at `{Dan, Members}`: nothing in the successor names it.
    g.insert(assume_verified(r(DAN, &alice_successor)));
    g.insert(assume_verified(r(DAN, &new_supply)));
    assert!(g.is_live(&alice_successor.digest()));
    assert!(g.is_live(&new_supply.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    // Permanence: Alice's old membership is grounded at Members itself, so it
    // would revive without the revocation Dan signed in office. That revocation
    // still covers it, through the reach that froze at Members.
    assert!(!g.is_live(&alice_member.digest()));
}

/// A revocation naming a hash nobody holds is stored and changes no answer.
pub fn unknown_revocation_is_inert<K: Keyline + Default>() {
    let (mut g, _, _) = standard::<K>();
    let before = g.members(id(DOC));
    let phantom = d(DAN, EVE, FRANK, Power::Relay);
    let revocation = assume_verified(r(BOB, &phantom));
    let revocation_digest = revocation.id();
    assert!(!g.contains(&revocation_digest));
    assert!(g.insert(revocation));
    assert!(g.contains(&revocation_digest));
    assert_eq!(g.members(id(DOC)), before);
    assert!(!g.is_live(&phantom.digest()));
    // The target itself was never inserted.
    assert!(!g.contains(&assume_verified::<K::RetentionWatermark, _>(phantom).id()));
}

/// First role of the gift-cert ladder; the ladder is `LADDER..LADDER + RUNGS`.
const LADDER: u8 = 20;
const RUNGS: u8 = 4;

/// The gift-cert attack from `design/keyline/evaluation-notes.md` §7 and §9.
/// Eve (the attacker) is a member with Edit over Doc. She builds a ladder of
/// self-rooted roles, each rung a member of the one above. She supplies the top
/// rung into Doc and gifts Alice (the victim) membership in the bottom rung.
/// Alice never consents.
///
/// The suite checks answers, not cost, so this pins the semantic claims that
/// the cost argument relies on:
///
/// - a gift raises the victim's effective power without her consent;
/// - removing the attacker takes the ladder out of Doc, while its internals stay
///   self-grounded (what a demand-driven evaluator must not walk);
/// - re-adding the same key revives the ladder and the gift with it;
/// - a fresh key revives nothing;
/// - revocation by the audience is total, an identical re-gift collides with the
///   revoked hash, and a varied one is a new certificate.
///
/// The cost phases (paid once, not walked after the removal) are obligations for
/// demand-driven backends and are not observable through the trait.
pub fn gift_cert_attack_follows_liveness<K: Keyline + Default>() {
    let rung = |i: u8| LADDER + i;
    let top = rung(0);
    let bottom = rung(RUNGS - 1);
    let eve_member = d(BOB, EVE, DOC, Power::Edit);
    let supply = d(EVE, top, DOC, Power::Edit);
    let gift = d(EVE, ALICE, bottom, Power::Admin);
    let inner = d(EVE, rung(1), top, Power::Admin);

    let after_removal = || -> (K, Digest<RevocationId>) {
        let mut g: K = build([
            d(DOC, OWNERS, DOC, Power::Admin).into(),
            d(OWNERS, BOB, OWNERS, Power::Admin).into(),
            d(BOB, ALICE, DOC, Power::Read).into(),
            eve_member.into(),
            supply.into(),
        ]);
        for i in 0..RUNGS {
            g.insert(assume_verified(d(rung(i), EVE, rung(i), Power::Admin)));
            if i + 1 < RUNGS {
                g.insert(assume_verified(d(EVE, rung(i + 1), rung(i), Power::Admin)));
            }
        }

        // Unaimed: the ladder reaches Doc, but Alice has only her own Read.
        assert_eq!(power(&g, DOC, bottom), Some(Power::Edit));
        assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));

        // The gift: one certificate, no acceptance step.
        assert!(g.insert(assume_verified(gift)));
        assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

        // Remove Eve: the ladder's standing over Doc rides her membership.
        let removal: Revocation<K::RetentionWatermark> = r(BOB, &eve_member);
        let removal_digest = removal.digest();
        g.insert(assume_verified(removal));
        assert_eq!(power(&g, DOC, EVE), None);
        assert!(!g.is_live(&supply.digest()));
        assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));
        assert!((0..RUNGS).all(|i| !g.members(id(DOC)).contains_key(&id(rung(i)))));
        // ...while the internals stay self-grounded.
        assert!(g.is_live(&inner.digest()));
        assert!(g.is_live(&gift.digest()));
        assert_eq!(power(&g, top, ALICE), Some(Power::Admin));
        (g, removal_digest)
    };

    // Re-adding Eve under a fresh key revives nothing her old key signed.
    let (mut g, _) = after_removal();
    g.insert(assume_verified(d(BOB, FRANK, DOC, Power::Edit)));
    assert!(!g.is_live(&supply.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));

    // But supplying the ladder again, under any key, regrounds Eve through her
    // Admin seat at its top, and with her, her old supply and the gift.
    g.insert(assume_verified(d(FRANK, top, DOC, Power::Edit)));
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
    assert!(g.is_live(&supply.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    // Same-key re-add: the ladder and the gift come back as the same
    // certificates. Nothing named them, so nothing stops them.
    let (mut g, removal) = after_removal();
    g.insert(assume_verified(eve_member.reissue(removal)));
    assert!(g.is_live(&supply.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    // Alice's revocation of the gift is total, and leaves her own route alone.
    let alice_revocation: Revocation<K::RetentionWatermark> = r(ALICE, &gift);
    let alice_revocation_digest = alice_revocation.digest();
    g.insert(assume_verified(alice_revocation));
    assert!(!g.is_live(&gift.digest()));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));
    assert_eq!(power(&g, DOC, bottom), Some(Power::Edit));

    // An identical re-gift is the revoked certificate.
    assert!(!g.insert(assume_verified(gift)));
    assert!(g
        .revocations_naming(&gift.digest())
        .into_iter()
        .eq([alice_revocation_digest]));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));

    // A varied re-gift is a new hash and needs its own revocation.
    let regift = gift.reissue(alice_revocation_digest);
    assert!(g.insert(assume_verified(regift)));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    g.insert(assume_verified(r(ALICE, &regift)));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Read));
}

/// The fixtures skip signing (`Verified::assume`). This scenario goes through
/// `Signed::try_sign` and `Signed::verify` for every certificate, so the
/// production path runs at least once, and checks that the signed set gives
/// the same answers and the same digest as the fixtures.
pub fn signed_certificates_agree_with_fixtures<K: Keyline + Default>() {
    let (fixtures, carol_owner, alice_member) = standard::<K>();
    let mut real = K::default();
    for c in [
        d(DOC, OWNERS, DOC, Power::Admin),
        d(OWNERS, BOB, OWNERS, Power::Admin),
        carol_owner,
        d(MEMBERS, OWNERS, MEMBERS, Power::Admin),
        d(BOB, MEMBERS, DOC, Power::Edit),
        alice_member,
    ] {
        assert!(real.insert(signed(c)));
    }
    assert!(real.insert(signed(r(CAROL, &alice_member))));
    assert!(!real.insert(signed(r(CAROL, &alice_member))));

    let mut fixtures = fixtures;
    fixtures.insert(assume_verified(r(CAROL, &alice_member)));
    assert_eq!(real.members(id(DOC)), fixtures.members(id(DOC)));
    assert_eq!(real.digest(), fixtures.digest());
    assert_eq!(
        real.is_live(&alice_member.digest()),
        fixtures.is_live(&alice_member.digest())
    );
    assert_eq!(power(&real, DOC, ALICE), None);
}

/// Two valid signatures over one payload are two `Signed` values but one
/// certificate: the set is keyed by digest, so the second insert is a
/// duplicate.
pub fn second_signature_is_the_same_certificate<K: Keyline + Default>() {
    let root = d(DOC, ALICE, DOC, Power::Admin);
    let first = signed::<K::RetentionWatermark, _>(root);
    let second = resigned::<K::RetentionWatermark, _>(root, 1);
    assert!(first != second, "different signatures");
    assert_eq!(first.id(), second.id());

    let digest = first.id();
    let mut g = K::default();
    assert!(g.insert(first));
    assert!(!g.insert(second));
    assert!(g.contains(&digest));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Admin));
}

/// Edit-rooting protects only the root edge. Memberships the role key signed
/// at creation are grounded at the role, which is in every apex admin's reach,
/// so two apex admins who revoke each other both lose their standing.
pub fn apex_duel_kills_creation_memberships_even_when_edit_rooted<K: Keyline + Default>() {
    let root = d(DOC, OWNERS, DOC, Power::Edit);
    let alice_owner = d(OWNERS, ALICE, OWNERS, Power::Admin);
    let bob_owner = d(OWNERS, BOB, OWNERS, Power::Admin);
    let mut g: K = build([root.into(), alice_owner.into(), bob_owner.into()]);
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));

    g.insert(assume_verified(r(ALICE, &bob_owner)));
    g.insert(assume_verified(r(BOB, &alice_owner)));
    assert!(g.is_live(&root.digest()));
    assert!(!g.is_live(&alice_owner.digest()));
    assert!(!g.is_live(&bob_owner.digest()));
    assert!(g.members(id(DOC)).into_keys().eq([id(OWNERS)]));
}

/// `retain` is part of a revocation's identity but not of its effect: two
/// revocations of one delegation that differ only there are two certificates,
/// and the set answers exactly as with either one.
pub fn retain_distinguishes_certificates_not_authority<K: Keyline + Default>()
where
    K::RetentionWatermark: Clone + Default,
{
    let (mut g, _, alice_member) = standard::<K>();
    let plain: Revocation<K::RetentionWatermark> = r(CAROL, &alice_member);
    let retaining = plain
        .clone()
        .retaining([(id(DOC), K::RetentionWatermark::default())].into());
    assert_ne!(plain.digest(), retaining.digest());

    assert!(g.insert(assume_verified(plain)));
    let members = g.members(id(DOC));
    assert!(g.insert(assume_verified(retaining)));
    assert_eq!(g.members(id(DOC)), members);
    assert_eq!(power(&g, DOC, ALICE), None);
}

/// Keys for `steward_rotation_leaves_former_officers_nothing`.
const STEWARD: u8 = 14;
const OFFICERS: u8 = 15;
const OFFICERS_B: u8 = 16;

/// The Steward pattern (`design/keyline/patterns.md`): documents rooted at
/// Edit in a permanent key, whose officers are an Edit member of it. Officers
/// reach every document at Edit and run their own roster, but never hold
/// Admin over a document or the steward. Rotating the officers' role is one
/// revocation by the steward, after which a former officer has no standing
/// and no reach over anything still routed.
pub fn steward_rotation_leaves_former_officers_nothing<K: Keyline + Default>() {
    let officers = d(STEWARD, OFFICERS, STEWARD, Power::Edit);
    let mut g: K = build([
        d(DOC, STEWARD, DOC, Power::Edit).into(),
        d(OTHER_DOC, STEWARD, OTHER_DOC, Power::Edit).into(),
        officers.into(),
        d(OFFICERS, ALICE, OFFICERS, Power::Admin).into(),
        d(OFFICERS, BOB, OFFICERS, Power::Admin).into(),
        d(ALICE, CAROL, DOC, Power::Admin).into(),
    ]);
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    assert_eq!(power(&g, OTHER_DOC, BOB), Some(Power::Edit));
    assert_eq!(power(&g, DOC, CAROL), Some(Power::Edit));
    assert_eq!(power(&g, STEWARD, ALICE), Some(Power::Edit));

    let successors = d(STEWARD, OFFICERS_B, STEWARD, Power::Edit);
    let bob_again = d(OFFICERS_B, BOB, OFFICERS_B, Power::Admin);
    g.insert(assume_verified(r(STEWARD, &officers)));
    g.insert(assume_verified(successors));
    g.insert(assume_verified(bob_again));
    assert_eq!(power(&g, DOC, ALICE), None);
    assert_eq!(power(&g, DOC, CAROL), None);
    assert_eq!(power(&g, OTHER_DOC, BOB), Some(Power::Edit));

    g.insert(assume_verified(r(ALICE, &successors)));
    g.insert(assume_verified(r(ALICE, &bob_again)));
    g.insert(assume_verified(d(ALICE, CAROL, OTHER_DOC, Power::Edit)));
    assert_eq!(power(&g, OTHER_DOC, BOB), Some(Power::Edit));
    assert_eq!(power(&g, OTHER_DOC, CAROL), None);
}

/// Keys for the pinning and caretaker scenarios.
const PIN: u8 = 17;
const CARETAKER: u8 = 18;

/// The audience is not on a delegation's route. Carol administers Members,
/// so Members is in her reach, but the supply into Members is grounded at Doc
/// through Owners and Bob and never transits Members: her revocation of it
/// covers nothing.
pub fn role_admin_cannot_revoke_the_supply_into_the_role<K: Keyline + Default>() {
    let supply = d(BOB, MEMBERS, DOC, Power::Edit);
    let g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        supply.into(),
        d(MEMBERS, CAROL, MEMBERS, Power::Admin).into(),
        r(CAROL, &supply).into(),
    ]);
    assert!(g.is_live(&supply.digest()));
    assert_eq!(power(&g, DOC, MEMBERS), Some(Power::Edit));
    assert_eq!(power(&g, DOC, CAROL), Some(Power::Edit));
}

/// Coverage is the union over every revocation of a delegation. Eve stands
/// over Doc through Mods and through Members; Dan administers Mods and Carol
/// administers Members. Either revocation of Eve's delegation to Frank alone
/// leaves the other derivation; both together leave none.
pub fn revocations_of_one_delegation_cover_jointly<K: Keyline + Default>() {
    let h = d(EVE, FRANK, DOC, Power::Admin);
    let base = || -> K {
        build([
            d(DOC, OWNERS, DOC, Power::Admin).into(),
            d(OWNERS, MODS, DOC, Power::Edit).into(),
            d(MODS, DAN, MODS, Power::Admin).into(),
            d(DAN, EVE, MODS, Power::Admin).into(),
            d(OWNERS, MEMBERS, DOC, Power::Edit).into(),
            d(MEMBERS, CAROL, MEMBERS, Power::Admin).into(),
            d(CAROL, EVE, MEMBERS, Power::Admin).into(),
            h.into(),
        ])
    };

    for revoker in [DAN, CAROL] {
        let mut g = base();
        g.insert(assume_verified(r(revoker, &h)));
        assert!(g.is_live(&h.digest()), "revoked by {revoker} alone");
        assert_eq!(power(&g, DOC, FRANK), Some(Power::Edit));
    }

    let mut g = base();
    g.insert(assume_verified(r(DAN, &h)));
    g.insert(assume_verified(r(CAROL, &h)));
    assert!(!g.is_live(&h.digest()));
    assert_eq!(power(&g, DOC, FRANK), None);
    assert_eq!(power(&g, DOC, EVE), Some(Power::Edit));
}

/// Pinning (`design/keyline/patterns.md`): Alice routes Eve's access through
/// `PIN`, a node that is itself a member of Members, so the access answers to
/// Members. `PIN`'s own key signs its creation edge, which is what gives Alice
/// standing over it. Eve's access dies with Alice's Members standing, even
/// though Alice keeps an independent route to Doc, and any Members admin can
/// cut it before that.
pub fn pinned_delegation_answers_to_the_role<K: Keyline + Default>() {
    let alice_member = d(CAROL, ALICE, MEMBERS, Power::Admin);
    let pinned = d(ALICE, PIN, MEMBERS, Power::Edit);
    let base = || -> K {
        build([
            d(DOC, OWNERS, DOC, Power::Admin).into(),
            d(OWNERS, BOB, OWNERS, Power::Admin).into(),
            d(OWNERS, CAROL, OWNERS, Power::Admin).into(),
            d(MEMBERS, OWNERS, MEMBERS, Power::Admin).into(),
            d(BOB, MEMBERS, DOC, Power::Edit).into(),
            alice_member.into(),
            d(BOB, ALICE, DOC, Power::Edit).into(),
            d(PIN, ALICE, PIN, Power::Admin).into(),
            pinned.into(),
            d(ALICE, EVE, PIN, Power::Edit).into(),
        ])
    };
    assert_eq!(power(&base(), DOC, EVE), Some(Power::Edit));

    let mut g = base();
    g.insert(assume_verified(r(CAROL, &alice_member)));
    assert_eq!(power(&g, DOC, ALICE), Some(Power::Edit));
    assert_eq!(power(&g, DOC, EVE), None);

    let mut g = base();
    g.insert(assume_verified(r(BOB, &pinned)));
    assert_eq!(power(&g, DOC, EVE), None);
}

/// A caretaker (`design/keyline/patterns.md`): `CARETAKER` is a member of
/// Members with one roster edge, to Carol, and Dan administers it. Dan holds no
/// Admin over Members or Doc, yet can sever Carol by revoking her roster edge.
/// He cannot revoke the supply into the caretaker: its audience is not on its
/// route. As an admin of the caretaker he also reaches what it reaches.
pub fn caretaker_admin_severs_downstream_but_not_the_supply<K: Keyline + Default>() {
    let supply = d(BOB, CARETAKER, MEMBERS, Power::Edit);
    let carol_roster = d(CARETAKER, CAROL, CARETAKER, Power::Edit);
    let mut g: K = build([
        d(DOC, OWNERS, DOC, Power::Admin).into(),
        d(OWNERS, BOB, OWNERS, Power::Admin).into(),
        d(MEMBERS, OWNERS, MEMBERS, Power::Admin).into(),
        d(BOB, MEMBERS, DOC, Power::Edit).into(),
        supply.into(),
        d(CARETAKER, DAN, CARETAKER, Power::Admin).into(),
        carol_roster.into(),
    ]);
    assert_eq!(power(&g, DOC, CAROL), Some(Power::Edit));
    assert_eq!(power(&g, DOC, DAN), Some(Power::Edit));
    assert_eq!(power(&g, MEMBERS, DAN), Some(Power::Edit));

    g.insert(assume_verified(r(DAN, &supply)));
    assert!(g.is_live(&supply.digest()));

    g.insert(assume_verified(r(DAN, &carol_roster)));
    assert_eq!(power(&g, DOC, CAROL), None);
}
