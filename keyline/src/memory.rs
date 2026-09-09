//! [`MemoryKeyline`]: the in-memory reference implementation of [`Keyline`].
//!
//! This is the evaluation program in `design/keyline/implementation.md`
//! executed literally, with no caching. Every query recomputes stratum 1
//! (service records and coverage) and stratum 2 (the live set and edge caps)
//! from the certificate set, then runs one widest-path search rooted at the
//! queried subject. Anything faster MUST agree with it on every set; the
//! conformance suite is how that is checked.
//!
//! ```text
//! stratum 1   reaches   = search(all subjects, exclude ∅, every edge, cap = can)
//!             record(k) = { n : last hop onto k is an Admin edge about n } ∪ {k}
//!             covered(h) = ⋃ record(k) for every k revoking h
//!
//! stratum 2   live      = least fixed point:  h joins when iss(h) is reachable
//!                         from sub(h) over live edges avoiding covered(h),
//!                         and aud(h) has not revoked h itself
//!             cap       = greatest fixed point from can: covered h conveys at most
//!                         the level iss(h) holds on a derivation avoiding covered(h)
//!
//! query       search(s, exclude ∅, live edges, cap)
//! ```
//!
//! `search` is one procedure: a bucketed widest-path pass per root, iterated to
//! a fixed point across every root it discovers, because `sub` composes (a
//! node's members inherit what the node reaches).

use crate::{
    access::Access,
    certificate::Certificate,
    collections::{Map, Set},
    delegation::Delegation,
    id::Id,
    keyline::{set_digest, Keyline},
    revocation::Revocation,
    signed::{Signed, Verified},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::digest::Digest;

/// The in-memory reference [`Keyline`].
///
/// Plain maps of plain data: no interior mutability, so `Send + Sync` hold and
/// `&self` queries may run in parallel behind a read lock.
#[derive(Debug, Default, Clone)]
pub struct MemoryKeyline {
    /// The set itself, keyed by certificate identity. Retained as received so
    /// certificates can be forwarded without re-encoding.
    certificates: Map<Digest<Certificate>, Signed<Certificate>>,

    delegations: Map<Digest<Delegation>, Delegation>,

    /// `sub -> iss -> edges about sub issued by iss`: the adjacency the search walks.
    edges: Map<Id, Map<Id, Vec<Digest<Delegation>>>>,

    revocations: Map<Digest<Revocation>, Revocation>,

    /// Target delegation -> the revocations naming it.
    denials: Map<Digest<Delegation>, Set<Digest<Revocation>>>,
}

impl MemoryKeyline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// The certificate as received, if present.
    pub fn get(&self, cert: &Digest<Certificate>) -> Option<&Signed<Certificate>> {
        self.certificates.get(cert)
    }

    pub fn delegation(&self, cert: &Digest<Delegation>) -> Option<&Delegation> {
        self.delegations.get(cert)
    }

    pub fn revocation(&self, cert: &Digest<Revocation>) -> Option<&Revocation> {
        self.revocations.get(cert)
    }

    /// Run both strata. Pure in the set.
    fn evaluate(&self) -> Evaluation {
        let covered = self.coverage();
        let live = self.live_set(&covered);
        let cap = self.caps(&covered, &live);
        Evaluation { live, cap }
    }

    /// Stratum 1: `covered(h, ·)` for every revoked delegation.
    fn coverage(&self) -> Map<Digest<Delegation>, Set<Id>> {
        let reaches = self.search(self.edges.keys().copied(), &Params::positive());

        // record(k, n): the last hop onto k is an Admin edge about n.
        let mut record: Map<Id, Set<Id>> = Map::new();
        for (n, by_iss) in &self.edges {
            let Some(levels) = reaches.get(n) else {
                continue;
            };
            for (iss, edges) in by_iss {
                let Some(l) = levels.get(iss) else { continue };
                for h in edges {
                    let d = &self.delegations[h];
                    if (*l).min(d.can) == Access::Admin {
                        record.entry(d.aud).or_default().insert(*n);
                    }
                }
            }
        }

        self.denials
            .iter()
            .map(|(h, revs)| {
                let mut nodes = Set::new();
                for k in revs.iter().map(|r| self.revocations[r].iss) {
                    nodes.insert(k);
                    if let Some(ns) = record.get(&k) {
                        nodes.extend(ns.iter().copied());
                    }
                }
                (*h, nodes)
            })
            .collect()
    }

    /// Stratum 2, existence: the least fixed point of the live set.
    fn live_set(&self, covered: &Map<Digest<Delegation>, Set<Id>>) -> Set<Digest<Delegation>> {
        let mut live: Set<Digest<Delegation>> = Set::new();

        loop {
            // One shared pass with no exclusion serves every uncovered edge and
            // prunes covered ones: reach avoiding N is a subset of reach avoiding ∅.
            let base = self.search(self.edges.keys().copied(), &Params::live(None, &live, None));

            let newly_live: Vec<Digest<Delegation>> = self
                .delegations
                .iter()
                .filter(|(h, _)| !live.contains(h))
                .filter(|(h, d)| {
                    if !reached(&base, d.sub, d.iss) {
                        return false;
                    }
                    match covered.get(h) {
                        None => true,
                        Some(n) => {
                            !(n.contains(&d.iss) || n.contains(&d.sub) || self.renounced(h, d.aud))
                                && reached(
                                    &self.search([d.sub], &Params::live(Some(n), &live, None)),
                                    d.sub,
                                    d.iss,
                                )
                        }
                    }
                })
                .map(|(h, _)| *h)
                .collect();

            if newly_live.is_empty() {
                return live;
            }
            live.extend(newly_live);
        }
    }

    /// Whether the recipient of `h` has revoked it themself. The recipient is
    /// not on the route to the issuer, so this is the one place a revocation's
    /// effect is decided by the signer's identity rather than their record.
    fn renounced(&self, h: &Digest<Delegation>, aud: Id) -> bool {
        self.denials
            .get(h)
            .is_some_and(|revs| revs.iter().any(|r| self.revocations[r].iss == aud))
    }

    /// Stratum 2, level: the greatest fixed point of covered-edge caps,
    /// iterated down from `can`. Uncovered edges are absent; their cap is `can`.
    fn caps(
        &self,
        covered: &Map<Digest<Delegation>, Set<Id>>,
        live: &Set<Digest<Delegation>>,
    ) -> Map<Digest<Delegation>, Access> {
        let mut cap: Map<Digest<Delegation>, Access> = covered
            .keys()
            .filter(|h| live.contains(h))
            .map(|h| (*h, self.delegations[h].can))
            .collect();

        loop {
            let lowered: Vec<(Digest<Delegation>, Access)> = cap
                .iter()
                .filter_map(|(h, current)| {
                    let d = &self.delegations[h];
                    let levels =
                        self.search([d.sub], &Params::live(Some(&covered[h]), live, Some(&cap)));
                    let at_iss = levels
                        .get(&d.sub)
                        .and_then(|m| m.get(&d.iss))
                        .copied()
                        .expect("a live edge's issuer is reachable on its avoiding derivation");
                    let next = d.can.min(at_iss);
                    (next < *current).then_some((*h, next))
                })
                .collect();

            if lowered.is_empty() {
                return cap;
            }
            cap.extend(lowered);
        }
    }

    /// The parameterised reachability search: `level(root, ·)` for each root and
    /// for every node discovered along the way, to a fixed point across roots.
    ///
    /// Returns `root -> node -> level`. A root inside the exclusion set has no
    /// entry for itself and reaches nothing.
    fn search<R: IntoIterator<Item = Id>>(
        &self,
        roots: R,
        params: &Params<'_>,
    ) -> Map<Id, Map<Id, Access>> {
        let mut levels: Map<Id, Map<Id, Access>> =
            roots.into_iter().map(|r| (r, Map::new())).collect();

        loop {
            let mut changed = false;
            let roots: Vec<Id> = levels.keys().copied().collect();

            for r in roots {
                let fresh = self.widest(r, params, &levels);
                for n in fresh.keys() {
                    if !levels.contains_key(n) {
                        levels.insert(*n, Map::new());
                        changed = true;
                    }
                }
                if levels[&r] != fresh {
                    levels.insert(r, fresh);
                    changed = true;
                }
            }

            if !changed {
                return levels;
            }
        }
    }

    /// One bucketed widest-path pass rooted at `r`.
    ///
    /// Steps along edges about `r` (rule 2) and into the members of any node
    /// reached (rule 3), taking members' levels from `others` as computed so
    /// far. Four levels, so a node is finalised the first time it is popped.
    fn widest(
        &self,
        r: Id,
        params: &Params<'_>,
        others: &Map<Id, Map<Id, Access>>,
    ) -> Map<Id, Access> {
        let mut best: Map<Id, Access> = Map::new();
        if params.excludes(&r) {
            return best;
        }

        let mut buckets: [Vec<Id>; 4] = Default::default();
        best.insert(r, Access::Admin);
        buckets[Access::Admin as usize].push(r);

        let relax = |best: &mut Map<Id, Access>, buckets: &mut [Vec<Id>; 4], v: Id, l: Access| {
            if params.excludes(&v) {
                return;
            }
            if best.get(&v).is_none_or(|current| *current < l) {
                best.insert(v, l);
                buckets[l as usize].push(v);
            }
        };

        while let Some((u, lu)) = pop_highest(&mut buckets) {
            if best[&u] != lu {
                continue; // stale entry; u was raised after this was queued
            }

            if let Some(edges) = self.edges.get(&r).and_then(|by_iss| by_iss.get(&u)) {
                for h in edges.iter().filter(|h| params.usable(h)) {
                    let d = &self.delegations[h];
                    relax(&mut best, &mut buckets, d.aud, lu.min(params.cap(h, d.can)));
                }
            }

            if u != r {
                if let Some(members) = others.get(&u) {
                    for (x, lx) in members {
                        relax(&mut best, &mut buckets, *x, lu.min(*lx));
                    }
                }
            }
        }

        best
    }
}

impl Keyline for MemoryKeyline {
    fn insert(&mut self, cert: Verified<Certificate>) -> bool {
        let digest = cert.digest();
        if self.certificates.contains_key(&digest) {
            return false;
        }

        let (payload, signed) = cert.into_parts();
        match payload {
            Certificate::Delegation(d) => {
                let h = d.digest();
                self.edges
                    .entry(d.sub)
                    .or_default()
                    .entry(d.iss)
                    .or_default()
                    .push(h);
                self.delegations.insert(h, d);
            }
            Certificate::Revocation(r) => {
                let k = r.digest();
                self.denials.entry(r.revoke).or_default().insert(k);
                self.revocations.insert(k, r);
            }
        }
        self.certificates.insert(digest, signed);
        true
    }

    fn contains(&self, cert: &Digest<Certificate>) -> bool {
        self.certificates.contains_key(cert)
    }

    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<Revocation>> {
        self.denials
            .get(cert)
            .map(|revs| revs.iter().copied().collect())
            .unwrap_or_default()
    }

    fn effective_access(&self, sub: Id, aud: Id) -> Option<Access> {
        self.levels(sub).get(&aud).copied()
    }

    fn members(&self, sub: Id) -> BTreeMap<Id, Access> {
        self.levels(sub)
            .into_iter()
            .filter(|(id, _)| *id != sub)
            .collect()
    }

    fn is_live(&self, cert: &Digest<Delegation>) -> bool {
        self.delegations.contains_key(cert) && self.evaluate().live.contains(cert)
    }

    fn digest(&self) -> Digest<BTreeSet<Certificate>> {
        set_digest(self.certificates.keys().copied())
    }
}

impl MemoryKeyline {
    /// The live level of every node over `sub`, including `sub` itself.
    fn levels(&self, sub: Id) -> Map<Id, Access> {
        let Evaluation { live, cap } = self.evaluate();
        self.search([sub], &Params::live(None, &live, Some(&cap)))
            .remove(&sub)
            .unwrap_or_default()
    }
}

/// Stratum 2 results.
struct Evaluation {
    live: Set<Digest<Delegation>>,
    cap: Map<Digest<Delegation>, Access>,
}

/// What a search may traverse.
struct Params<'a> {
    /// Nodes a derivation may not touch: `covered(h, ·)` for the edge under test.
    exclude: Option<&'a Set<Id>>,
    /// Edges the search may step along; `None` means every edge (stratum 1).
    live: Option<&'a Set<Digest<Delegation>>>,
    /// Caps on covered edges; absent edges convey their `can`.
    cap: Option<&'a Map<Digest<Delegation>, Access>>,
}

impl<'a> Params<'a> {
    /// Stratum 1: blind to revocations.
    fn positive() -> Params<'static> {
        Params {
            exclude: None,
            live: None,
            cap: None,
        }
    }

    fn live(
        exclude: Option<&'a Set<Id>>,
        live: &'a Set<Digest<Delegation>>,
        cap: Option<&'a Map<Digest<Delegation>, Access>>,
    ) -> Self {
        Params {
            exclude,
            live: Some(live),
            cap,
        }
    }

    fn excludes(&self, id: &Id) -> bool {
        self.exclude.is_some_and(|n| n.contains(id))
    }

    fn usable(&self, h: &Digest<Delegation>) -> bool {
        self.live.is_none_or(|live| live.contains(h))
    }

    fn cap(&self, h: &Digest<Delegation>, can: Access) -> Access {
        self.cap
            .and_then(|cap| cap.get(h).copied())
            .map_or(can, |c| c.min(can))
    }
}

fn reached(levels: &Map<Id, Map<Id, Access>>, root: Id, node: Id) -> bool {
    levels.get(&root).is_some_and(|m| m.contains_key(&node))
}

fn pop_highest(buckets: &mut [Vec<Id>; 4]) -> Option<(Id, Access)> {
    Access::ALL
        .iter()
        .rev()
        .find_map(|l| buckets[*l as usize].pop().map(|id| (id, *l)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{cert, id};

    const DOC: u8 = 1;
    const OWNERS: u8 = 2;
    const MEMBERS: u8 = 3;
    const ALICE: u8 = 4;
    const BROOKE: u8 = 5;
    const CAROL: u8 = 6;
    const MODS: u8 = 7;
    const K: u8 = 8;
    const B: u8 = 9;
    const C: u8 = 10;

    fn d(iss: u8, aud: u8, sub: u8, can: Access) -> Delegation {
        Delegation::new(id(iss), id(aud), id(sub), can)
    }

    fn r(iss: u8, target: &Delegation) -> Revocation {
        Revocation::new(id(iss), target.digest())
    }

    fn graph<I: IntoIterator<Item = Certificate>>(certs: I) -> MemoryKeyline {
        let mut g = MemoryKeyline::new();
        for c in certs {
            g.insert(cert(c));
        }
        g
    }

    fn access(g: &MemoryKeyline, sub: u8, aud: u8) -> Option<Access> {
        g.effective_access(id(sub), id(aud))
    }

    /// Doc -> Owners (root); Owners administers Members; Brooke and Carol are
    /// Owners; Members has Edit over Doc; Alice is a Member (added by Carol).
    fn standard() -> (MemoryKeyline, Delegation, Delegation) {
        let carol_owner = d(OWNERS, CAROL, OWNERS, Access::Admin);
        let alice_member = d(CAROL, ALICE, MEMBERS, Access::Admin);
        let g = graph([
            d(DOC, OWNERS, DOC, Access::Admin).into(),
            d(OWNERS, BROOKE, OWNERS, Access::Admin).into(),
            carol_owner.into(),
            d(MEMBERS, OWNERS, MEMBERS, Access::Admin).into(),
            d(BROOKE, MEMBERS, DOC, Access::Edit).into(),
            alice_member.into(),
        ]);
        (g, carol_owner, alice_member)
    }

    #[test]
    fn empty_graph() {
        let g = MemoryKeyline::new();
        assert_eq!(access(&g, DOC, DOC), Some(Access::Admin));
        assert_eq!(access(&g, DOC, ALICE), None);
        assert!(g.members(id(DOC)).is_empty());
    }

    #[test]
    fn attenuation_and_widest_path() {
        let g = graph([
            d(DOC, ALICE, DOC, Access::Admin).into(),
            d(ALICE, BROOKE, DOC, Access::Read).into(),
            d(BROOKE, CAROL, DOC, Access::Admin).into(),
            d(DOC, CAROL, DOC, Access::Relay).into(),
        ]);
        assert_eq!(access(&g, DOC, ALICE), Some(Access::Admin));
        assert_eq!(access(&g, DOC, BROOKE), Some(Access::Read));
        // min along the chain is Read; the direct Relay route loses to it.
        assert_eq!(access(&g, DOC, CAROL), Some(Access::Read));
    }

    #[test]
    fn ungrounded_edges_are_dead() {
        let stray = d(ALICE, BROOKE, DOC, Access::Admin);
        let g = graph([stray.into(), d(BROOKE, CAROL, DOC, Access::Admin).into()]);
        assert!(!g.is_live(&stray.digest()));
        assert!(g.members(id(DOC)).is_empty());

        // An ungrounded cycle does not certify itself.
        let g = graph([
            d(ALICE, BROOKE, DOC, Access::Admin).into(),
            d(BROOKE, ALICE, DOC, Access::Admin).into(),
        ]);
        assert!(g.members(id(DOC)).is_empty());
    }

    #[test]
    fn membership_composes() {
        let (g, _, _) = standard();
        assert_eq!(access(&g, DOC, OWNERS), Some(Access::Admin));
        assert_eq!(access(&g, DOC, BROOKE), Some(Access::Admin));
        assert_eq!(access(&g, DOC, MEMBERS), Some(Access::Edit));
        // Alice: Admin over Members, clamped to Members' Edit over Doc.
        assert_eq!(access(&g, MEMBERS, ALICE), Some(Access::Admin));
        assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
        // Owners administer Members through Members' root edge.
        assert_eq!(access(&g, MEMBERS, CAROL), Some(Access::Admin));

        let members: Vec<Id> = g.members(id(DOC)).into_keys().collect();
        assert_eq!(members.len(), 5);
        assert!(!members.contains(&id(DOC)));
    }

    #[test]
    fn late_binding_grants_new_documents_to_members() {
        let (mut g, _, _) = standard();
        let other = 11;
        assert_eq!(access(&g, other, ALICE), None);
        g.insert(cert(d(other, MEMBERS, other, Access::Read)));
        assert_eq!(access(&g, other, ALICE), Some(Access::Read));
    }

    #[test]
    fn retraction_is_total() {
        let (mut g, _, alice_member) = standard();
        g.insert(cert(r(CAROL, &alice_member)));
        assert!(!g.is_live(&alice_member.digest()));
        assert_eq!(access(&g, DOC, ALICE), None);
        assert_eq!(access(&g, MEMBERS, ALICE), None);
    }

    #[test]
    fn renunciation_is_total() {
        let (mut g, _, alice_member) = standard();
        g.insert(cert(r(ALICE, &alice_member)));
        assert!(!g.is_live(&alice_member.digest()));
        assert_eq!(access(&g, DOC, ALICE), None);
    }

    #[test]
    fn admin_over_a_transited_node_cuts_deep() {
        // Brooke never signed Alice's membership, but Owners is in Brooke's
        // record and Members' only route to Carol grounds through Owners.
        let (mut g, _, alice_member) = standard();
        g.insert(cert(r(BROOKE, &alice_member)));
        assert!(!g.is_live(&alice_member.digest()));
        assert_eq!(access(&g, DOC, ALICE), None);
        // Carol herself is untouched.
        assert_eq!(access(&g, DOC, CAROL), Some(Access::Admin));
    }

    #[test]
    fn non_admin_cut_is_confined_to_own_node() {
        let k_grant = d(K, ALICE, DOC, Access::Read);
        let (mut g, _, alice_member) = standard();
        g.insert(cert(d(DOC, K, DOC, Access::Read)));
        g.insert(cert(k_grant));
        // K holds only Read; K's record is {K}. Alice's membership never
        // transits K, so K's cut of it is inert.
        g.insert(cert(r(K, &alice_member)));
        assert!(g.is_live(&alice_member.digest()));
        assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
        // K's own hop is K's to cut.
        g.insert(cert(r(K, &k_grant)));
        assert!(!g.is_live(&k_grant.digest()));
    }

    #[test]
    fn ex_admin_record_is_frozen() {
        let (mut g, carol_owner, alice_member) = standard();
        // Brooke boots Carol from Owners; Carol was Alice's sponsor, so Alice
        // dies implicitly. Carol's record still holds Owners.
        g.insert(cert(r(BROOKE, &carol_owner)));
        assert_eq!(access(&g, DOC, CAROL), None);
        assert_eq!(access(&g, DOC, ALICE), None);

        // Brooke re-sponsors Alice; Carol, though booted, can still cut it.
        let brooke_sponsors = d(BROOKE, ALICE, MEMBERS, Access::Admin);
        g.insert(cert(brooke_sponsors));
        assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
        g.insert(cert(r(CAROL, &brooke_sponsors)));
        assert_eq!(access(&g, DOC, ALICE), None);
        assert!(!g.is_live(&alice_member.digest()));
    }

    #[test]
    fn mutual_revocation_leaves_both_cuts_standing() {
        let (mut g, carol_owner, _) = standard();
        let brooke_owner = d(OWNERS, BROOKE, OWNERS, Access::Admin);
        g.insert(cert(r(BROOKE, &carol_owner)));
        g.insert(cert(r(CAROL, &brooke_owner)));
        assert_eq!(access(&g, DOC, BROOKE), None);
        assert_eq!(access(&g, DOC, CAROL), None);
        // The apex is bricked: nothing below survives.
        assert!(g.members(id(DOC)).into_keys().eq([id(OWNERS)]));
    }

    #[test]
    fn root_edge_is_undeniable_by_admins() {
        let (mut g, _, _) = standard();
        let root = d(DOC, OWNERS, DOC, Access::Admin);
        g.insert(cert(r(BROOKE, &root)));
        // Doc is in nobody's record; the route to Doc is [Doc] alone.
        assert!(g.is_live(&root.digest()));
        assert_eq!(access(&g, DOC, BROOKE), Some(Access::Admin));
    }

    #[test]
    fn covered_edges_are_clamped_not_just_gated() {
        // K administers Mods. B is a Mod (Admin over Doc through Mods) and
        // separately holds Read over Doc from Owners. B grants C Admin; K
        // revokes it. C keeps only what B has independently of Mods.
        let h = d(B, C, DOC, Access::Admin);
        let mut g = graph([
            d(DOC, OWNERS, DOC, Access::Admin).into(),
            d(OWNERS, MODS, DOC, Access::Admin).into(),
            d(MODS, K, MODS, Access::Admin).into(),
            d(K, B, MODS, Access::Admin).into(),
            d(OWNERS, B, DOC, Access::Read).into(),
            h.into(),
        ]);
        assert_eq!(access(&g, DOC, B), Some(Access::Admin));
        assert_eq!(access(&g, DOC, C), Some(Access::Admin));

        g.insert(cert(r(K, &h)));
        assert!(g.is_live(&h.digest()));
        assert_eq!(access(&g, DOC, B), Some(Access::Admin));
        assert_eq!(access(&g, DOC, C), Some(Access::Read));
    }

    #[test]
    fn revocation_may_arrive_before_its_target() {
        let (mut g, _, alice_member) = standard();
        let mut early = MemoryKeyline::new();
        assert!(early.insert(cert(r(CAROL, &alice_member))));
        assert!(early.members(id(DOC)).is_empty());
        for c in [
            d(DOC, OWNERS, DOC, Access::Admin),
            d(OWNERS, CAROL, OWNERS, Access::Admin),
            d(MEMBERS, OWNERS, MEMBERS, Access::Admin),
            d(BROOKE, MEMBERS, DOC, Access::Edit),
            d(OWNERS, BROOKE, OWNERS, Access::Admin),
            alice_member,
        ] {
            early.insert(cert(c));
        }
        g.insert(cert(r(CAROL, &alice_member)));
        assert_eq!(early.members(id(DOC)), g.members(id(DOC)));
        assert_eq!(early.digest(), g.digest());
        assert_eq!(access(&early, DOC, ALICE), None);
    }

    #[test]
    fn insert_is_idempotent_and_reports_duplicates() {
        let (mut g, _, alice_member) = standard();
        let before = g.digest();
        assert!(!g.insert(cert(alice_member)));
        assert_eq!(g.digest(), before);
        assert_eq!(g.len(), 6);

        let rev = r(CAROL, &alice_member);
        g.insert(cert(rev));
        assert!(!g.insert(cert(alice_member)));
        assert!(g
            .revocations_naming(&alice_member.digest())
            .into_iter()
            .eq([rev.digest()]));
    }

    #[test]
    fn reissue_with_seen_heals() {
        let (mut g, _, alice_member) = standard();
        let rev = r(CAROL, &alice_member);
        g.insert(cert(rev));
        assert_eq!(access(&g, DOC, ALICE), None);

        let healed = alice_member.reissue(rev.digest());
        assert_ne!(healed.digest(), alice_member.digest());
        assert!(g.insert(cert(healed)));
        assert!(g.is_live(&healed.digest()));
        assert!(!g.is_live(&alice_member.digest()));
        assert_eq!(access(&g, DOC, ALICE), Some(Access::Edit));
    }

    #[test]
    fn order_independent() {
        let (g, carol_owner, alice_member) = standard();
        let mut certs: Vec<Certificate> = g
            .certificates
            .values()
            .map(|s| {
                s.encoded()
                    .decode()
                    .expect("stored certificates are canonical")
            })
            .collect();
        certs.push(r(BROOKE, &carol_owner).into());
        certs.push(r(K, &alice_member).into());

        let forward = graph(certs.iter().copied());
        certs.reverse();
        let backward = graph(certs);

        assert_eq!(forward.digest(), backward.digest());
        for sub in [DOC, OWNERS, MEMBERS] {
            assert_eq!(forward.members(id(sub)), backward.members(id(sub)));
        }
        assert_eq!(
            forward.is_live(&alice_member.digest()),
            backward.is_live(&alice_member.digest())
        );
    }
}
