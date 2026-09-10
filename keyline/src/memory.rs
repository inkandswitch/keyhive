//! [`MemoryKeyline`]: the in-memory reference implementation of [`Keyline`].
//!
//! This is the evaluation program in `design/keyline/implementation.md`
//! executed literally, with no caching. Every query recomputes stratum 1
//! (admin reach and coverage) and stratum 2 (the live set and edge caps)
//! from the certificate set, then runs one widest-path search rooted at the
//! queried subject. Anything faster MUST agree with it on every set; the
//! conformance suite is how that is checked.
//!
//! ```text
//! stratum 1   reaches   = search(all subjects, exclude ∅, every edge, cap = can)
//!             admin_reach(k) = { n : k reaches n at Admin } ∪ {k}
//!             covered(h) = ⋃ admin_reach(k) for every k revoking h
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
use tracing::{debug, instrument, trace};

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
    #[instrument(level = "debug", skip(self), fields(
        delegations = self.delegations.len(),
        revocations = self.revocations.len(),
    ))]
    fn evaluate(&self) -> Evaluation {
        let contexts = self.contexts(self.coverage());
        let live = self.live_set(&contexts);
        let cap = self.caps(&contexts, &live);
        debug!(
            contexts = contexts.len(),
            live = live.len(),
            dead = self.delegations.len() - live.len(),
            clamped = cap.values().filter(|c| **c < Access::Admin).count(),
            "evaluated"
        );
        Evaluation { live, cap }
    }

    /// The live level of every node over `sub`, including `sub` itself.
    fn levels(&self, sub: Id) -> Map<Id, Access> {
        let Evaluation { live, cap } = self.evaluate();
        self.search([sub], &Params::live(None, &live, Some(&cap)))
            .remove(&sub)
            .unwrap_or_default()
    }

    /// Group covered delegations by exclusion set. `covered(h, ·)` depends
    /// only on who revoked `h`, so one key's revocation spree yields one set;
    /// every edge in a context shares its searches.
    fn contexts(&self, covered: Map<Digest<Delegation>, Set<Id>>) -> Vec<Context> {
        let mut by_set: BTreeMap<BTreeSet<Id>, Context> = BTreeMap::new();
        for (h, exclude) in covered {
            let key: BTreeSet<Id> = exclude.iter().copied().collect();
            by_set
                .entry(key)
                .or_insert_with(|| Context {
                    exclude,
                    edges: Vec::new(),
                })
                .edges
                .push(h);
        }
        by_set.into_values().collect()
    }

    /// Stratum 1: `covered(h, ·)` for every revoked delegation.
    fn coverage(&self) -> Map<Digest<Delegation>, Set<Id>> {
        let reaches = self.search(self.edges.keys().copied(), &Params::positive());

        // admin_reach(k, n): k reaches n at Admin, however derived.
        let mut reach: Map<Id, Set<Id>> = Map::new();
        for (n, levels) in &reaches {
            for (k, l) in levels {
                if *l == Access::Admin {
                    reach.entry(*k).or_default().insert(*n);
                }
            }
        }

        self.denials
            .iter()
            .map(|(h, revs)| {
                let mut nodes = Set::new();
                for k in revs.iter().map(|r| self.revocations[r].iss) {
                    nodes.insert(k);
                    if let Some(ns) = reach.get(&k) {
                        nodes.extend(ns.iter().copied());
                    }
                }
                (*h, nodes)
            })
            .collect()
    }

    /// Stratum 2, existence: the least fixed point of the live set.
    fn live_set(&self, contexts: &[Context]) -> Set<Digest<Delegation>> {
        let covered: Set<Digest<Delegation>> = contexts
            .iter()
            .flat_map(|c| c.edges.iter().copied())
            .collect();
        let mut live: Set<Digest<Delegation>> = Set::new();

        loop {
            // One shared pass with no exclusion serves every uncovered edge and
            // prunes covered ones: reach avoiding N is a subset of reach avoiding ∅.
            let base = self.search(self.edges.keys().copied(), &Params::live(None, &live, None));

            let mut newly_live: Vec<Digest<Delegation>> = self
                .delegations
                .iter()
                .filter(|(h, d)| {
                    !live.contains(h) && !covered.contains(h) && reached(&base, d.sub, d.iss)
                })
                .map(|(h, _)| *h)
                .collect();

            for ctx in contexts {
                // Cheap rejections first; the search runs once per context.
                let candidates: Vec<(&Digest<Delegation>, &Delegation)> = ctx
                    .edges
                    .iter()
                    .filter(|h| !live.contains(h))
                    .filter_map(|h| self.delegations.get(h).map(|d| (h, d)))
                    .filter(|(h, d)| {
                        !(ctx.exclude.contains(&d.iss)
                            || ctx.exclude.contains(&d.sub)
                            || self.renounced(h, d.aud))
                            && reached(&base, d.sub, d.iss)
                    })
                    .collect();
                if candidates.is_empty() {
                    continue;
                }

                let levels = self.search(
                    candidates.iter().map(|(_, d)| d.sub),
                    &Params::live(Some(&ctx.exclude), &live, None),
                );
                newly_live.extend(
                    candidates
                        .iter()
                        .filter(|(_, d)| reached(&levels, d.sub, d.iss))
                        .map(|(h, _)| **h),
                );
            }

            if newly_live.is_empty() {
                return live;
            }
            trace!(
                newly_live = newly_live.len(),
                live = live.len(),
                "live fixpoint round"
            );
            live.extend(newly_live);
        }
    }

    /// Whether the recipient of `h` has signed a revocation of it. The recipient is
    /// not on the route to the issuer, so this is the one place a revocation's
    /// effect is decided by the signer's identity rather than their admin reach.
    fn renounced(&self, h: &Digest<Delegation>, aud: Id) -> bool {
        self.denials
            .get(h)
            .is_some_and(|revs| revs.iter().any(|r| self.revocations[r].iss == aud))
    }

    /// Stratum 2, level: the greatest fixed point of covered-edge caps,
    /// iterated down from `can`. Uncovered edges are absent; their cap is `can`.
    fn caps(
        &self,
        contexts: &[Context],
        live: &Set<Digest<Delegation>>,
    ) -> Map<Digest<Delegation>, Access> {
        let mut cap: Map<Digest<Delegation>, Access> = contexts
            .iter()
            .flat_map(|c| c.edges.iter())
            .filter(|h| live.contains(h))
            .map(|h| (*h, self.delegations[h].can))
            .collect();

        loop {
            let mut lowered: Vec<(Digest<Delegation>, Access)> = Vec::new();

            for ctx in contexts {
                let edges: Vec<(&Digest<Delegation>, &Delegation)> = ctx
                    .edges
                    .iter()
                    .filter(|h| live.contains(h))
                    .map(|h| (h, &self.delegations[h]))
                    .collect();
                if edges.is_empty() {
                    continue;
                }

                let levels = self.search(
                    edges.iter().map(|(_, d)| d.sub),
                    &Params::live(Some(&ctx.exclude), live, Some(&cap)),
                );
                for (h, d) in edges {
                    let at_iss = levels
                        .get(&d.sub)
                        .and_then(|m| m.get(&d.iss))
                        .copied()
                        .expect("a live edge's issuer is reachable on its avoiding derivation");
                    let next = d.can.min(at_iss);
                    if next < cap[h] {
                        lowered.push((*h, next));
                    }
                }
            }

            if lowered.is_empty() {
                return cap;
            }
            trace!(lowered = lowered.len(), "cap descent round");
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
    #[instrument(level = "debug", skip(self, cert), fields(digest = %cert.digest()))]
    fn insert(&mut self, cert: Verified<Certificate>) -> bool {
        let digest = cert.digest();
        if self.certificates.contains_key(&digest) {
            debug!("duplicate certificate; not inserted");
            return false;
        }

        let (payload, signed) = cert.into_parts();
        match payload {
            Certificate::Delegation(d) => {
                let h = d.digest();
                debug!(iss = %d.iss, aud = %d.aud, sub = %d.sub, can = %d.can, seen = d.seen.is_some(), "delegation inserted");
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
                debug!(
                    iss = %r.iss,
                    revoke = %r.revoke,
                    target_known = self.delegations.contains_key(&r.revoke),
                    "revocation inserted"
                );
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

    #[instrument(level = "trace", skip(self), fields(%sub, %aud))]
    fn effective_access(&self, sub: Id, aud: Id) -> Option<Access> {
        self.levels(sub).get(&aud).copied()
    }

    #[instrument(level = "trace", skip(self), fields(%sub))]
    fn members(&self, sub: Id) -> BTreeMap<Id, Access> {
        self.levels(sub)
            .into_iter()
            .filter(|(id, _)| *id != sub)
            .collect()
    }

    #[instrument(level = "trace", skip(self), fields(%cert))]
    fn is_live(&self, cert: &Digest<Delegation>) -> bool {
        self.delegations.contains_key(cert) && self.evaluate().live.contains(cert)
    }

    fn digest(&self) -> Digest<BTreeSet<Certificate>> {
        set_digest(self.certificates.keys().copied())
    }
}

/// Covered delegations sharing one exclusion set, and therefore one search.
struct Context {
    exclude: Set<Id>,
    edges: Vec<Digest<Delegation>>,
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
    use crate::{
        conformance::{d, scenarios, scenarios::standard, DOC, OWNERS},
        test_utils::cert,
    };

    #[cfg(feature = "arbitrary")]
    use crate::conformance::laws;

    // One test per scenario and law. Add new ones to `scenarios.rs` / `laws.rs`
    // and list them here; a second backend copies this block.
    #[test]
    fn empty_graph() {
        scenarios::empty_graph::<MemoryKeyline>();
    }

    #[test]
    fn attenuation_and_widest_path() {
        scenarios::attenuation_and_widest_path::<MemoryKeyline>();
    }

    #[test]
    fn ungrounded_edges_are_dead() {
        scenarios::ungrounded_edges_are_dead::<MemoryKeyline>();
    }

    #[test]
    fn membership_composes() {
        scenarios::membership_composes::<MemoryKeyline>();
    }

    #[test]
    fn late_binding_grants_new_documents_to_members() {
        scenarios::late_binding_grants_new_documents_to_members::<MemoryKeyline>();
    }

    #[test]
    fn retraction_is_total() {
        scenarios::retraction_is_total::<MemoryKeyline>();
    }

    #[test]
    fn renunciation_is_total() {
        scenarios::renunciation_is_total::<MemoryKeyline>();
    }

    #[test]
    fn admin_over_a_transited_node_cuts_deep() {
        scenarios::admin_over_a_transited_node_cuts_deep::<MemoryKeyline>();
    }

    #[test]
    fn non_admin_cut_is_confined_to_own_node() {
        scenarios::non_admin_cut_is_confined_to_own_node::<MemoryKeyline>();
    }

    #[test]
    fn ex_admin_reach_is_frozen() {
        scenarios::ex_admin_reach_is_frozen::<MemoryKeyline>();
    }

    #[test]
    fn mutual_revocation_leaves_both_cuts_standing() {
        scenarios::mutual_revocation_leaves_both_cuts_standing::<MemoryKeyline>();
    }

    #[test]
    fn apex_admin_can_deny_the_root_edge() {
        scenarios::apex_admin_can_deny_the_root_edge::<MemoryKeyline>();
    }

    #[test]
    fn edit_rooted_root_edge_is_undeniable() {
        scenarios::edit_rooted_root_edge_is_undeniable::<MemoryKeyline>();
    }

    #[test]
    fn senior_role_admin_cuts_inside_junior_role() {
        scenarios::senior_role_admin_cuts_inside_junior_role::<MemoryKeyline>();
    }

    #[test]
    fn supply_is_daisy_chained() {
        scenarios::supply_is_daisy_chained::<MemoryKeyline>();
    }

    #[test]
    fn covered_edges_are_clamped_not_just_gated() {
        scenarios::covered_edges_are_clamped_not_just_gated::<MemoryKeyline>();
    }

    #[test]
    fn revocation_may_arrive_before_its_target() {
        scenarios::revocation_may_arrive_before_its_target::<MemoryKeyline>();
    }

    #[test]
    fn insert_is_idempotent_and_reports_duplicates() {
        scenarios::insert_is_idempotent_and_reports_duplicates::<MemoryKeyline>();
    }

    #[test]
    fn reissue_with_seen_heals() {
        scenarios::reissue_with_seen_heals::<MemoryKeyline>();
    }

    #[test]
    fn rotation_escapes_frozen_reach() {
        scenarios::rotation_escapes_frozen_reach::<MemoryKeyline>();
    }

    #[test]
    fn unknown_revocation_is_inert() {
        scenarios::unknown_revocation_is_inert::<MemoryKeyline>();
    }

    #[test]
    fn signed_certificates_agree_with_fixtures() {
        scenarios::signed_certificates_agree_with_fixtures::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn matches_naive_oracle_without_revocations() {
        laws::matches_naive_oracle_without_revocations::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn matches_naive_oracle_with_revocations() {
        laws::matches_naive_oracle_with_revocations::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn order_independent() {
        laws::order_independent::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn idempotent() {
        laws::idempotent::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn revocations_only_deny() {
        laws::revocations_only_deny::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn digest_identifies_the_set() {
        laws::digest_identifies_the_set::<MemoryKeyline>();
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn queries_are_consistent() {
        laws::queries_are_consistent::<MemoryKeyline>();
    }

    #[test]
    fn inherent_accessors() {
        let (g, _, _) = standard::<MemoryKeyline>();
        assert_eq!(g.len(), 6);
        assert!(!g.is_empty());
        let root = d(DOC, OWNERS, DOC, Access::Admin);
        assert_eq!(g.delegation(&root.digest()), Some(&root));
        assert!(g.get(&cert(root).digest()).is_some());
        assert!(g.revocation(&Digest::from([0u8; 32])).is_none());
    }
}
