//! [`MemoryKeyline`]: the in-memory reference implementation of [`Keyline`].
//!
//! This is the evaluation program in `design/keyline/implementation.md`
//! executed literally, with no caching. Every query recomputes stratum 1
//! (admin reach and coverage) and stratum 2 (the live set and edge caps)
//! from the certificate set, then runs one widest-path search rooted at the
//! queried subject. Any faster backend must agree with it on every set; the
//! conformance suite is how that is checked.
//!
//! Without caching, stratum 1 is global, so a query costs what the whole
//! replica costs, not what the queried subject costs. Without demand-driven
//! evaluation, `effective_power` materializes the subject's entire row before
//! indexing into it, so a point query costs what `members` costs. Both suit an
//! embedded replica holding one document's closure, and not a relay.
//!
//! ```text
//! stratum 1   reaches   = search(all subjects, exclude ∅, every edge, cap = power)
//!             admin_reach(k) = { n : k reaches n at Admin } ∪ {k}
//!             covered(h) = ⋃ admin_reach(k) for every k revoking h
//!
//! stratum 2   live      = least fixed point:  h joins when issuer(h) is reachable
//!                         from subject(h) over live edges avoiding covered(h),
//!                         and audience(h) has not revoked h itself
//!             cap       = least fixed point from Relay: covered h conveys at most
//!                         the level issuer(h) holds on a derivation avoiding covered(h)
//!
//! query       search(s, exclude ∅, live edges, cap)
//! ```
//!
//! `search` is one procedure: a bucketed widest-path pass per root, iterated to
//! a fixed point across every root it discovers, because `subject` composes (a
//! node's members inherit what the node reaches).

use crate::{
    certificate::Certificate,
    collections::{Map, Set},
    contract::{set_digest, CertificateSet, Keyline},
    delegation::Delegation,
    id::Id,
    power::Power,
    revocation::{Revocation, RevocationId},
    signed::{Signed, Verified},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::digest::Digest;
use tracing::{debug, instrument, trace};

/// The in-memory reference [`Keyline`].
///
/// Plain maps of plain data: no interior mutability, so `Send + Sync` hold and
/// `&self` queries may run in parallel behind a read lock.
#[derive(Debug, Clone)]
pub struct MemoryKeyline<W> {
    /// The set itself, keyed by certificate identity. Retained as received so
    /// certificates can be forwarded without re-encoding.
    certificates: Map<Digest<Certificate<W>>, Signed<Certificate<W>>>,

    delegations: Map<Digest<Delegation>, Delegation>,

    /// `subject -> issuer -> edges about subject issued by issuer`: the adjacency the search walks.
    edges: Map<Id, Map<Id, Vec<Digest<Delegation>>>>,

    revocations: Map<Digest<RevocationId>, Revocation<W>>,

    /// Target delegation -> the revocations naming it.
    revocations_of: Map<Digest<Delegation>, Set<Digest<RevocationId>>>,
}

impl<W> MemoryKeyline<W> {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many certificates are in the set.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// The certificate as received, if present.
    pub fn get(&self, cert: &Digest<Certificate<W>>) -> Option<&Signed<Certificate<W>>> {
        self.certificates.get(cert)
    }

    /// The delegation with this payload digest, if present.
    pub fn delegation(&self, cert: &Digest<Delegation>) -> Option<&Delegation> {
        self.delegations.get(cert)
    }

    /// The revocation with this payload digest, if present.
    pub fn revocation(&self, cert: &Digest<RevocationId>) -> Option<&Revocation<W>> {
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
            clamped = cap
                .iter()
                .filter(|(h, c)| self.delegations.get(*h).is_some_and(|d| **c < d.power))
                .count(),
            "evaluated"
        );
        Evaluation { live, cap }
    }

    /// The live level of every node over `subject`, including `subject` itself.
    fn levels(&self, subject: Id) -> Map<Id, Power> {
        let Evaluation { live, cap } = self.evaluate();
        self.search([subject], &Params::live(None, &live, Some(&cap)))
            .remove(&subject)
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

    /// Stratum 1: `covered(h, ·)` for every revoked delegation, restricted to
    /// nodes that could lie on a route for `h`.
    ///
    /// A route for `h` transits only nodes with standing over `subject(h)`, so
    /// covering any other node changes nothing: `h` then behaves exactly as an
    /// uncovered edge. Dropping those nodes, and `h` when none remain, keeps a
    /// revocation by a key with no reach over `h`'s subject from costing a
    /// context, and so a search per round.
    fn coverage(&self) -> Map<Digest<Delegation>, Set<Id>> {
        let reaches = self.search(self.edges.keys().copied(), &Params::positive());

        // admin_reach(k, n): k reaches n at Admin, however derived.
        let mut reach: Map<Id, Set<Id>> = Map::new();
        for (n, levels) in &reaches {
            for (k, l) in levels {
                if *l == Power::Admin {
                    reach.entry(*k).or_default().insert(*n);
                }
            }
        }

        self.revocations_of
            .iter()
            .filter_map(|(h, ids)| {
                let on_routes = reaches.get(&self.delegations.get(h)?.subject)?;
                let nodes: Set<Id> = ids
                    .iter()
                    .filter_map(|r| self.revocations.get(r))
                    .flat_map(|r| {
                        core::iter::once(r.issuer)
                            .chain(reach.get(&r.issuer).into_iter().flatten().copied())
                    })
                    .filter(|n| on_routes.contains_key(n))
                    .collect();
                (!nodes.is_empty()).then_some((*h, nodes))
            })
            .collect()
    }

    /// Stratum 2, existence: the least fixed point of the live set.
    ///
    /// Semi-naive iteration: each round derives what it can from the live set
    /// so far, keeps only what is new (`derived \ live`), and stops when
    /// nothing is. It terminates because `live` only grows within the finite
    /// set of delegations.
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

            let mut derived: Set<Digest<Delegation>> = self
                .delegations
                .iter()
                .filter(|(h, d)| {
                    !live.contains(h) && !covered.contains(h) && reached(&base, d.subject, d.issuer)
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
                        !ctx.excludes_an_endpoint(d)
                            && !self.revoked_by_audience(h, d.audience)
                            && reached(&base, d.subject, d.issuer)
                    })
                    .collect();
                if candidates.is_empty() {
                    continue;
                }

                let levels = self.search(
                    candidates.iter().map(|(_, d)| d.subject),
                    &Params::live(Some(&ctx.exclude), &live, None),
                );
                derived.extend(
                    candidates
                        .iter()
                        .filter(|(_, d)| reached(&levels, d.subject, d.issuer))
                        .map(|(h, _)| **h),
                );
            }

            let newly_live: Vec<Digest<Delegation>> = derived.difference(&live).copied().collect();
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

    /// Whether the audience of `h` has signed a revocation of it. The audience is
    /// not on the route to the issuer, so this is the one place a revocation's
    /// effect is decided by the signer's identity rather than their admin reach.
    fn revoked_by_audience(&self, h: &Digest<Delegation>, audience: Id) -> bool {
        self.revocations_of.get(h).is_some_and(|ids| {
            ids.iter()
                .filter_map(|id| self.revocations.get(id))
                .any(|revocation| revocation.issuer == audience)
        })
    }

    /// Stratum 2, level: the least fixed point of covered-edge caps, rising
    /// from `Relay`. Uncovered edges are absent; their cap is `power`.
    ///
    /// A live covered edge conveys at least `Relay`: being live means its
    /// issuer has a grounded derivation that avoids `covered(h)`. Each round
    /// raises a cap to `min(power, issuer's level on that derivation)` under
    /// the current caps, and iteration stops when a round changes nothing.
    /// Rising from the bottom is what keeps levels grounded: two covered edges
    /// on each other's avoiding derivation cannot lift each other above what
    /// some derivation outside the cycle supports. Caps only rise, within
    /// `power`, so the iteration terminates.
    fn caps(
        &self,
        contexts: &[Context],
        live: &Set<Digest<Delegation>>,
    ) -> Map<Digest<Delegation>, Power> {
        // `live` is fixed for the whole iteration, so each context's live
        // covered edges are too.
        let edges_by_context: Vec<(&Context, Vec<_>)> = contexts
            .iter()
            .map(|ctx| {
                let edges = ctx
                    .edges
                    .iter()
                    .filter(|h| live.contains(h))
                    .filter_map(|h| self.delegations.get(h).map(|d| (h, d)))
                    .collect::<Vec<_>>();
                (ctx, edges)
            })
            .filter(|(_, edges)| !edges.is_empty())
            .collect();

        let mut cap: Map<Digest<Delegation>, Power> = edges_by_context
            .iter()
            .flat_map(|(_, edges)| edges.iter().map(|(h, _)| (**h, Power::Relay)))
            .collect();

        loop {
            let mut next = cap.clone();

            for (ctx, edges) in &edges_by_context {
                let levels = self.search(
                    edges.iter().map(|(_, d)| d.subject),
                    &Params::live(Some(&ctx.exclude), live, Some(&cap)),
                );
                for (h, d) in edges {
                    // Liveness found a grounded avoiding derivation, so the
                    // issuer is reached; a miss would leave the cap at `Relay`.
                    if let Some(at_iss) = levels.get(&d.subject).and_then(|m| m.get(&d.issuer)) {
                        let raised = cap[*h].max(d.power.min(*at_iss));
                        next.insert(**h, raised);
                    }
                }
            }

            if next == cap {
                return cap;
            }
            trace!("cap ascent round");
            cap = next;
        }
    }

    /// The parameterised reachability search: `level(root, ·)` for each root and
    /// for every node discovered along the way, to a fixed point across roots.
    ///
    /// Returns `root -> node -> level`. A root inside the exclusion set has no
    /// entry for itself and reaches nothing.
    ///
    /// Each round recomputes every root in place, so later roots see earlier
    /// roots' updates within the round, and stops when a whole round leaves
    /// the map unchanged. Levels only grow and roots are only added, within
    /// finitely many nodes, so the map must stop changing.
    fn search<R: IntoIterator<Item = Id>>(
        &self,
        roots: R,
        params: &Params<'_>,
    ) -> Map<Id, Map<Id, Power>> {
        let mut levels: Map<Id, Map<Id, Power>> =
            roots.into_iter().map(|r| (r, Map::new())).collect();

        loop {
            let roots: Vec<Id> = levels.keys().copied().collect();
            let mut changed = false;

            for r in roots {
                let fresh = self.widest(r, params, &levels);
                // Only nodes that are the subject of some delegation can contribute
                // through rule 3: for any other n, reaches(n, ·) is just {n}, and
                // composing it yields reaches(s, n), which we already have.
                for n in fresh.keys().filter(|n| self.edges.contains_key(n)) {
                    if !levels.contains_key(n) {
                        levels.insert(*n, Map::new());
                        changed = true;
                    }
                }
                changed |= levels.get(&r) != Some(&fresh);
                levels.insert(r, fresh);
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
    /// far.
    ///
    /// Lazy Dijkstra over four levels: every step queues its level, buckets
    /// pop highest first, and a step never raises a level, so a node's first
    /// pop carries its final level. That pop settles the node into `best`;
    /// later, lower entries for it are skipped. Each node is expanded at most
    /// once, which bounds the loop.
    fn widest(
        &self,
        r: Id,
        params: &Params<'_>,
        others: &Map<Id, Map<Id, Power>>,
    ) -> Map<Id, Power> {
        let mut best: Map<Id, Power> = Map::new();
        if params.excludes(&r) {
            return best;
        }

        let mut buckets: [Vec<Id>; Power::ALL.len()] = Default::default();
        buckets[Power::Admin.rank()].push(r);

        let relax = |buckets: &mut [Vec<Id>; Power::ALL.len()], v: Id, l: Power| {
            if params.excludes(&v) {
                return;
            }
            buckets[l.rank()].push(v);
        };

        while let Some((u, lu)) = pop_highest(&mut buckets) {
            if best.contains_key(&u) {
                continue; // settled earlier, at this level or higher
            }
            best.insert(u, lu);

            if let Some(edges) = self.edges.get(&r).and_then(|by_iss| by_iss.get(&u)) {
                for h in edges.iter().filter(|h| params.usable(h)) {
                    let Some(d) = self.delegations.get(h) else {
                        continue;
                    };
                    relax(&mut buckets, d.audience, lu.min(params.cap(h, d.power)));
                }
            }

            if u != r {
                if let Some(members) = others.get(&u) {
                    for (x, lx) in members {
                        relax(&mut buckets, *x, lu.min(*lx));
                    }
                }
            }
        }

        best
    }
}

// Manual: the derive would add a spurious `W: Default` bound, which no field needs.
impl<W> Default for MemoryKeyline<W> {
    fn default() -> Self {
        MemoryKeyline {
            certificates: Map::new(),
            delegations: Map::new(),
            edges: Map::new(),
            revocations: Map::new(),
            revocations_of: Map::new(),
        }
    }
}

impl<W: Encode + Decode> Keyline for MemoryKeyline<W> {
    type RetentionWatermark = W;

    #[instrument(level = "debug", skip(self, cert), fields(digest = %cert.digest()))]
    fn insert(&mut self, cert: Verified<Certificate<W>>) -> bool {
        let digest = cert.digest();
        if self.certificates.contains_key(&digest) {
            debug!("duplicate certificate; not inserted");
            return false;
        }

        let (payload, signed) = cert.into_parts();
        match payload {
            Certificate::Delegation(d) => {
                let h = d.digest();
                debug!(issuer = %d.issuer, audience = %d.audience, subject = %d.subject, power = %d.power, citation = d.citation.is_some(), "delegation inserted");
                self.edges
                    .entry(d.subject)
                    .or_default()
                    .entry(d.issuer)
                    .or_default()
                    .push(h);
                self.delegations.insert(h, d);
            }
            Certificate::Revocation(r) => {
                let k = r.digest();
                debug!(
                    issuer = %r.issuer,
                    revoke = %r.revoke,
                    target_known = self.delegations.contains_key(&r.revoke),
                    "revocation inserted"
                );
                self.revocations_of.entry(r.revoke).or_default().insert(k);
                self.revocations.insert(k, r);
            }
        }
        self.certificates.insert(digest, signed);
        true
    }

    fn contains(&self, cert: &Digest<Certificate<W>>) -> bool {
        self.certificates.contains_key(cert)
    }

    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<RevocationId>> {
        self.revocations_of
            .get(cert)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    #[instrument(level = "trace", skip(self), fields(%subject, %audience))]
    fn effective_power(&self, subject: Id, audience: Id) -> Option<Power> {
        self.levels(subject).get(&audience).copied()
    }

    #[instrument(level = "trace", skip(self), fields(%subject))]
    fn members(&self, subject: Id) -> BTreeMap<Id, Power> {
        self.levels(subject)
            .into_iter()
            .filter(|(id, _)| *id != subject)
            .collect()
    }

    #[instrument(level = "trace", skip(self), fields(%cert))]
    fn is_live(&self, cert: &Digest<Delegation>) -> bool {
        self.delegations.contains_key(cert) && self.evaluate().live.contains(cert)
    }

    fn digest(&self) -> Digest<CertificateSet<W>> {
        set_digest(self.certificates.keys().copied())
    }
}

/// Covered delegations sharing one exclusion set, and therefore one search.
struct Context {
    exclude: Set<Id>,
    edges: Vec<Digest<Delegation>>,
}

impl Context {
    /// Whether `d`'s issuer or subject is excluded.
    ///
    /// A shortcut only: the context search excludes these nodes anyway (an
    /// excluded subject reaches nothing, an excluded issuer is never reached),
    /// so `d` could not be found live there. Skipping it saves a search root.
    /// Because the answer cannot change, mutation testing skips this function
    /// (`.cargo/mutants.toml`).
    fn excludes_an_endpoint(&self, d: &Delegation) -> bool {
        self.exclude.contains(&d.issuer) || self.exclude.contains(&d.subject)
    }
}

/// Stratum 2 results.
struct Evaluation {
    live: Set<Digest<Delegation>>,
    cap: Map<Digest<Delegation>, Power>,
}

/// What a search may traverse.
struct Params<'a> {
    /// Nodes a derivation may not touch: `covered(h, ·)` for the edge under test.
    exclude: Option<&'a Set<Id>>,
    /// Edges the search may step along; `None` means every edge (stratum 1).
    live: Option<&'a Set<Digest<Delegation>>>,
    /// Caps on covered edges; absent edges convey their `power`.
    cap: Option<&'a Map<Digest<Delegation>, Power>>,
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
        cap: Option<&'a Map<Digest<Delegation>, Power>>,
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

    fn cap(&self, h: &Digest<Delegation>, power: Power) -> Power {
        self.cap
            .and_then(|cap| cap.get(h).copied())
            .map_or(power, |c| c.min(power))
    }
}

fn reached(levels: &Map<Id, Map<Id, Power>>, root: Id, node: Id) -> bool {
    levels.get(&root).is_some_and(|m| m.contains_key(&node))
}

fn pop_highest(buckets: &mut [Vec<Id>; Power::ALL.len()]) -> Option<(Id, Power)> {
    Power::ALL
        .iter()
        .rev()
        .find_map(|l| buckets[l.rank()].pop().map(|id| (id, *l)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        cert,
        conformance::{d, scenarios::standard, DOC, OWNERS},
    };

    #[cfg(feature = "arbitrary")]
    use crate::test_utils::conformance::laws;

    crate::keyline_conformance!(MemoryKeyline<()>);

    /// A watermark type with a variable-length encoding.
    ///
    /// At `W = ()` a `retain` entry carries a subject and an empty watermark,
    /// so the laws above never see watermark bytes. The tests below re-run
    /// the laws about `retain` with watermarks that carry bytes.
    #[cfg(feature = "arbitrary")]
    type Watermark = Vec<u8>;

    /// Both oracles keep only `(issuer, revoke)`, so neither can read a
    /// watermark even by accident. Agreement therefore shows that the
    /// evaluator does not read one either.
    #[cfg(feature = "arbitrary")]
    #[test]
    fn retain_does_not_affect_authority() {
        laws::matches_naive_oracle_with_revocations::<MemoryKeyline<Watermark>>();
        laws::matches_threshold_oracle::<MemoryKeyline<Watermark>>();
        laws::retain_is_inert::<MemoryKeyline<Watermark>>();
    }

    /// The converse: `retain` is covered by the certificate digest, so two
    /// revocations differing only there are two certificates, not one.
    #[cfg(feature = "arbitrary")]
    #[test]
    fn retain_is_part_of_set_identity() {
        laws::digest_identifies_the_set::<MemoryKeyline<Watermark>>();
    }

    #[test]
    fn inherent_accessors() {
        assert!(MemoryKeyline::<()>::new().is_empty());

        let (mut g, _, alice_member) = standard::<MemoryKeyline<()>>();
        assert_eq!(g.len(), 6);
        assert!(!g.is_empty());
        let root = d(DOC, OWNERS, DOC, Power::Admin);
        assert_eq!(g.delegation(&root.digest()), Some(&root));
        assert!(g.get(&cert(root).digest()).is_some());
        assert!(g.revocation(&Digest::from([0u8; 32])).is_none());

        let revocation: Revocation<()> =
            Revocation::new(alice_member.issuer, alice_member.digest());
        g.insert(cert(revocation.clone()));
        assert_eq!(g.revocation(&revocation.digest()), Some(&revocation));
    }
}
