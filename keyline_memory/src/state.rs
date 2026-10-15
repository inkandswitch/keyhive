//! [`State`]: the certificate set and its synchronous evaluator.
//!
//! This is the evaluation program in `design/keyline/implementation.md`.
//! The first query after an insert evaluates stratum 1 (positive reach, admin
//! reach and coverage) and stratum 2 (the live set and edge caps) over the
//! whole set, and caches the result until the next insert that changes the
//! set. Each query then runs one widest-path search rooted at its subject.
//! Any faster backend must agree with it on every set; the conformance suite
//! is how that is checked.
//!
//! Five shortcuts depart from a literal transcription and preserve every
//! answer (the oracles transcribe the program literally, so agreement checks
//! this):
//!
//! - _Coverage that touches no route is dropped._ A revoked delegation whose
//!   covered nodes all lack standing over its subject needs no context.
//! - _Contexts are shared._ Delegations with the same exclusion set share one
//!   search per round.
//! - _One unexcluded search pre-filters._ Reach avoiding a set is a subset of
//!   reach avoiding nothing, so a delegation unreached there is skipped.
//! - _Uncovered edges are usable from the first round._ A search steps along
//!   an edge only from a node it has already reached, so every edge it uses
//!   is grounded. Allowing every uncovered edge at once therefore finds
//!   exactly the uncovered edges the least fixed point would, in one round
//!   instead of one round per link of the longest chain. Only covered edges
//!   need the fixed point.
//! - _Uncovered caps are `power`._ An uncovered edge's cap would be
//!   `min(power, issuer's plain level)`. Every search, final or in a context,
//!   reaches the issuer at or below that level, so `power` alone gives the
//!   same `min`.
//!
//! Stratum 1 is global, so the first query after an insert costs what the
//! whole replica costs, not what the queried subject costs; later queries
//! share it. Without demand-driven evaluation, `effective_power` materializes
//! the subject's entire row before indexing into it, so a point query costs
//! what `members` costs. Both suit an embedded replica holding one document's
//! closure, and not a relay.
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

use crate::collections::{Map, Set};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::fmt;
use keyhive_crypto::digest::Digest;
use keyline::{
    certificate::{Certificate, CertificateId, VerifiedCertificate},
    contract::{set_digest, CertificateSet, Version},
    delegation::Delegation,
    id::Id,
    power::Power,
    revocation::{Revocation, RevocationId},
    signed::Verified,
};
use once_cell::race::OnceBox;
use tracing::{debug, instrument, trace};

/// A certificate set, with every [`Keyline`] query as a synchronous method.
///
/// Inserts take `&mut self` and queries `&self`; there is no async and no
/// lock. `keyline_memory::MemoryKeyline` adds the concurrency. The conformance
/// oracles and most tests want this form.
///
/// [`Keyline`]: keyline::contract::Keyline
#[expect(
    clippy::type_complexity,
    reason = "the indexes are nested maps of shared certificates; aliases would only hide that"
)]
pub struct State<W> {
    /// Every delegation, verified, by digest: payload, signed form and
    /// digest, held once. The indexes below share these.
    delegations: Map<Digest<Delegation>, Arc<Verified<Delegation>>>,

    /// `subject -> issuer -> edges about subject issued by issuer`: the
    /// adjacency the search walks, an index over `delegations`.
    edges: Map<Id, Map<Id, Vec<Arc<Verified<Delegation>>>>>,

    /// Every revocation, verified, by digest.
    revocations: Map<Digest<RevocationId>, Arc<Verified<Revocation<W>>>>,

    /// Target delegation -> the revocations naming it: an index over
    /// `revocations`.
    revocations_of: Map<Digest<Delegation>, Vec<Arc<Verified<Revocation<W>>>>>,

    /// Counts the inserts that changed the set.
    version: Version,

    /// Strata 1 and 2 for the set as it stands: filled by the first query
    /// after an insert, emptied by the next insert that changes the set.
    /// `OnceBox` is `Sync`, so queries behind a read lock share it.
    evaluation: OnceBox<Evaluation>,
}

impl<W> State<W> {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many certificates are in the set.
    pub fn len(&self) -> usize {
        self.delegations.len() + self.revocations.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.delegations.is_empty() && self.revocations.is_empty()
    }

    /// The version of the set: [`Version::INITIAL`] when empty, and one more
    /// for every insert that added a certificate.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Add a batch of certificates. Returns the version after.
    ///
    /// The version moves, and the cached evaluation is dropped, only if the
    /// batch added a certificate, so duplicate gossip costs nothing.
    pub fn insert_all<I: IntoIterator<Item = VerifiedCertificate<W>>>(
        &mut self,
        batch: I,
    ) -> Version {
        let added = batch
            .into_iter()
            .fold(false, |added, cert| self.add(cert) || added);
        if added {
            self.version = self.version.next();
            self.evaluation = OnceBox::new();
        }
        self.version
    }

    /// Add one certificate. Returns whether it was new.
    pub fn insert(&mut self, cert: VerifiedCertificate<W>) -> bool {
        let before = self.version;
        self.insert_all([cert]) != before
    }

    /// Whether a certificate with this identity is in the set.
    pub fn contains(&self, cert: &CertificateId) -> bool {
        match cert {
            CertificateId::Delegation(h) => self.delegations.contains_key(h),
            CertificateId::Revocation(k) => self.revocations.contains_key(k),
        }
    }

    /// The certificate as received, if present. Shares its signed form.
    pub fn get(&self, cert: &CertificateId) -> Option<Certificate<W>> {
        match cert {
            CertificateId::Delegation(h) => self
                .delegations
                .get(h)
                .map(|v| Certificate::Delegation(Arc::clone(v.signed()))),
            CertificateId::Revocation(k) => self
                .revocations
                .get(k)
                .map(|v| Certificate::Revocation(Arc::clone(v.signed()))),
        }
    }

    /// Every certificate, in [`CertificateId`] order.
    pub fn certificates(&self) -> Vec<Certificate<W>> {
        self.in_order(self.ids().collect())
    }

    /// The delegation with this digest, if present.
    pub fn delegation(&self, cert: &Digest<Delegation>) -> Option<&Verified<Delegation>> {
        self.delegations.get(cert).map(Arc::as_ref)
    }

    /// The revocation with this digest, if present.
    pub fn revocation(&self, cert: &Digest<RevocationId>) -> Option<&Verified<Revocation<W>>> {
        self.revocations.get(cert).map(Arc::as_ref)
    }

    /// Revocations naming this delegation, covering or not.
    pub fn revocations_of(
        &self,
        delegation: &Digest<Delegation>,
    ) -> BTreeSet<Digest<RevocationId>> {
        self.revocations_of
            .get(delegation)
            .into_iter()
            .flatten()
            .map(|r| r.digest().coerce())
            .collect()
    }

    /// Every delegation from `subject` to `audience`, live or not.
    pub fn delegations_to(
        &self,
        subject: Id,
        audience: Id,
    ) -> BTreeMap<Digest<Delegation>, Delegation> {
        self.edges
            .get(&subject)
            .into_iter()
            .flat_map(Map::values)
            .flatten()
            .filter(|v| v.payload().audience == audience)
            .map(|v| (v.digest(), *v.payload()))
            .collect()
    }

    /// `audience`'s live level over `subject`.
    #[instrument(level = "trace", skip(self), fields(%subject, %audience))]
    pub fn effective_power(&self, subject: Id, audience: Id) -> Option<Power> {
        self.levels(subject).get(&audience).copied()
    }

    /// Every node but `subject` with a live route to it, with its level.
    #[instrument(level = "trace", skip(self), fields(%subject))]
    pub fn members(&self, subject: Id) -> BTreeMap<Id, Power> {
        self.levels(subject)
            .into_iter()
            .filter(|(id, _)| *id != subject)
            .collect()
    }

    /// The subject of every delegation in the set.
    pub fn subjects(&self) -> BTreeSet<Id> {
        self.edges.keys().copied().collect()
    }

    /// Whether `delegation` is live.
    #[instrument(level = "trace", skip(self), fields(%delegation))]
    pub fn is_live(&self, delegation: &Digest<Delegation>) -> bool {
        self.delegations.contains_key(delegation) && self.evaluation().live.contains(delegation)
    }

    /// `audience`'s level over `subject` in the positive graph.
    #[instrument(level = "trace", skip(self), fields(%subject, %audience))]
    pub fn positive_power(&self, subject: Id, audience: Id) -> Option<Power> {
        if subject == audience {
            return Some(Power::Admin);
        }
        self.evaluation()
            .reaches
            .get(&subject)
            .and_then(|row| row.get(&audience))
            .copied()
    }

    /// The closure of `subject`, in [`CertificateId`] order.
    #[instrument(level = "trace", skip(self), fields(%subject))]
    pub fn closure(&self, subject: Id) -> Vec<Certificate<W>> {
        let evaluation = self.evaluation();
        let nodes = evaluation
            .reaches
            .get(&subject)
            .map(|row| row.keys().copied().collect::<Vec<Id>>())
            .unwrap_or_else(|| alloc::vec![subject]);
        let delegations = nodes
            .iter()
            .filter_map(|n| self.edges.get(n))
            .flat_map(Map::values)
            .flatten();
        let ids: Vec<CertificateId> = delegations
            .flat_map(|v| {
                core::iter::once(CertificateId::from(v.digest())).chain(
                    self.revocations_of
                        .get(&v.digest())
                        .into_iter()
                        .flatten()
                        .map(|r| CertificateId::Revocation(r.digest().coerce())),
                )
            })
            .collect();
        self.in_order(ids)
    }

    /// A digest of the whole set.
    pub fn digest(&self) -> Digest<CertificateSet> {
        set_digest(self.ids())
    }

    /// Every certificate's identity, in no particular order.
    fn ids(&self) -> impl Iterator<Item = CertificateId> + '_ {
        self.delegations
            .keys()
            .map(|h| CertificateId::Delegation(*h))
            .chain(
                self.revocations
                    .keys()
                    .map(|k| CertificateId::Revocation(*k)),
            )
    }

    /// The certificates with these identities, sorted and deduplicated.
    fn in_order(&self, mut ids: Vec<CertificateId>) -> Vec<Certificate<W>> {
        ids.sort_unstable();
        ids.dedup();
        ids.iter().filter_map(|id| self.get(id)).collect()
    }

    /// Add one certificate without moving the version.
    #[instrument(level = "debug", skip(self, cert), fields(id = ?cert.id()))]
    fn add(&mut self, cert: VerifiedCertificate<W>) -> bool {
        if self.contains(&cert.id()) {
            debug!("duplicate certificate; not inserted");
            return false;
        }

        match cert {
            VerifiedCertificate::Delegation(v) => {
                let d = v.payload();
                debug!(
                    issuer = %d.issuer,
                    audience = %d.audience,
                    subject = %d.subject,
                    power = %d.power,
                    citation = d.citation.is_some(),
                    "delegation inserted"
                );
                self.edges
                    .entry(d.subject)
                    .or_default()
                    .entry(d.issuer)
                    .or_default()
                    .push(Arc::clone(&v));
                self.delegations.insert(v.digest(), v);
            }
            VerifiedCertificate::Revocation(v) => {
                let r = v.payload();
                debug!(
                    issuer = %r.issuer,
                    revoke = %r.revoke,
                    target_known = self.delegations.contains_key(&r.revoke),
                    "revocation inserted"
                );
                self.revocations_of
                    .entry(r.revoke)
                    .or_default()
                    .push(Arc::clone(&v));
                self.revocations.insert(v.digest().coerce(), v);
            }
        }
        true
    }

    /// The cached evaluation, computed on first use after a change.
    fn evaluation(&self) -> &Evaluation {
        self.evaluation.get_or_init(|| Box::new(self.evaluate()))
    }

    /// Run both strata. Pure in the set.
    #[instrument(level = "debug", skip(self), fields(
        delegations = self.delegations.len(),
        revocations = self.revocations.len(),
    ))]
    fn evaluate(&self) -> Evaluation {
        let reaches = self.search(self.edges.keys().copied(), &Params::positive());
        let contexts = self.contexts(self.coverage(&reaches));
        let live = self.live_set(&contexts);
        let cap = self.caps(&contexts, &live);
        debug!(
            contexts = contexts.len(),
            live = live.len(),
            dead = self.delegations.len() - live.len(),
            clamped = cap
                .iter()
                .filter(|(h, c)| {
                    self.delegations
                        .get(*h)
                        .is_some_and(|v| **c < v.payload().power)
                })
                .count(),
            "evaluated"
        );
        Evaluation { reaches, live, cap }
    }

    /// The live level of every node over `subject`, including `subject` itself.
    fn levels(&self, subject: Id) -> Map<Id, Power> {
        let Evaluation { live, cap, .. } = self.evaluation();
        self.search([subject], &Params::live(None, live, Some(cap)))
            .remove(&subject)
            .unwrap_or_default()
    }

    /// Group covered delegations by exclusion set. `covered(h, ·)` depends
    /// only on who revoked `h`, so one key's revocation spree yields one set,
    /// and every edge in a context shares its searches.
    fn contexts(&self, covered: Vec<(Arc<Verified<Delegation>>, Set<Id>)>) -> Vec<Context> {
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

    /// Stratum 1: `covered(h, ·)` for every revoked delegation whose covered
    /// nodes could lie on a route for it.
    ///
    /// A route for `h` transits only nodes with standing over `subject(h)`, so
    /// if no covered node has that standing, `h` behaves exactly as an
    /// uncovered edge and is dropped: a revocation by a key with no standing
    /// over `h`'s subject costs no context. The set itself is kept whole, not
    /// trimmed to those nodes, so that it still depends only on who revoked
    /// `h` and a one-key spree still shares one context. Excluding a node
    /// without standing over a search's root changes nothing, since the search
    /// never reaches it.
    fn coverage(
        &self,
        reaches: &Map<Id, Map<Id, Power>>,
    ) -> Vec<(Arc<Verified<Delegation>>, Set<Id>)> {
        // admin_reach(k, n): k reaches n at Admin, however derived.
        let mut reach: Map<Id, Set<Id>> = Map::new();
        for (n, levels) in reaches {
            for (k, l) in levels {
                if *l == Power::Admin {
                    reach.entry(*k).or_default().insert(*n);
                }
            }
        }

        self.revocations_of
            .iter()
            .filter_map(|(h, revocations)| {
                let target = self.delegations.get(h)?;
                let on_routes = reaches.get(&target.payload().subject)?;
                let nodes: Set<Id> = revocations
                    .iter()
                    .map(|r| r.payload().issuer)
                    .flat_map(|k| {
                        core::iter::once(k).chain(reach.get(&k).into_iter().flatten().copied())
                    })
                    .collect();
                nodes
                    .iter()
                    .any(|n| on_routes.contains_key(n))
                    .then(|| (Arc::clone(target), nodes))
            })
            .collect()
    }

    /// Stratum 2, existence: the least fixed point of the live set.
    ///
    /// Every uncovered edge is usable from the first round (see the module
    /// documentation), so the rounds are only for covered edges. Each round
    /// re-runs the search over the usable edges, adds the covered edges found
    /// live in their contexts, and stops when it adds none. It terminates
    /// because the usable set only grows within the finite set of delegations.
    fn live_set(&self, contexts: &[Context]) -> Set<Digest<Delegation>> {
        let covered: Set<Digest<Delegation>> = contexts
            .iter()
            .flat_map(|c| c.edges.iter().map(|v| v.digest()))
            .collect();
        // Every uncovered edge, grounded or not, and the covered edges found
        // live so far. A search steps along an edge only from a node it has
        // reached, so the ungrounded ones are never used.
        let mut usable: Set<Digest<Delegation>> = self
            .delegations
            .keys()
            .filter(|h| !covered.contains(h))
            .copied()
            .collect();

        loop {
            // One shared pass with no exclusion serves every uncovered edge and
            // prunes covered ones: reach avoiding N is a subset of reach avoiding ∅.
            let base = self.search(
                self.edges.keys().copied(),
                &Params::live(None, &usable, None),
            );

            let mut newly_live: Vec<Digest<Delegation>> = Vec::new();
            for ctx in contexts {
                // Cheap rejections first; the search runs once per context.
                let candidates: Vec<&Verified<Delegation>> = ctx
                    .edges
                    .iter()
                    .map(Arc::as_ref)
                    .filter(|v| {
                        let d = v.payload();
                        !usable.contains(&v.digest())
                            && !ctx.excludes_an_endpoint(d)
                            && !self.revoked_by_audience(&v.digest(), d.audience)
                            && reached(&base, d.subject, d.issuer)
                    })
                    .collect();
                if candidates.is_empty() {
                    continue;
                }

                let levels = self.search(
                    candidates.iter().map(|v| v.payload().subject),
                    &Params::live(Some(&ctx.exclude), &usable, None),
                );
                newly_live.extend(
                    candidates
                        .iter()
                        .filter(|v| reached(&levels, v.payload().subject, v.payload().issuer))
                        .map(|v| v.digest()),
                );
            }

            if newly_live.is_empty() {
                // No audience check for uncovered edges: a delegation its
                // audience revoked is always covered (the audience is in its
                // own reach and has standing over the subject whenever the
                // delegation could be live).
                return usable
                    .into_iter()
                    .filter(|h| {
                        covered.contains(h)
                            || self.delegations.get(h).is_some_and(|v| {
                                reached(&base, v.payload().subject, v.payload().issuer)
                            })
                    })
                    .collect();
            }
            trace!(
                newly_live = newly_live.len(),
                usable = usable.len(),
                "live fixpoint round"
            );
            usable.extend(newly_live);
        }
    }

    /// Whether the audience of `h` has signed a revocation of it. The audience is
    /// not on the route to the issuer, so this is the one place a revocation's
    /// effect is decided by the signer's identity rather than their admin reach.
    fn revoked_by_audience(&self, h: &Digest<Delegation>, audience: Id) -> bool {
        self.revocations_of
            .get(h)
            .is_some_and(|rs| rs.iter().any(|r| r.payload().issuer == audience))
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
        let edges_by_context: Vec<(&Context, Vec<&Verified<Delegation>>)> = contexts
            .iter()
            .map(|ctx| {
                let edges = ctx
                    .edges
                    .iter()
                    .map(Arc::as_ref)
                    .filter(|v| live.contains(&v.digest()))
                    .collect::<Vec<_>>();
                (ctx, edges)
            })
            .filter(|(_, edges)| !edges.is_empty())
            .collect();

        let mut cap: Map<Digest<Delegation>, Power> = edges_by_context
            .iter()
            .flat_map(|(_, edges)| edges.iter().map(|v| (v.digest(), Power::Relay)))
            .collect();

        loop {
            let mut next = cap.clone();

            for (ctx, edges) in &edges_by_context {
                let levels = self.search(
                    edges.iter().map(|v| v.payload().subject),
                    &Params::live(Some(&ctx.exclude), live, Some(&cap)),
                );
                for v in edges {
                    let d = v.payload();
                    // Liveness found a grounded avoiding derivation, so the
                    // issuer is reached; a miss would leave the cap at `Relay`.
                    if let Some(at_iss) = levels.get(&d.subject).and_then(|m| m.get(&d.issuer)) {
                        let raised = cap[&v.digest()].max(d.power.min(*at_iss));
                        next.insert(v.digest(), raised);
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

    /// The parameterized reachability search: `level(root, ·)` for each root and
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
                for v in edges.iter().filter(|v| params.usable(&v.digest())) {
                    let d = v.payload();
                    relax(
                        &mut buckets,
                        d.audience,
                        lu.min(params.cap(&v.digest(), d.power)),
                    );
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

// Manual: derives would bound `W`, which no field needs (every certificate is
// shared, so a clone copies pointers), and a clone should not carry the cache.
impl<W> Default for State<W> {
    fn default() -> Self {
        State {
            delegations: Map::new(),
            edges: Map::new(),
            revocations: Map::new(),
            revocations_of: Map::new(),
            version: Version::INITIAL,
            evaluation: OnceBox::new(),
        }
    }
}

impl<W> Clone for State<W> {
    fn clone(&self) -> Self {
        State {
            delegations: self.delegations.clone(),
            edges: self.edges.clone(),
            revocations: self.revocations.clone(),
            revocations_of: self.revocations_of.clone(),
            version: self.version,
            evaluation: OnceBox::new(),
        }
    }
}

impl<W> fmt::Debug for State<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("certificates", &self.len())
            .field("version", &self.version)
            .field("evaluated", &self.evaluation.get().is_some())
            .finish_non_exhaustive()
    }
}

/// Covered delegations sharing one exclusion set, and therefore one search.
struct Context {
    exclude: Set<Id>,
    edges: Vec<Arc<Verified<Delegation>>>,
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

/// One evaluation of the set: what every query after an insert shares.
struct Evaluation {
    /// Stratum 1: `subject -> node -> level` in the positive graph, for every
    /// subject of a delegation.
    reaches: Map<Id, Map<Id, Power>>,

    /// Stratum 2: the live delegations.
    live: Set<Digest<Delegation>>,

    /// Stratum 2: the caps on live covered delegations.
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
