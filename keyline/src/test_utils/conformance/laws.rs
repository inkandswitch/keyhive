//! Properties every `Keyline` must satisfy on every set, checked with `bolero`
//! over generated [`CertSet`]s, including agreement with both
//! [oracles](super::oracle).
use super::{
    build,
    gen::{ids, CertSet},
    oracle::{naive, threshold, Levels},
    Backend, Harness, TestWatermark,
};
use crate::{
    contract::set_digest, delegation::Delegation, power::Power, test_utils::assume_verified,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::{digest::Digest, id::Id};

/// Every `(subject, node)` level a backend reports over the pool, plus the
/// live status of every delegation: what the laws compare.
///
/// Levels are read through `members`, one evaluation per subject rather than
/// one per pair; [`queries_are_consistent`] checks that `members` and
/// `effective_power` agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub levels: BTreeMap<(Id, Id), Power>,
    pub live: BTreeSet<Digest<Delegation>>,
}

pub fn observe<C: Backend>(k: &Harness<C>, set: &CertSet<C::Watermark>) -> Observed
where
    C::Watermark: TestWatermark,
{
    let levels = ids()
        .flat_map(|s| {
            k.members(s)
                .into_iter()
                .map(move |(x, l)| ((s, x), l))
                .chain([((s, s), Power::Admin)])
        })
        .collect();
    let live = set
        .delegations()
        .map(|d| d.digest())
        .filter(|h| k.is_live(h))
        .collect();
    Observed { levels, live }
}

/// `members(s)` as an oracle's levels give it: every node but `s` with a level.
fn members_of(levels: &Levels, s: Id) -> BTreeMap<Id, Power> {
    levels
        .iter()
        .filter(|((s2, x), _)| *s2 == s && *x != s)
        .map(|((_, x), l)| (*x, *l))
        .collect()
}

/// Without revocations, `members` is exactly stratum 1, and every
/// delegation whose issuer reaches its subject is live.
pub fn matches_naive_oracle_without_revocations<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let set = set.without_revocations();
            let expected = naive::reaches(&set);
            let k: Harness<C> = build(set.certs.iter().cloned());

            for s in ids() {
                assert_eq!(k.members(s), members_of(&expected, s), "members({s})");
            }
            for d in set.delegations() {
                assert_eq!(
                    k.is_live(&d.digest()),
                    expected.contains_key(&(d.subject, d.issuer)),
                    "is_live({d:?})"
                );
            }
        });
}

/// With revocations, `members` and `is_live` agree with the value form: admin
/// reach, coverage, the live set as a least fixed point with revocation by the
/// audience, and clamped powers.
pub fn matches_naive_oracle_with_revocations<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let expected = naive::evaluate(set);
            let k: Harness<C> = build(set.certs.iter().cloned());

            for s in ids() {
                assert_eq!(
                    k.members(s),
                    members_of(&expected.levels, s),
                    "members({s})"
                );
            }
            for d in set.delegations() {
                assert_eq!(
                    k.is_live(&d.digest()),
                    expected.live.contains(&d.digest()),
                    "is_live({d:?})"
                );
            }
        });
}

/// Every query agrees with the threshold form, which computes its answers
/// differently from [`naive`]: thresholds instead of values, and each
/// covered certificate's level read off its own context instead of a cap
/// fixed point.
pub fn matches_threshold_oracle<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let expected = threshold::evaluate(set);
            let k: Harness<C> = build(set.certs.iter().cloned());

            for s in ids() {
                assert_eq!(
                    k.members(s),
                    members_of(&expected.effective, s),
                    "members({s})"
                );
            }
            for d in set.delegations() {
                assert_eq!(
                    k.is_live(&d.digest()),
                    expected.live.contains(&d.digest()),
                    "is_live({d:?})"
                );
            }
        });
}

/// A revocation signed by its target's issuer or audience kills the target,
/// whatever else is in the set.
pub fn party_revocation_is_total<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let k: Harness<C> = build(set.certs.iter().cloned());
            for r in set.revocations() {
                let party = set.delegations().any(|d| {
                    d.digest() == r.revoke && (r.issuer == d.issuer || r.issuer == d.audience)
                });
                if party {
                    assert!(!k.is_live(&r.revoke), "{r:?} is by a party to its target");
                }
            }
        });
}

/// `retain` never changes an answer: emptying every map leaves every query as
/// it was.
pub fn retain_is_inert<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let with: Harness<C> = build(set.certs.iter().cloned());
            let without: Harness<C> = build(set.without_watermarks().certs);
            assert_eq!(observe(&with, set), observe(&without, set));
        });
}

/// Any insertion order gives the same answers and the same digest: a uniformly
/// shuffled order, and the reverse order, on every set.
pub fn order_independent<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<C::Watermark>, u64)>()
        .for_each(|(set, seed)| {
            let a: Harness<C> = build(set.certs.iter().cloned());
            for b in [
                build::<C, _>(set.shuffled(*seed).certs),
                build::<C, _>(set.reversed().certs),
            ] {
                assert_eq!(a.digest(), b.digest());
                assert_eq!(observe(&a, set), observe(&b, set));
            }
        });
}

/// Inserting a certificate already present returns `false` and changes nothing.
pub fn idempotent<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let mut k: Harness<C> = build(set.certs.iter().cloned());
            let before = (k.digest(), observe(&k, set));
            for c in &set.certs {
                assert!(!k.insert(assume_verified(c.clone())));
            }
            assert_eq!((k.digest(), observe(&k, set)), before);
        });
}

/// Adding a revocation never raises any level and never revives a delegation.
pub fn revocations_only_deny<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let with: Harness<C> = build(set.certs.iter().cloned());
            let after = observe(&with, set);

            let revocations: Vec<usize> = set
                .certs
                .iter()
                .enumerate()
                .filter(|(_, c)| c.as_revocation().is_some())
                .map(|(i, _)| i)
                .collect();

            for i in revocations {
                let without: Harness<C> = build(set.without(i).certs);
                let before = observe(&without, set);
                for (key, l) in &after.levels {
                    assert!(
                        before.levels.get(key).is_some_and(|b| b >= l),
                        "revocation {i} raised {key:?} to {l}"
                    );
                }
                assert!(
                    after.live.is_subset(&before.live),
                    "revocation {i} revived an edge"
                );
            }
        });
}

/// `digest` is a function of the set: same set (any order), same digest, and
/// that digest is `set_digest` of the members' ids; dropping any certificate
/// changes it.
pub fn digest_identifies_the_set<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<C::Watermark>, u64)>()
        .for_each(|(set, seed)| {
            let a: Harness<C> = build(set.certs.iter().cloned());
            let b: Harness<C> = build(set.shuffled(*seed).certs);
            assert_eq!(a.digest(), b.digest());
            // The digest is `set_digest` of the members' ids, so every backend
            // computes the same one for the same set.
            assert_eq!(
                a.digest(),
                set_digest(set.certs.iter().map(|c| assume_verified(c.clone()).id()))
            );

            let distinct: BTreeSet<_> = set.certs.iter().collect();
            for i in 0..set.certs.len() {
                // Removing one copy of a duplicated certificate leaves the set unchanged.
                if set.certs.iter().filter(|c| **c == set.certs[i]).count() > 1 {
                    continue;
                }
                let smaller: Harness<C> = build(set.without(i).certs);
                assert_ne!(
                    a.digest(),
                    smaller.digest(),
                    "dropping cert {i} of {}",
                    distinct.len()
                );
            }
        });
}

/// Every node is Admin over itself; `members` is exactly `effective_power`
/// minus the subject; `contains` is true of every inserted certificate and
/// false of one left out.
pub fn queries_are_consistent<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let k: Harness<C> = build(set.certs.iter().cloned());
            for s in ids() {
                assert_eq!(k.effective_power(s, s), Some(Power::Admin));
                let members = k.members(s);
                assert!(!members.contains_key(&s));
                for x in ids().filter(|x| *x != s) {
                    assert_eq!(members.get(&x).copied(), k.effective_power(s, x));
                }
            }
            for (i, c) in set.certs.iter().enumerate() {
                assert!(k.contains(&assume_verified(c.clone()).id()));
                if set.certs.iter().filter(|x| *x == c).count() == 1 {
                    let smaller: Harness<C> = build(set.without(i).certs);
                    assert!(!smaller.contains(&assume_verified(c.clone()).id()));
                }
            }
            // Every target named, present or not: a revocation that arrives
            // before its target must already explain the collision.
            let targets = set
                .delegations()
                .map(|d| d.digest())
                .chain(set.revocations().map(|r| r.revoke));
            for target in targets {
                let expected: BTreeSet<_> = set
                    .revocations()
                    .filter(|r| r.revoke == target)
                    .map(|r| r.digest())
                    .collect();
                assert_eq!(k.revocations_of(&target), expected);
            }
        });
}

/// `positive_power` is stratum 1 alone: the naive oracle's reach over the
/// set with every revocation ignored, and `Admin` for a subject over itself.
pub fn positive_power_matches_stratum_one<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let expected = naive::reaches(&set.without_revocations());
            let k: Harness<C> = build(set.certs.iter().cloned());
            for s in ids() {
                for x in ids() {
                    let want = if s == x {
                        Some(Power::Admin)
                    } else {
                        expected.get(&(s, x)).copied()
                    };
                    assert_eq!(k.positive_power(s, x), want, "positive_power({s}, {x})");
                }
            }
        });
}

/// Adding a certificate, revocations included, never lowers `positive_power`:
/// a positive answer read at one version holds at every later one.
pub fn positive_power_is_monotone<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let all: Harness<C> = build(set.certs.iter().cloned());
            for i in 0..set.certs.len() {
                let fewer: Harness<C> = build(set.without(i).certs);
                for s in ids() {
                    for x in ids() {
                        assert!(
                            fewer.positive_power(s, x) <= all.positive_power(s, x),
                            "certificate {i} lowered positive_power({s}, {x})"
                        );
                    }
                }
            }
        });
}

/// `certificates`, `get`, `delegations_to` and `subjects` list exactly what
/// the set holds.
pub fn listings_match_the_set<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let k: Harness<C> = build(set.certs.iter().cloned());
            let ids_in_set: BTreeSet<_> = set
                .certs
                .iter()
                .map(|c| assume_verified(c.clone()).id())
                .collect();

            let listed: Vec<_> = k.certificates().iter().map(|c| c.id()).collect();
            assert_eq!(
                listed,
                ids_in_set.iter().copied().collect::<Vec<_>>(),
                "certificates() lists the set in id order"
            );
            for id in &ids_in_set {
                assert_eq!(k.get(id).map(|c| c.id()), Some(*id), "get({id:?})");
            }
            for (i, c) in set.certs.iter().enumerate() {
                let id = assume_verified(c.clone()).id();
                if set.certs.iter().filter(|x| *x == c).count() == 1 {
                    let smaller: Harness<C> = build(set.without(i).certs);
                    assert_eq!(smaller.get(&id), None, "get of a missing certificate");
                }
            }

            for s in ids() {
                for a in ids() {
                    let expected: BTreeMap<_, _> = set
                        .delegations()
                        .filter(|d| d.subject == s && d.audience == a)
                        .map(|d| (d.digest(), (d.issuer, d.payload)))
                        .collect();
                    assert_eq!(k.delegations_to(s, a), expected, "delegations_to({s}, {a})");
                }
            }

            let subjects: BTreeSet<_> = set.delegations().map(|d| d.subject).collect();
            assert_eq!(k.subjects(), subjects, "subjects()");
        });
}

/// No certificate outside `closure(s)` changes an answer about `s`: a store
/// holding only the closure agrees with the full store on `s`'s members, its
/// positive powers, and the liveness of every delegation about `s`. Closures
/// only grow: dropping a certificate never adds to one.
pub fn closure_is_sufficient<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let all: Harness<C> = build(set.certs.iter().cloned());
            let by_id: BTreeMap<_, _> = set
                .certs
                .iter()
                .map(|c| (assume_verified(c.clone()).id(), c.clone()))
                .collect();

            for s in ids() {
                let closure: BTreeSet<_> = all.closure(s).iter().map(|c| c.id()).collect();
                let only: Harness<C> = build(closure.iter().map(|id| {
                    by_id
                        .get(id)
                        .expect("the closure holds only certificates in the set")
                        .clone()
                }));

                assert_eq!(
                    only.members(s),
                    all.members(s),
                    "members({s}) from its closure"
                );
                for x in ids() {
                    assert_eq!(
                        only.positive_power(s, x),
                        all.positive_power(s, x),
                        "positive_power({s}, {x}) from the closure of {s}"
                    );
                }
                for d in set.delegations().filter(|d| d.subject == s) {
                    assert_eq!(
                        only.is_live(&d.digest()),
                        all.is_live(&d.digest()),
                        "is_live({d:?}) from the closure of {s}"
                    );
                }

                for i in 0..set.certs.len() {
                    let fewer: Harness<C> = build(set.without(i).certs);
                    let smaller: BTreeSet<_> = fewer.closure(s).iter().map(|c| c.id()).collect();
                    assert!(
                        smaller.is_subset(&closure),
                        "dropping certificate {i} grew the closure of {s}"
                    );
                }
            }
        });
}

/// `members_for_subset` over any subset answers as a store containing only that
/// subset and ignores identities the background store does not contain.
pub fn members_for_subset_answers_as_the_subset<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<C::Watermark>, u64)>()
        .for_each(|(set, mask)| {
            let all: Harness<C> = build(set.certs.iter().cloned());
            let (kept, left_out): (Vec<_>, Vec<_>) = set
                .certs
                .iter()
                .enumerate()
                .partition(|(i, _)| mask >> (i % 64) & 1 == 1);
            let only: Harness<C> = build(kept.into_iter().map(|(_, c)| c.clone()));
            let subset: BTreeSet<_> = only.certificates().iter().map(|c| c.id()).collect();
            let everything: BTreeSet<_> = set
                .certs
                .iter()
                .map(|c| assume_verified(c.clone()).id())
                .collect();

            for s in ids() {
                assert_eq!(
                    all.members_for_subset(subset.clone(), s),
                    only.members(s),
                    "members_for_subset({s}) over {} of {} certificates",
                    subset.len(),
                    everything.len()
                );
                if !left_out.is_empty() {
                    assert_eq!(
                        only.members_for_subset(everything.clone(), s),
                        only.members(s),
                        "members_for_subset({s}) containing certificates the store lacks"
                    );
                }
            }
        });
}

/// Inserting a set as one batch, or as two batches split anywhere, answers as
/// inserting it one certificate at a time.
pub fn batches_equal_singles<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<C::Watermark>, u8)>()
        .for_each(|(set, split)| {
            let singles: Harness<C> = build(set.certs.iter().cloned());
            let expected = (singles.digest(), observe(&singles, set));

            let mut one = Harness::<C>::default();
            one.insert_batch(
                &set.certs
                    .iter()
                    .cloned()
                    .map(assume_verified)
                    .collect::<Vec<_>>(),
            );
            assert_eq!((one.digest(), observe(&one, set)), expected, "one batch");

            let at = usize::from(*split) % (set.certs.len() + 1);
            let (head, tail) = set.certs.split_at(at);
            let mut two = Harness::<C>::default();
            two.insert_batch(
                &head
                    .iter()
                    .cloned()
                    .map(assume_verified)
                    .collect::<Vec<_>>(),
            );
            two.insert_batch(
                &tail
                    .iter()
                    .cloned()
                    .map(assume_verified)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                (two.digest(), observe(&two, set)),
                expected,
                "two batches at {at}"
            );
        });
}

/// Querying after every insert, then finishing, answers as building the whole
/// set fresh. A backend that caches must drop what an insert invalidates.
pub fn interleaving_is_invisible<C: Backend>()
where
    C::Watermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<C::Watermark>>()
        .for_each(|set| {
            let fresh: Harness<C> = build(set.certs.iter().cloned());
            let expected = observe(&fresh, set);

            let mut k = Harness::<C>::default();
            for c in &set.certs {
                k.insert(assume_verified(c.clone()));
                // Touch every query that a cache could serve stale.
                let _ = observe(&k, set);
                for s in ids() {
                    let _ = (k.positive_power(s, s), k.closure(s));
                }
            }
            assert_eq!(observe(&k, set), expected);
            for s in ids() {
                for x in ids() {
                    assert_eq!(k.positive_power(s, x), fresh.positive_power(s, x));
                }
                assert_eq!(k.closure(s), fresh.closure(s), "closure({s})");
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The two oracles agree with each other on the same sets, with no
    /// backend in between: the value form and the threshold form in
    /// `design/keyline/implementation.md` say the same thing.
    #[test]
    fn oracles_agree() {
        bolero::check!()
            .with_arbitrary::<CertSet<Vec<u8>>>()
            .for_each(|set| {
                let value = naive::evaluate(set);
                let threshold = threshold::evaluate(set);
                assert_eq!(value.live, threshold.live, "live sets");
                assert_eq!(value.levels, threshold.effective, "levels");
            });
    }
}
