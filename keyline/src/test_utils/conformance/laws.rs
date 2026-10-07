//! Properties every `Keyline` must satisfy on every set, checked with `bolero`
//! over generated [`CertSet`]s, including agreement with both
//! [oracles](super::oracle).
use super::{
    build,
    gen::{ids, CertSet},
    oracle::{naive, threshold, Levels},
    TestWatermark,
};
use crate::{
    contract::Keyline, delegation::Delegation, id::Id, power::Power, test_utils::assume_verified,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::digest::Digest;

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

pub fn observe<K: Keyline>(k: &K, set: &CertSet<K::RetentionWatermark>) -> Observed
where
    K::RetentionWatermark: TestWatermark,
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
        .map(Delegation::digest)
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
pub fn matches_naive_oracle_without_revocations<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let set = set.without_revocations();
            let expected = naive::reaches(&set);
            let k: K = build(set.certs.iter().cloned());

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
pub fn matches_naive_oracle_with_revocations<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let expected = naive::evaluate(set);
            let k: K = build(set.certs.iter().cloned());

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

/// Every query agrees with the threshold form, which reaches its answers by a
/// different route than [`naive`]: thresholds instead of values, and each
/// covered certificate's level read off its own context instead of a cap
/// fixed point.
pub fn matches_threshold_oracle<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let expected = threshold::evaluate(set);
            let k: K = build(set.certs.iter().cloned());

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
pub fn party_revocation_is_total<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let k: K = build(set.certs.iter().cloned());
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
pub fn retain_is_inert<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let with: K = build(set.certs.iter().cloned());
            let without: K = build(set.without_watermarks().certs);
            assert_eq!(observe(&with, set), observe(&without, set));
            for s in ids() {
                assert_eq!(with.members(s), without.members(s));
            }
        });
}

/// Any insertion order gives the same answers and the same digest: a uniformly
/// shuffled order, and the reverse order, on every set.
pub fn order_independent<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<K::RetentionWatermark>, u64)>()
        .for_each(|(set, seed)| {
            let a: K = build(set.certs.iter().cloned());
            for b in [
                build::<K, _>(set.shuffled(*seed).certs),
                build::<K, _>(set.reversed().certs),
            ] {
                assert_eq!(a.digest(), b.digest());
                assert_eq!(observe(&a, set), observe(&b, set));
                for s in ids() {
                    assert_eq!(a.members(s), b.members(s));
                }
            }
        });
}

/// Inserting a certificate already present returns `false` and changes nothing.
pub fn idempotent<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let mut k: K = build(set.certs.iter().cloned());
            let before = (k.digest(), observe(&k, set));
            for c in &set.certs {
                assert!(!k.insert(assume_verified(c.clone())));
            }
            assert_eq!((k.digest(), observe(&k, set)), before);
        });
}

/// Adding a revocation never raises any level and never revives a delegation.
pub fn revocations_only_deny<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let with: K = build(set.certs.iter().cloned());
            let after = observe(&with, set);

            let revocations: Vec<usize> = set
                .certs
                .iter()
                .enumerate()
                .filter(|(_, c)| c.as_revocation().is_some())
                .map(|(i, _)| i)
                .collect();

            for i in revocations {
                let without: K = build(set.without(i).certs);
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

/// `digest` is a function of the set: same set (any order), same digest;
/// dropping any certificate changes it.
pub fn digest_identifies_the_set<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<K::RetentionWatermark>, u64)>()
        .for_each(|(set, seed)| {
            let a: K = build(set.certs.iter().cloned());
            let b: K = build(set.shuffled(*seed).certs);
            assert_eq!(a.digest(), b.digest());

            let distinct: BTreeSet<_> = set.certs.iter().collect();
            for i in 0..set.certs.len() {
                // Removing one copy of a duplicated certificate leaves the set unchanged.
                if set.certs.iter().filter(|c| **c == set.certs[i]).count() > 1 {
                    continue;
                }
                let smaller: K = build(set.without(i).certs);
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
pub fn queries_are_consistent<K: Keyline + Default>()
where
    K::RetentionWatermark: TestWatermark,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::RetentionWatermark>>()
        .for_each(|set| {
            let k: K = build(set.certs.iter().cloned());
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
                    let smaller: K = build(set.without(i).certs);
                    assert!(!smaller.contains(&assume_verified(c.clone()).id()));
                }
            }
            // Every target named, present or not: a revocation that arrives
            // before its target must already explain the collision.
            let targets = set
                .delegations()
                .map(Delegation::digest)
                .chain(set.revocations().map(|r| r.revoke));
            for target in targets {
                let expected: BTreeSet<_> = set
                    .revocations()
                    .filter(|r| r.revoke == target)
                    .map(|r| r.digest())
                    .collect();
                assert_eq!(k.revocations_naming(&target), expected);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two oracles agree with each other on the same sets, with no
    /// backend in between: the value form and the threshold form in
    /// `design/keyline/implementation.md` say the same thing.
    #[test]
    fn oracles_agree() {
        bolero::check!()
            .with_arbitrary::<CertSet<alloc::vec::Vec<u8>>>()
            .for_each(|set| {
                let value = naive::evaluate(set);
                let threshold = threshold::evaluate(set);
                assert_eq!(value.live, threshold.live, "live sets");
                assert_eq!(value.levels, threshold.effective, "levels");
            });
    }
}
