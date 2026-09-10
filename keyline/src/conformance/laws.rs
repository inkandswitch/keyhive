//! Properties every `Keyline` must satisfy on every set, checked with `bolero`
//! over generated [`CertSet`]s.
//!
//! The revocation-free case has an independent oracle: [`naive_reaches`] is
//! the three stratum-1 rules run as a plain tuple fixpoint, sharing no code
//! with any backend. With revocations, the laws pin down monotonicity and
//! consistency; exact agreement is by scenario (see `scenarios`).

use super::{
    build,
    gen::{ids, CertSet},
};
use crate::{access::Access, delegation::Delegation, id::Id, keyline::Keyline, test_utils::cert};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::digest::Digest;

/// Every `(subject, node)` level a backend reports over the pool, plus the
/// live status of every delegation: the whole observable state of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub levels: BTreeMap<(Id, Id), Access>,
    pub live: BTreeSet<Digest<Delegation>>,
}

pub fn observe<K: Keyline>(k: &K, set: &CertSet) -> Observed {
    let levels = ids()
        .flat_map(|s| ids().map(move |x| (s, x)))
        .filter_map(|(s, x)| k.effective_access(s, x).map(|l| ((s, x), l)))
        .collect();
    let live = set
        .delegations()
        .map(Delegation::digest)
        .filter(|h| k.is_live(h))
        .collect();
    Observed { levels, live }
}

/// Stratum 1 as a tuple fixpoint: the three `reaches` rules over the pool,
/// nothing else.
pub fn naive_reaches(dels: &[Delegation]) -> BTreeMap<(Id, Id), Access> {
    let nodes: BTreeSet<Id> = ids()
        .chain(dels.iter().flat_map(|d| [d.iss, d.aud, d.sub]))
        .collect();

    let mut reaches: BTreeMap<(Id, Id), Access> =
        nodes.iter().map(|n| ((*n, *n), Access::Admin)).collect();

    loop {
        let mut next = reaches.clone();
        let mut raise = |key: (Id, Id), l: Access| {
            let e = next.entry(key).or_insert(l);
            *e = (*e).max(l);
        };

        for d in dels {
            if let Some(l) = reaches.get(&(d.sub, d.iss)) {
                raise((d.sub, d.aud), (*l).min(d.can));
            }
        }
        for &s in &nodes {
            for &n in &nodes {
                if n == s {
                    continue;
                }
                let Some(l1) = reaches.get(&(s, n)) else {
                    continue;
                };
                for &x in &nodes {
                    if let Some(l2) = reaches.get(&(n, x)) {
                        raise((s, x), (*l1).min(*l2));
                    }
                }
            }
        }

        if next == reaches {
            return reaches;
        }
        reaches = next;
    }
}

/// Without revocations, `effective_access` is exactly stratum 1, and every
/// delegation whose issuer reaches its subject is live.
pub fn matches_naive_oracle_without_revocations<K: Keyline + Default>() {
    bolero::check!()
        .with_arbitrary::<CertSet>()
        .for_each(|set| {
            let set = set.without_revocations();
            let dels: Vec<Delegation> = set.delegations().copied().collect();
            let expected = naive_reaches(&dels);
            let k: K = build(set.certs.iter().copied());

            for s in ids() {
                for x in ids() {
                    assert_eq!(
                        k.effective_access(s, x),
                        expected.get(&(s, x)).copied(),
                        "effective_access({s}, {x})"
                    );
                }
            }
            for d in &dels {
                assert_eq!(
                    k.is_live(&d.digest()),
                    expected.contains_key(&(d.sub, d.iss)),
                    "is_live({d:?})"
                );
            }
        });
}

/// Any insertion order gives the same answers and the same digest.
pub fn order_independent<K: Keyline + Default>() {
    bolero::check!()
        .with_arbitrary::<(CertSet, Vec<u8>)>()
        .for_each(|(set, keys)| {
            let a: K = build(set.certs.iter().copied());
            let b: K = build(set.permuted(keys).certs);
            assert_eq!(a.digest(), b.digest());
            assert_eq!(observe(&a, set), observe(&b, set));
            for s in ids() {
                assert_eq!(a.members(s), b.members(s));
            }
        });
}

/// Inserting a certificate already present returns `false` and changes nothing.
pub fn idempotent<K: Keyline + Default>() {
    bolero::check!()
        .with_arbitrary::<CertSet>()
        .for_each(|set| {
            let mut k: K = build(set.certs.iter().copied());
            let before = (k.digest(), observe(&k, set));
            for c in &set.certs {
                assert!(!k.insert(cert(*c)));
            }
            assert_eq!((k.digest(), observe(&k, set)), before);
        });
}

/// Adding a revocation never raises any level and never revives a delegation.
pub fn revocations_only_deny<K: Keyline + Default>() {
    bolero::check!()
        .with_arbitrary::<CertSet>()
        .for_each(|set| {
            let with: K = build(set.certs.iter().copied());
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
pub fn digest_identifies_the_set<K: Keyline + Default>() {
    bolero::check!()
        .with_arbitrary::<(CertSet, Vec<u8>)>()
        .for_each(|(set, keys)| {
            let a: K = build(set.certs.iter().copied());
            let b: K = build(set.permuted(keys).certs);
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

/// Every node is Admin over itself; `members` is exactly `effective_access`
/// minus the subject; `contains` agrees with what was inserted.
pub fn queries_are_consistent<K: Keyline + Default>() {
    bolero::check!()
        .with_arbitrary::<CertSet>()
        .for_each(|set| {
            let k: K = build(set.certs.iter().copied());
            for s in ids() {
                assert_eq!(k.effective_access(s, s), Some(Access::Admin));
                let members = k.members(s);
                assert!(!members.contains_key(&s));
                for x in ids().filter(|x| *x != s) {
                    assert_eq!(members.get(&x).copied(), k.effective_access(s, x));
                }
            }
            for c in &set.certs {
                assert!(k.contains(&cert(*c).digest()));
                if let Some(d) = c.as_delegation() {
                    let naming = k.revocations_naming(&d.digest());
                    let expected: BTreeSet<_> = set
                        .revocations()
                        .filter(|r| r.revoke == d.digest())
                        .map(|r| r.digest())
                        .collect();
                    assert_eq!(naming, expected);
                }
            }
        });
}
