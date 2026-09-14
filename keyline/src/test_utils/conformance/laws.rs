//! Properties every `Keyline` must satisfy on every set, checked with `bolero`
//! over generated [`CertSet`]s.
//!
//! The oracle is [`naive`]: the normative program from
//! `design/keyline/implementation.md` § Evaluation transcribed as plain tuple
//! fixpoints (Jacobi iteration over `BTreeMap`s), sharing no code with any
//! backend. It is slow and obviously correct; `MemoryKeyline` must agree with
//! it on every generated set, with and without revocations.
use super::{
    build,
    gen::{ids, CertSet},
    TestContent,
};
use crate::{
    power::Power, certificate::Certificate, delegation::Delegation, id::Id, keyline::Keyline,
    test_utils::cert,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::digest::Digest;

/// Every `(subject, node)` level a backend reports over the pool, plus the
/// live status of every delegation: the whole observable state of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub levels: BTreeMap<(Id, Id), Power>,
    pub live: BTreeSet<Digest<Delegation>>,
}

pub fn observe<K: Keyline>(k: &K, set: &CertSet<K::Content>) -> Observed
where
    K::Content: TestContent,
{
    let levels = ids()
        .flat_map(|s| ids().map(move |x| (s, x)))
        .filter_map(|(s, x)| k.effective_power(s, x).map(|l| ((s, x), l)))
        .collect();
    let live = set
        .delegations()
        .map(Delegation::digest)
        .filter(|h| k.is_live(h))
        .collect();
    Observed { levels, live }
}

/// The normative program, executed naively.
pub mod naive {
    use super::*;

    /// `(subject, node) -> level`.
    pub type Levels = BTreeMap<(Id, Id), Power>;

    /// What the oracle derives from a set.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Evaluation {
        pub live: BTreeSet<Digest<Delegation>>,
        pub levels: Levels,
    }

    struct Facts {
        nodes: BTreeSet<Id>,
        dels: BTreeMap<Digest<Delegation>, Delegation>,
        // Issuer and target only: `retains` has no bearing on authority, so the
        // oracle cannot read it even by accident.
        revs: Vec<(Id, Digest<Delegation>)>,
    }

    fn raise(m: &mut Levels, key: (Id, Id), l: Power) -> bool {
        match m.get(&key) {
            Some(current) if *current >= l => false,
            _ => {
                m.insert(key, l);
                true
            }
        }
    }

    /// `level(s, x, h, l)` for one exclusion set: rules 1-3 over `usable`
    /// edges weighted by `cap`, every node in `exclude` refused. With
    /// `exclude = ∅`, every edge usable and `cap = power`, this is stratum 1.
    fn level(
        f: &Facts,
        exclude: &BTreeSet<Id>,
        usable: &dyn Fn(&Digest<Delegation>) -> bool,
        cap: &dyn Fn(&Digest<Delegation>, &Delegation) -> Power,
    ) -> Levels {
        let mut m: Levels = f
            .nodes
            .iter()
            .filter(|n| !exclude.contains(n))
            .map(|n| ((*n, *n), Power::Admin))
            .collect();

        loop {
            let mut changed = false;
            let snapshot = m.clone();

            for (h, d) in &f.dels {
                if !usable(h) || exclude.contains(&d.audience) {
                    continue;
                }
                if let Some(l) = snapshot.get(&(d.subject, d.issuer)) {
                    changed |= raise(&mut m, (d.subject, d.audience), (*l).min(cap(h, d)));
                }
            }
            for ((s, n), l1) in &snapshot {
                if n == s {
                    continue;
                }
                for ((n2, x), l2) in &snapshot {
                    if n2 == n {
                        changed |= raise(&mut m, (*s, *x), (*l1).min(*l2));
                    }
                }
            }

            if !changed {
                return m;
            }
        }
    }

    fn facts<C>(set: &CertSet<C>) -> Facts {
        let mut nodes: BTreeSet<Id> = ids().collect();
        let mut dels = BTreeMap::new();
        let mut revs = Vec::new();
        for c in &set.certs {
            match c {
                Certificate::Delegation(d) => {
                    nodes.extend([d.issuer, d.audience, d.subject]);
                    dels.insert(d.digest(), *d);
                }
                Certificate::Revocation(r) => {
                    nodes.insert(r.issuer);
                    revs.push((r.issuer, r.revokes));
                }
            }
        }
        Facts { nodes, dels, revs }
    }

    /// Stratum 1 alone: `reaches` over the pool, blind to revocations.
    pub fn reaches<C>(set: &CertSet<C>) -> Levels {
        level(&facts(set), &BTreeSet::new(), &|_| true, &|_, d| d.power)
    }

    /// Both strata: the live set (LFP) and caps (GFP), then the live levels.
    pub fn evaluate<C>(set: &CertSet<C>) -> Evaluation {
        let f = facts(set);
        let none = BTreeSet::new();

        let reaches = level(&f, &none, &|_| true, &|_, d| d.power);
        let admin_reach = |k: Id| -> BTreeSet<Id> {
            let mut s: BTreeSet<Id> = f
                .nodes
                .iter()
                .copied()
                .filter(|n| reaches.get(&(*n, k)) == Some(&Power::Admin))
                .collect();
            s.insert(k);
            s
        };
        let mut covered: BTreeMap<Digest<Delegation>, BTreeSet<Id>> = BTreeMap::new();
        for (issuer, revokes) in &f.revs {
            covered
                .entry(*revokes)
                .or_default()
                .extend(admin_reach(*issuer));
        }
        let renounced = |h: &Digest<Delegation>, audience: Id| {
            f.revs
                .iter()
                .any(|(issuer, revokes)| revokes == h && *issuer == audience)
        };

        let mut live: BTreeSet<Digest<Delegation>> = BTreeSet::new();
        loop {
            let added: Vec<Digest<Delegation>> = f
                .dels
                .iter()
                .filter(|(h, d)| !live.contains(*h) && !renounced(h, d.audience))
                .filter(|(h, d)| {
                    let exclude = covered.get(*h).cloned().unwrap_or_default();
                    level(&f, &exclude, &|x| live.contains(x), &|_, d| d.power)
                        .contains_key(&(d.subject, d.issuer))
                })
                .map(|(h, _)| *h)
                .collect();
            if added.is_empty() {
                break;
            }
            live.extend(added);
        }

        let mut cap: BTreeMap<Digest<Delegation>, Power> =
            f.dels.iter().map(|(h, d)| (*h, d.power)).collect();
        loop {
            let mut changed = false;
            for (h, d) in &f.dels {
                if !live.contains(h) {
                    continue;
                }
                let exclude = covered.get(h).cloned().unwrap_or_default();
                let current = cap.clone();
                let at_iss = level(&f, &exclude, &|x| live.contains(x), &|x, d| {
                    current[x].min(d.power)
                })[&(d.subject, d.issuer)];
                let next = d.power.min(at_iss);
                if next < cap[h] {
                    cap.insert(*h, next);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let levels = level(&f, &none, &|x| live.contains(x), &|x, d| cap[x].min(d.power));
        Evaluation { live, levels }
    }
}

/// Without revocations, `effective_power` is exactly stratum 1, and every
/// delegation whose issuer reaches its subject is live.
pub fn matches_naive_oracle_without_revocations<K: Keyline + Default>()
where
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::Content>>()
        .for_each(|set| {
            let set = set.without_revocations();
            let expected = naive::reaches(&set);
            let k: K = build(set.certs.iter().cloned());

            for s in ids() {
                for x in ids() {
                    assert_eq!(
                        k.effective_power(s, x),
                        expected.get(&(s, x)).copied(),
                        "effective_power({s}, {x})"
                    );
                }
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

/// With revocations, every query agrees with the normative program: admin
/// reach, coverage, the live set as a least fixed point with renunciation,
/// and clamped levels.
pub fn matches_naive_oracle_with_revocations<K: Keyline + Default>()
where
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::Content>>()
        .for_each(|set| {
            let expected = naive::evaluate(set);
            let k: K = build(set.certs.iter().cloned());

            for s in ids() {
                for x in ids() {
                    assert_eq!(
                        k.effective_power(s, x),
                        expected.levels.get(&(s, x)).copied(),
                        "effective_power({s}, {x})"
                    );
                }
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

/// Any insertion order gives the same answers and the same digest.
pub fn order_independent<K: Keyline + Default>()
where
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<K::Content>, Vec<u8>)>()
        .for_each(|(set, keys)| {
            let a: K = build(set.certs.iter().cloned());
            let b: K = build(set.permuted(keys).certs);
            assert_eq!(a.digest(), b.digest());
            assert_eq!(observe(&a, set), observe(&b, set));
            for s in ids() {
                assert_eq!(a.members(s), b.members(s));
            }
        });
}

/// Inserting a certificate already present returns `false` and changes nothing.
pub fn idempotent<K: Keyline + Default>()
where
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::Content>>()
        .for_each(|set| {
            let mut k: K = build(set.certs.iter().cloned());
            let before = (k.digest(), observe(&k, set));
            for c in &set.certs {
                assert!(!k.insert(cert(c.clone())));
            }
            assert_eq!((k.digest(), observe(&k, set)), before);
        });
}

/// Adding a revocation never raises any level and never revives a delegation.
pub fn revocations_only_deny<K: Keyline + Default>()
where
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::Content>>()
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
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<(CertSet<K::Content>, Vec<u8>)>()
        .for_each(|(set, keys)| {
            let a: K = build(set.certs.iter().cloned());
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

/// Every node is Admin over itself; `members` is exactly `effective_power`
/// minus the subject; `contains` agrees with what was inserted.
pub fn queries_are_consistent<K: Keyline + Default>()
where
    K::Content: TestContent,
{
    bolero::check!()
        .with_arbitrary::<CertSet<K::Content>>()
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
            for c in &set.certs {
                assert!(k.contains(&cert(c.clone()).digest()));
                if let Some(d) = c.as_delegation() {
                    let naming = k.revocations_naming(&d.digest());
                    let expected: BTreeSet<_> = set
                        .revocations()
                        .filter(|r| r.revokes == d.digest())
                        .map(|r| r.digest())
                        .collect();
                    assert_eq!(naming, expected);
                }
            }
        });
}
