//! The value-form program from `design/keyline/implementation.md`
//! § Evaluation, executed naively: plain tuple fixpoints over `BTreeMap`s
//! (Jacobi iteration for levels, caps raised in place), with caps as a second
//! fixed point.

use super::Levels;
use crate::{
    delegation::Delegation,
    id::Id,
    power::Power,
    test_utils::{
        conformance::gen::{ids, CertSet},
        Statement,
    },
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use keyhive_crypto::digest::Digest;

/// What the oracle derives from a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub live: BTreeSet<Digest<Delegation>>,
    pub levels: Levels,
}

struct Facts {
    nodes: BTreeSet<Id>,
    dels: BTreeMap<Digest<Delegation>, Delegation>,
    // Issuer and target only: `retain` has no bearing on authority, so the
    // oracle cannot read it even by accident.
    revocations: Vec<(Id, Digest<Delegation>)>,
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

fn facts<W>(set: &CertSet<W>) -> Facts {
    let mut nodes: BTreeSet<Id> = ids().collect();
    let mut dels = BTreeMap::new();
    let mut revocations = Vec::new();
    for c in &set.certs {
        match c {
            Statement::Delegation(d) => {
                nodes.extend([d.issuer, d.audience, d.subject]);
                dels.insert(d.digest(), *d);
            }
            Statement::Revocation(r) => {
                nodes.insert(r.issuer);
                revocations.push((r.issuer, r.revoke));
            }
        }
    }
    Facts {
        nodes,
        dels,
        revocations,
    }
}

/// Stratum 1 alone: `reaches` over the pool, blind to revocations.
pub fn reaches<W>(set: &CertSet<W>) -> Levels {
    level(&facts(set), &BTreeSet::new(), &|_| true, &|_, d| d.power)
}

/// Both strata: the live set and the caps, each a least fixed point, then
/// the live levels.
pub fn evaluate<W>(set: &CertSet<W>) -> Evaluation {
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
    for (issuer, revoke) in &f.revocations {
        covered
            .entry(*revoke)
            .or_default()
            .extend(admin_reach(*issuer));
    }
    let revoked_by_audience = |h: &Digest<Delegation>, audience: Id| {
        f.revocations
            .iter()
            .any(|(issuer, revoke)| revoke == h && *issuer == audience)
    };

    let mut live: BTreeSet<Digest<Delegation>> = BTreeSet::new();
    loop {
        let added: Vec<Digest<Delegation>> = f
            .dels
            .iter()
            .filter(|(h, d)| !live.contains(*h) && !revoked_by_audience(h, d.audience))
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

    // Caps rise from `Relay`: a live edge conveys at least that, and only
    // a grounded derivation can raise it further.
    let mut cap: BTreeMap<Digest<Delegation>, Power> =
        f.dels.keys().map(|h| (*h, Power::Relay)).collect();
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
            if next > cap[h] {
                cap.insert(*h, next);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let levels = level(&f, &none, &|x| live.contains(x), &|x, d| {
        cap[x].min(d.power)
    });
    Evaluation { live, levels }
}
