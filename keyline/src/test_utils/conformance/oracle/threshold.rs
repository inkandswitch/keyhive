//! The threshold form from `design/keyline/implementation.md`, transcribed
//! rule for rule as naive set fixpoints, except that stratum 3 takes the
//! maximum threshold directly instead of through `shadowed`.
//!
//! Relation and rule names follow the document. A context is `None` for
//! `empty`, or `Some(c)` for covered certificate `c`.

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
use alloc::{collections::BTreeSet, vec::Vec};
use keyhive_crypto::digest::Digest;

type Ctx = Option<Digest<Delegation>>;

/// What the threshold form derives from a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub effective: Levels,
    pub live: BTreeSet<Digest<Delegation>>,
}

pub fn evaluate<W>(set: &CertSet<W>) -> Evaluation {
    // stratum 0
    let mut node: BTreeSet<Id> = ids().collect();
    let mut delegation: BTreeSet<(Digest<Delegation>, Id, Id, Id, Power)> = BTreeSet::new();
    let mut revocation: BTreeSet<(Id, Digest<Delegation>)> = BTreeSet::new();
    for c in &set.certs {
        match c {
            Statement::Delegation(d) => {
                node.extend([d.issuer, d.audience, d.subject]);
                delegation.insert((d.digest(), d.issuer, d.audience, d.subject, d.power));
            }
            Statement::Revocation(r) => {
                node.insert(r.issuer);
                revocation.insert((r.issuer, r.revoke));
            }
        }
    }
    let level = Power::ALL;
    let le = |l1: Power, l2: Power| l1 <= l2;

    // stratum 1
    let mut reaches: BTreeSet<(Power, Id, Id)> = level
        .iter()
        .flat_map(|l| node.iter().map(move |s| (*l, *s, *s)))
        .collect();
    loop {
        let mut new = Vec::new();
        for &(_, iss, aud, sub, can) in &delegation {
            for &l in level.iter().filter(|l| le(**l, can)) {
                for &s in &node {
                    if reaches.contains(&(l, s, sub))
                        && reaches.contains(&(l, sub, iss))
                        && !reaches.contains(&(l, s, aud))
                    {
                        new.push((l, s, aud));
                    }
                }
            }
        }
        if new.is_empty() {
            break;
        }
        reaches.extend(new);
    }

    // stratum 1b
    let admin_reach = |k: Id, n: Id| reaches.contains(&(Power::Admin, n, k));
    let mut covered_total: BTreeSet<Digest<Delegation>> = BTreeSet::new();
    let mut covered: BTreeSet<(Digest<Delegation>, Id)> = BTreeSet::new();
    for &(i, c) in &revocation {
        for &(dc, di, da, _, _) in &delegation {
            if dc != c {
                continue;
            }
            if i == di || i == da {
                covered_total.insert(c);
            } else {
                covered.extend(node.iter().filter(|n| admin_reach(i, **n)).map(|n| (c, *n)));
            }
        }
    }

    // contexts
    let ctx: BTreeSet<Ctx> = core::iter::once(None)
        .chain(covered.iter().map(|(c, _)| Some(*c)))
        .collect();
    let excl = |x: Ctx, n: Id| x.is_some_and(|c| covered.contains(&(c, n)));
    let own_ctx = |c: Digest<Delegation>| covered.iter().any(|(cc, _)| *cc == c).then_some(c);

    // stratum 2
    let mut live: BTreeSet<(Ctx, Power, Id, Id)> = BTreeSet::new();
    for &x in &ctx {
        for &s in node.iter().filter(|s| !excl(x, **s)) {
            for &l in &level {
                live.insert((x, l, s, s));
            }
        }
    }
    loop {
        let mut new = Vec::new();
        for &(c, iss, aud, sub, can) in &delegation {
            if covered_total.contains(&c) {
                continue;
            }
            let o = own_ctx(c);
            for &l in level.iter().filter(|l| le(**l, can)) {
                for &x in &ctx {
                    if excl(x, iss) || excl(o, iss) || excl(x, aud) {
                        continue;
                    }
                    for &s in &node {
                        if live.contains(&(x, l, s, sub))
                            && live.contains(&(x, l, sub, iss))
                            && live.contains(&(o, l, sub, iss))
                            && !live.contains(&(x, l, s, aud))
                        {
                            new.push((x, l, s, aud));
                        }
                    }
                }
            }
        }
        if new.is_empty() {
            break;
        }
        live.extend(new);
    }

    // stratum 3
    let mut effective = Levels::new();
    for &(x, l, s, n) in &live {
        if x.is_none() {
            let best = effective.entry((s, n)).or_insert(l);
            *best = (*best).max(l);
        }
    }
    let is_live = delegation
        .iter()
        .filter(|(c, iss, _, sub, _)| {
            !covered_total.contains(c)
                && level
                    .iter()
                    .any(|l| live.contains(&(own_ctx(*c), *l, *sub, *iss)))
        })
        .map(|(c, ..)| *c)
        .collect();
    Evaluation {
        effective,
        live: is_live,
    }
}
